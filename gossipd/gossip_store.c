#include "config.h"
#include <ccan/array_size/array_size.h>
#include <ccan/crc32c/crc32c.h>
#include <ccan/noerr/noerr.h>
#include <ccan/read_write_all/read_write_all.h>
#include <ccan/tal/str/str.h>
#include <common/gossip_store.h>
#include <common/status.h>
#include <errno.h>
#include <fcntl.h>
#include <gossipd/gossip_store.h>
#include <gossipd/gossip_store_wiregen.h>
#include <gossipd/gossipd.h>
#include <gossipd/gossmap_manage.h>
#include <inttypes.h>
#include <sys/stat.h>
#include <sys/uio.h>
#include <unistd.h>
#include <wire/peer_wire.h>

/* Obsolete ZOMBIE bit */
#define GOSSIP_STORE_ZOMBIE_BIT_V13 0x1000U

#define GOSSIP_STORE_TEMP_FILENAME "gossip_store.tmp"
/* We write it as major version 0, minor version 14 */
#define GOSSIP_STORE_VER ((0 << 5) | 14)

struct gossip_store {
	/* Back pointer. */
	struct daemon *daemon;

	int fd;
	u8 version;

	/* Offset of current EOF */
	u64 len;

	/* Timestamp of store when we opened it (0 if we created it) */
	u32 timestamp;
};

static void gossip_store_destroy(struct gossip_store *gs)
{
	close(gs->fd);
}

#if HAVE_PWRITEV
/* One fewer syscall for the win! */
static ssize_t gossip_pwritev(int fd, const struct iovec *iov, int iovcnt,
			      off_t offset)
{
	return pwritev(fd, iov, iovcnt, offset);
}
#else /* Hello MacOS! */
static ssize_t gossip_pwritev(int fd, const struct iovec *iov, int iovcnt,
			      off_t offset)
{
	if (lseek(fd, offset, SEEK_SET) != offset)
		return -1;
	return writev(fd, iov, iovcnt);
}
#endif /* !HAVE_PWRITEV */

static bool append_msg(int fd, const u8 *msg, u32 timestamp, u64 *len)
{
	struct gossip_hdr hdr;
	u32 msglen;
	struct iovec iov[2];

	/* Don't ever overwrite the version header! */
	assert(*len);

	msglen = tal_count(msg);
	hdr.len = cpu_to_be16(msglen);
	hdr.flags = 0;
	hdr.crc = cpu_to_be32(crc32c(timestamp, msg, msglen));
	hdr.timestamp = cpu_to_be32(timestamp);

	/* pwritev makes it more likely to appear at once, plus it's
	 * exactly what we want. */
	iov[0].iov_base = &hdr;
	iov[0].iov_len = sizeof(hdr);
	iov[1].iov_base = (void *)msg;
	iov[1].iov_len = msglen;
	if (gossip_pwritev(fd, iov, ARRAY_SIZE(iov), *len) != sizeof(hdr) + msglen)
		return false;
	*len += sizeof(hdr) + msglen;
	return true;
}

/* v9 added the GOSSIP_STORE_LEN_RATELIMIT_BIT.
 * v10 removed any remaining non-htlc-max channel_update.
 * v11 mandated channel_updates use the htlc_maximum_msat field
 * v12 added the zombie flag for expired channel updates
 * v13 removed private gossip entries
 * v14 removed zombie and spam flags
 */
static bool can_upgrade(u8 oldversion)
{
	return oldversion >= 9 && oldversion <= 13;
}

/* On upgrade, do best effort on private channels: hand them to
 * lightningd as if we just receive them, before removing from the
 * store */
static void give_lightningd_canned_private_update(struct daemon *daemon,
						  const u8 *msg)
{
	u8 *update;
	secp256k1_ecdsa_signature signature;
	struct bitcoin_blkid chain_hash;
	struct short_channel_id short_channel_id;
	u32 timestamp;
	u8 message_flags, channel_flags;
	u16 cltv_expiry_delta;
	struct amount_msat htlc_minimum_msat, htlc_maximum_msat;
	u32 fee_base_msat, fee_proportional_millionths;

	if (!fromwire_gossip_store_private_update_obs(tmpctx, msg, &update)) {
		status_broken("Could not parse private update %s",
			      tal_hex(tmpctx, msg));
		return;
	}
	if (!fromwire_channel_update(update,
				     &signature,
				     &chain_hash,
				     &short_channel_id,
				     &timestamp,
				     &message_flags,
				     &channel_flags,
				     &cltv_expiry_delta,
				     &htlc_minimum_msat,
				     &fee_base_msat,
				     &fee_proportional_millionths,
				     &htlc_maximum_msat)) {
		status_broken("Could not parse inner private update %s",
			      tal_hex(tmpctx, msg));
		return;
	}

	/* From NULL source (i.e. trust us!) */
	tell_lightningd_peer_update(daemon,
				    NULL,
				    short_channel_id,
				    fee_base_msat,
				    fee_proportional_millionths,
				    cltv_expiry_delta,
				    htlc_minimum_msat,
				    htlc_maximum_msat);
}

static bool upgrade_field(u8 oldversion,
			  struct daemon *daemon,
			  u16 hdr_flags,
			  u8 **msg)
{
	int type = fromwire_peektype(*msg);
	assert(can_upgrade(oldversion));

	if (oldversion <= 10) {
		/* Remove old channel_update with no htlc_maximum_msat */
		if (type == WIRE_CHANNEL_UPDATE
		    && tal_bytelen(*msg) == 130) {
			*msg = tal_free(*msg);
		}
	}
	if (oldversion <= 12) {
		/* Remove private entries */
		if (type == WIRE_GOSSIP_STORE_PRIVATE_CHANNEL_OBS) {
			*msg = tal_free(*msg);
		} else if (type == WIRE_GOSSIP_STORE_PRIVATE_UPDATE_OBS) {
			give_lightningd_canned_private_update(daemon, *msg);
			*msg = tal_free(*msg);
		}
	}
	if (oldversion <= 13) {
		/* Discard any zombies */
		if (hdr_flags & GOSSIP_STORE_ZOMBIE_BIT_V13) {
			*msg = tal_free(*msg);
		}
	}

	return true;
}

/* Read gossip store entries, copy non-deleted ones.  Check basic
 * validity, but this code is written as simply and robustly as
 * possible!
 *
 * Returns fd of new store.
 */
static int gossip_store_compact(struct daemon *daemon,
				u64 *total_len,
				bool *populated,
				struct chan_dying **dying)
{
	size_t cannounces = 0, cupdates = 0, nannounces = 0, deleted = 0;
	int old_fd, new_fd;
	u64 old_len, cur_off;
	struct gossip_hdr hdr;
	u8 oldversion, version = GOSSIP_STORE_VER;
	struct stat st;
	bool prev_chan_ann = false;
	struct timeabs start = time_now();
	const char *bad;

	*populated = false;
	old_len = 0;

	new_fd = open(GOSSIP_STORE_TEMP_FILENAME, O_RDWR|O_TRUNC|O_CREAT, 0600);
	if (new_fd < 0) {
		status_failed(STATUS_FAIL_INTERNAL_ERROR,
			      "Opening new gossip_store file: %s",
			      strerror(errno));
	}

	if (!write_all(new_fd, &version, sizeof(version))) {
		status_failed(STATUS_FAIL_INTERNAL_ERROR,
			      "Writing new gossip_store file: %s",
			      strerror(errno));
	}
	*total_len = sizeof(version);

	/* RDWR since we add closed marker at end! */
	old_fd = open(GOSSIP_STORE_FILENAME, O_RDWR);
	if (old_fd == -1) {
		if (errno == ENOENT)
			goto rename_new;

		status_failed(STATUS_FAIL_INTERNAL_ERROR,
			      "Reading gossip_store file: %s",
			      strerror(errno));
	};

	if (fstat(old_fd, &st) != 0) {
		status_broken("Could not stat gossip_store: %s",
			      strerror(errno));
		goto rename_new;
	}

	if (!read_all(old_fd, &oldversion, sizeof(oldversion))
	    || (oldversion != version && !can_upgrade(oldversion))) {
		status_broken("gossip_store_compact: bad version");
		goto rename_new;
	}

	cur_off = old_len = sizeof(oldversion);

	/* Read everything, write non-deleted ones to new_fd.  If something goes wrong,
	 * we end up with truncated store. */
	while (read_all(old_fd, &hdr, sizeof(hdr))) {
		size_t msglen;
		u8 *msg;

		/* Partial writes can happen, and we simply truncate */
		msglen = be16_to_cpu(hdr.len);
		msg = tal_arr(NULL, u8, msglen);
		if (!read_all(old_fd, msg, msglen)) {
			status_unusual("gossip_store_compact: store ends early at %"PRIu64,
				       old_len);
			tal_free(msg);
			goto rename_new;
		}

		cur_off = old_len;
		old_len += sizeof(hdr) + msglen;

		if (be16_to_cpu(hdr.flags) & GOSSIP_STORE_DELETED_BIT) {
			deleted++;
			tal_free(msg);
			continue;
		}

		/* Check checksum (upgrade would overwrite, so do it now) */
		if (be32_to_cpu(hdr.crc)
		    != crc32c(be32_to_cpu(hdr.timestamp), msg, msglen)) {
			bad = tal_fmt(tmpctx, "checksum verification failed? %08x should be %08x",
				      be32_to_cpu(hdr.crc),
				      crc32c(be32_to_cpu(hdr.timestamp), msg, msglen));
			goto badmsg;
		}

		if (oldversion != version) {
			if (!upgrade_field(oldversion, daemon,
					   be16_to_cpu(hdr.flags), &msg)) {
				tal_free(msg);
				bad = "upgrade of store failed";
				goto badmsg;
			}

			/* It can tell us to delete record entirely. */
			if (msg == NULL) {
				deleted++;
				continue;
			}

			/* Recalc msglen and header */
			msglen = tal_bytelen(msg);
			hdr.len = cpu_to_be16(msglen);
			hdr.crc = cpu_to_be32(crc32c(be32_to_cpu(hdr.timestamp),
						      msg, msglen));
		}

		/* Don't write out old tombstones */
		if (fromwire_peektype(msg) == WIRE_GOSSIP_STORE_DELETE_CHAN) {
			deleted++;
			tal_free(msg);
			continue;
		}

		switch (fromwire_peektype(msg)) {
		case WIRE_GOSSIP_STORE_CHANNEL_AMOUNT:
			/* Previous channel_announcement may have been deleted */
			if (prev_chan_ann)
				cannounces++;
			prev_chan_ann = false;
			break;
		case WIRE_CHANNEL_ANNOUNCEMENT:
			if (prev_chan_ann) {
				bad = "channel_announcement without amount";
				goto badmsg;
			}
			prev_chan_ann = true;
			break;
		case WIRE_GOSSIP_STORE_CHAN_DYING: {
			struct chan_dying cd;

			if (!fromwire_gossip_store_chan_dying(msg,
							      &cd.scid,
							      &cd.deadline)) {
				bad = "Bad gossip_store_chan_dying";
				goto badmsg;
			}
			/* By convention, these offsets are *after* header */
			cd.gossmap_offset = *total_len + sizeof(hdr);
			tal_arr_expand(dying, cd);
			break;
		}
		case WIRE_CHANNEL_UPDATE:
			cupdates++;
			break;
		case WIRE_NODE_ANNOUNCEMENT:
			nannounces++;
			break;
		default:
			bad = "Unknown message";
			goto badmsg;
		}

		if (!write_all(new_fd, &hdr, sizeof(hdr))
		    || !write_all(new_fd, msg, msglen)) {
			status_failed(STATUS_FAIL_INTERNAL_ERROR,
				      "gossip_store_compact: writing msg len %zu to new store: %s",
				      msglen, strerror(errno));
		}
		tal_free(msg);
		*total_len += sizeof(hdr) + msglen;
	}

	assert(*total_len == lseek(new_fd, 0, SEEK_END));

	/* Unlikely, but a channel_announcement without an amount: we just truncate. */
	if (prev_chan_ann) {
		bad = "channel_announcement without amount";
		goto badmsg;
	}

	/* If we have any contents, and the file is less than 1 hour
	 * old, say "seems good" */
	if (st.st_mtime > time_now().ts.tv_sec - 3600 && *total_len > 1) {
		*populated = true;
	}

rename_new:
	if (rename(GOSSIP_STORE_TEMP_FILENAME, GOSSIP_STORE_FILENAME) != 0) {
		status_failed(STATUS_FAIL_INTERNAL_ERROR,
			      "gossip_store_compact: rename failed: %s",
			      strerror(errno));
	}

	/* Create end marker now new file exists. */
	if (old_fd != -1) {
		append_msg(old_fd, towire_gossip_store_ended(tmpctx, *total_len),
			   0, &old_len);
		close(old_fd);
	}

	status_debug("Store compact time: %"PRIu64" msec",
		     time_to_msec(time_between(time_now(), start)));
	status_debug("gossip_store: Read %zu/%zu/%zu/%zu cannounce/cupdate/nannounce/delete from store in %"PRIu64" bytes, now %"PRIu64" bytes (populated=%s)",
		     cannounces, cupdates, nannounces, deleted,
		     old_len, *total_len,
		     *populated ? "true": "false");
	return new_fd;

badmsg:
	/* We truncate */
	status_broken("gossip_store: %s (offset %"PRIu64"). Moving to %s.corrupt and truncating",
		      bad, cur_off, GOSSIP_STORE_FILENAME);

	rename(GOSSIP_STORE_FILENAME, GOSSIP_STORE_FILENAME ".corrupt");
	if (lseek(new_fd, 0, SEEK_SET) != 0
	    || !write_all(new_fd, &version, sizeof(version))) {
		status_failed(STATUS_FAIL_INTERNAL_ERROR,
			      "Overwriting new gossip_store file: %s",
			      strerror(errno));
	}
	*total_len = sizeof(version);
	goto rename_new;
}

struct gossip_store *gossip_store_new(const tal_t *ctx,
				      struct daemon *daemon,
				      bool *populated,
				      struct chan_dying **dying)
{
	struct gossip_store *gs = tal(ctx, struct gossip_store);

	gs->daemon = daemon;
	*dying = tal_arr(ctx, struct chan_dying, 0);
	gs->fd = gossip_store_compact(daemon, &gs->len, populated, dying);
	tal_add_destructor(gs, gossip_store_destroy);
	return gs;
}

int gossip_store_get_fd(const struct gossip_store *gs)
{
	return gs->fd;
}

u64 gossip_store_add(struct gossip_store *gs, const u8 *gossip_msg, u32 timestamp)
{
	u64 off = gs->len;

	if (!append_msg(gs->fd, gossip_msg, timestamp, &gs->len)) {
		status_broken("Failed writing to gossip store: %s",
			      strerror(errno));
		return 0;
	}

	/* By gossmap convention, offset is *after* hdr */
	return off + sizeof(struct gossip_hdr);
}

/* Offsets are all gossmap-style: *after* hdr! */
static const u8 *gossip_store_get_with_hdr(const tal_t *ctx,
					   struct gossip_store *gs,
					   u64 offset,
					   struct gossip_hdr *hdr)
{
	u32 msglen, checksum;
	u8 *msg;

	if (offset <= sizeof(*hdr))
		status_failed(STATUS_FAIL_INTERNAL_ERROR,
			      "gossip_store: can't access offset %"PRIu64,
			      offset);
	if (pread(gs->fd, hdr, sizeof(*hdr), offset - sizeof(*hdr)) != sizeof(*hdr)) {
		status_failed(STATUS_FAIL_INTERNAL_ERROR,
			      "gossip_store: can't read hdr offset %"PRIu64
			      "/%"PRIu64": %s",
			      offset - sizeof(*hdr), gs->len, strerror(errno));
	}

	if (be16_to_cpu(hdr->flags) & GOSSIP_STORE_DELETED_BIT)
		status_failed(STATUS_FAIL_INTERNAL_ERROR,
			      "gossip_store: get delete entry offset %"PRIu64
			      "/%"PRIu64"",
			      offset - sizeof(*hdr), gs->len);

	msglen = be16_to_cpu(hdr->len);
	checksum = be32_to_cpu(hdr->crc);
	msg = tal_arr(ctx, u8, msglen);
	if (pread(gs->fd, msg, msglen, offset) != msglen)
		status_failed(STATUS_FAIL_INTERNAL_ERROR,
			      "gossip_store: can't read len %u offset %"PRIu64
			      "/%"PRIu64, msglen, offset, gs->len);

	if (checksum != crc32c(be32_to_cpu(hdr->timestamp), msg, msglen))
		status_failed(STATUS_FAIL_INTERNAL_ERROR,
			      "gossip_store: bad checksum offset %"PRIu64": %s",
			      offset - sizeof(*hdr), tal_hex(tmpctx, msg));

	return msg;
}

/* Populates hdr */
static bool check_msg_type(struct gossip_store *gs, u64 offset, int flag, int type,
			   struct gossip_hdr *hdr)
{
	const u8 *msg = gossip_store_get_with_hdr(tmpctx, gs, offset, hdr);

	if (fromwire_peektype(msg) == type)
		return true;

	status_broken("asked to flag-%u type %i @%"PRIu64" but store contains "
		      "%i (gs->len=%"PRIu64"): %s",
		      flag, type, offset, fromwire_peektype(msg),
		      gs->len, tal_hex(tmpctx, msg));
	return false;
}

/* Returns offset of following entry (i.e. after its header). */
u64 gossip_store_set_flag(struct gossip_store *gs,
			  u64 offset, u16 flag, int type)
{
	struct gossip_hdr hdr;

	if (!check_msg_type(gs, offset, flag, type, &hdr))
		return offset;

	if (be16_to_cpu(hdr.flags) & flag) {
		status_broken("gossip_store flag-%u @%"PRIu64" for %u already set!",
			      flag, offset, type);
	}

	hdr.flags |= cpu_to_be16(flag);
	if (pwrite(gs->fd, &hdr, sizeof(hdr), offset - sizeof(hdr)) != sizeof(hdr))

		status_failed(STATUS_FAIL_INTERNAL_ERROR,
			      "Failed writing set flags @%"PRIu64": %s",
			      offset, strerror(errno));

	return offset + be16_to_cpu(hdr.len) + sizeof(struct gossip_hdr);
}

u16 gossip_store_get_flags(struct gossip_store *gs,
			   u64 offset, int type)
{
	struct gossip_hdr hdr;

	if (!check_msg_type(gs, offset, -1, type, &hdr))
		return 0;

	return be16_to_cpu(hdr.flags);
}

void gossip_store_clear_flag(struct gossip_store *gs,
			     u64 offset, u16 flag, int type)
{
	struct gossip_hdr hdr;

	if (!check_msg_type(gs, offset, flag, type, &hdr))
		return;

	assert(be16_to_cpu(hdr.flags) & flag);
	hdr.flags &= ~cpu_to_be16(flag);
	if (pwrite(gs->fd, &hdr, sizeof(hdr), offset - sizeof(hdr)) != sizeof(hdr))
		status_failed(STATUS_FAIL_INTERNAL_ERROR,
			      "Failed writing clear flags @%"PRIu64": %s",
			      offset, strerror(errno));
}

void gossip_store_del(struct gossip_store *gs,
		      u64 offset,
		      int type)
{
	u32 next_index;

	assert(offset > sizeof(struct gossip_hdr));
	next_index = gossip_store_set_flag(gs, offset,
					   GOSSIP_STORE_DELETED_BIT,
					   type);

	/* For a channel_announcement, we need to delete amount too */
	if (type == WIRE_CHANNEL_ANNOUNCEMENT)
		gossip_store_set_flag(gs, next_index,
				      GOSSIP_STORE_DELETED_BIT,
				      WIRE_GOSSIP_STORE_CHANNEL_AMOUNT);
}

u32 gossip_store_get_timestamp(struct gossip_store *gs, u64 offset)
{
	struct gossip_hdr hdr;

	assert(offset > sizeof(struct gossip_hdr));

	if (pread(gs->fd, &hdr, sizeof(hdr), offset - sizeof(hdr)) != sizeof(hdr)) {
		status_broken("gossip_store overrun during get_timestamp @%"PRIu64
			      " gs->len: %"PRIu64, offset, gs->len);
		return 0;
	}

	return be32_to_cpu(hdr.timestamp);
}

void gossip_store_set_timestamp(struct gossip_store *gs, u64 offset, u32 timestamp)
{
	struct gossip_hdr hdr;
	const u8 *msg;

	msg = gossip_store_get_with_hdr(tmpctx, gs, offset, &hdr);

	/* Change timestamp and crc */
	hdr.timestamp = cpu_to_be32(timestamp);
	hdr.crc = cpu_to_be32(crc32c(timestamp, msg, tal_bytelen(msg)));

	if (pwrite(gs->fd, &hdr, sizeof(hdr), offset - sizeof(hdr)) != sizeof(hdr))
		status_failed(STATUS_FAIL_INTERNAL_ERROR,
			      "Failed writing header to re-timestamp @%"PRIu64": %s",
			      offset, strerror(errno));
}

u64 gossip_store_len_written(const struct gossip_store *gs)
{
	return gs->len;
}
