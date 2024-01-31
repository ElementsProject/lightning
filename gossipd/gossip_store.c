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

	/* This is false when we're loading */
	bool writable;

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

/* Read gossip store entries, copy non-deleted ones.  This code is written
 * as simply and robustly as possible! */
static u32 gossip_store_compact_offline(struct daemon *daemon)
{
	size_t count = 0, deleted = 0;
	int old_fd, new_fd;
	u64 oldlen, newlen;
	struct gossip_hdr hdr;
	u8 oldversion, version = GOSSIP_STORE_VER;
	struct stat st;

	old_fd = open(GOSSIP_STORE_FILENAME, O_RDWR);
	if (old_fd == -1)
		return 0;

	if (fstat(old_fd, &st) != 0) {
		status_broken("Could not stat gossip_store: %s",
			      strerror(errno));
		goto close_old;
	}

	new_fd = open(GOSSIP_STORE_TEMP_FILENAME, O_RDWR|O_TRUNC|O_CREAT, 0600);
	if (new_fd < 0) {
		status_broken(
		    "Could not open file for gossip_store compaction");
		goto close_old;
	}

	if (!read_all(old_fd, &oldversion, sizeof(oldversion))
	    || (oldversion != version && !can_upgrade(oldversion))) {
		status_broken("gossip_store_compact: bad version");
		goto close_and_delete;
	}

	if (!write_all(new_fd, &version, sizeof(version))) {
		status_broken("gossip_store_compact_offline: writing version to store: %s",
			      strerror(errno));
		goto close_and_delete;
	}

	/* Read everything, write non-deleted ones to new_fd */
	while (read_all(old_fd, &hdr, sizeof(hdr))) {
		size_t msglen;
		u8 *msg;

		msglen = be16_to_cpu(hdr.len);
		msg = tal_arr(NULL, u8, msglen);
		if (!read_all(old_fd, msg, msglen)) {
			status_broken("gossip_store_compact_offline: reading msg len %zu from store: %s",
				      msglen, strerror(errno));
			tal_free(msg);
			goto close_and_delete;
		}

		if (be16_to_cpu(hdr.flags) & GOSSIP_STORE_DELETED_BIT) {
			deleted++;
			tal_free(msg);
			continue;
		}

		/* Check checksum (upgrade would overwrite, so do it now) */
		if (be32_to_cpu(hdr.crc)
		    != crc32c(be32_to_cpu(hdr.timestamp), msg, msglen)) {
			status_broken("gossip_store_compact_offline: checksum verification failed? %08x should be %08x",
				      be32_to_cpu(hdr.crc),
				      crc32c(be32_to_cpu(hdr.timestamp), msg, msglen));
			tal_free(msg);
			goto close_and_delete;
		}

		if (oldversion != version) {
			if (!upgrade_field(oldversion, daemon,
					   be16_to_cpu(hdr.flags), &msg)) {
				tal_free(msg);
				goto close_and_delete;
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

		if (!write_all(new_fd, &hdr, sizeof(hdr))
		    || !write_all(new_fd, msg, msglen)) {
			status_broken("gossip_store_compact_offline: writing msg len %zu to new store: %s",
				      msglen, strerror(errno));
			tal_free(msg);
			goto close_and_delete;
		}
		tal_free(msg);
		count++;
	}
	if (close(new_fd) != 0) {
		status_broken("gossip_store_compact_offline: closing new store: %s",
			      strerror(errno));
		goto close_old;
	}
	if (rename(GOSSIP_STORE_TEMP_FILENAME, GOSSIP_STORE_FILENAME) != 0) {
		status_broken("gossip_store_compact_offline: rename failed: %s",
			      strerror(errno));
	}

	/* Create end marker now new file exists. */
	oldlen = lseek(old_fd, SEEK_END, 0);
	newlen = lseek(new_fd, SEEK_END, 0);
	append_msg(old_fd, towire_gossip_store_ended(tmpctx, newlen),
		   0, &oldlen);
	close(old_fd);
	status_debug("gossip_store_compact_offline: %zu deleted, %zu copied",
		     deleted, count);
	return st.st_mtime;

close_and_delete:
	close(new_fd);
close_old:
	close(old_fd);
	unlink(GOSSIP_STORE_TEMP_FILENAME);
	return 0;
}

struct gossip_store *gossip_store_new(struct daemon *daemon)
{
	struct gossip_store *gs = tal(daemon, struct gossip_store);
	gs->writable = true;
	gs->timestamp = gossip_store_compact_offline(daemon);
	gs->fd = open(GOSSIP_STORE_FILENAME, O_RDWR|O_CREAT, 0600);
	if (gs->fd < 0)
		status_failed(STATUS_FAIL_INTERNAL_ERROR,
			      "Opening gossip_store store: %s",
			      strerror(errno));
	gs->daemon = daemon;
	gs->len = sizeof(gs->version);

	tal_add_destructor(gs, gossip_store_destroy);

	/* Try to read the version, write it if this is a new file, or truncate
	 * if the version doesn't match */
	if (read(gs->fd, &gs->version, sizeof(gs->version))
	    == sizeof(gs->version)) {
		/* Version match?  All good */
		if (gs->version == GOSSIP_STORE_VER)
			return gs;

		status_unusual("Gossip store version %u not %u: removing",
			       gs->version, GOSSIP_STORE_VER);
		if (ftruncate(gs->fd, 0) != 0)
			status_failed(STATUS_FAIL_INTERNAL_ERROR,
				      "Truncating store: %s", strerror(errno));
		/* Subtle: we are at offset 1, move back to start! */
		if (lseek(gs->fd, 0, SEEK_SET) != 0)
			status_failed(STATUS_FAIL_INTERNAL_ERROR,
				      "Seeking to start of store: %s",
				      strerror(errno));
	}
	/* Empty file, write version byte */
	gs->version = GOSSIP_STORE_VER;
	if (write(gs->fd, &gs->version, sizeof(gs->version))
	    != sizeof(gs->version))
		status_failed(STATUS_FAIL_INTERNAL_ERROR,
			      "Writing version to store: %s", strerror(errno));
	return gs;
}

u64 gossip_store_add(struct gossip_store *gs, const u8 *gossip_msg, u32 timestamp)
{
	u64 off = gs->len;

	/* Should never get here during loading! */
	assert(gs->writable);

	if (!append_msg(gs->fd, gossip_msg, timestamp, &gs->len)) {
		status_broken("Failed writing to gossip store: %s",
			      strerror(errno));
		return 0;
	}

	return off;
}

static const u8 *gossip_store_get_with_hdr(const tal_t *ctx,
					   struct gossip_store *gs,
					   u64 offset,
					   struct gossip_hdr *hdr)
{
	u32 msglen, checksum;
	u8 *msg;

	if (offset == 0)
		status_failed(STATUS_FAIL_INTERNAL_ERROR,
			      "gossip_store: can't access offset %"PRIu64,
			      offset);
	if (pread(gs->fd, hdr, sizeof(*hdr), offset) != sizeof(*hdr)) {
		status_failed(STATUS_FAIL_INTERNAL_ERROR,
			      "gossip_store: can't read hdr offset %"PRIu64
			      "/%"PRIu64": %s",
			      offset, gs->len, strerror(errno));
	}

	if (be16_to_cpu(hdr->flags) & GOSSIP_STORE_DELETED_BIT)
		status_failed(STATUS_FAIL_INTERNAL_ERROR,
			      "gossip_store: get delete entry offset %"PRIu64
			      "/%"PRIu64"",
			      offset, gs->len);

	msglen = be16_to_cpu(hdr->len);
	checksum = be32_to_cpu(hdr->crc);
	msg = tal_arr(ctx, u8, msglen);
	if (pread(gs->fd, msg, msglen, offset + sizeof(*hdr)) != msglen)
		status_failed(STATUS_FAIL_INTERNAL_ERROR,
			      "gossip_store: can't read len %u offset %"PRIu64
			      "/%"PRIu64, msglen, offset, gs->len);

	if (checksum != crc32c(be32_to_cpu(hdr->timestamp), msg, msglen))
		status_failed(STATUS_FAIL_INTERNAL_ERROR,
			      "gossip_store: bad checksum offset %"PRIu64": %s",
			      offset, tal_hex(tmpctx, msg));

	return msg;
}

static bool check_msg_type(struct gossip_store *gs, u32 index, int flag, int type)
{
	struct gossip_hdr hdr;
	const u8 *msg = gossip_store_get_with_hdr(tmpctx, gs, index, &hdr);

	if (fromwire_peektype(msg) == type)
		return true;

	status_broken("asked to flag-%u type %i @%u but store contains "
		      "%i (gs->len=%"PRIu64"): %s",
		      flag, type, index, fromwire_peektype(msg),
		      gs->len, tal_hex(tmpctx, msg));
	return false;
}

/* Returns index of following entry. */
static u32 flag_by_index(struct gossip_store *gs, u32 index, int flag, int type)
{
	struct {
		beint16_t beflags;
		beint16_t belen;
	} hdr;

	/* Should never get here during loading! */
	assert(gs->writable);

	/* Should never try to overwrite version */
	assert(index);

	/* FIXME: debugging a gs->len overrun issue reported in #6270 */
	if (pread(gs->fd, &hdr, sizeof(hdr), index) != sizeof(hdr)) {
		status_broken("gossip_store pread fail during flag %u @%u type: %i"
			      " gs->len: %"PRIu64, flag, index, type, gs->len);
		return index;
	}
	if (index + sizeof(struct gossip_hdr) +
	    be16_to_cpu(hdr.belen) > gs->len) {
		status_broken("gossip_store overrun during flag-%u @%u type: %i"
			      " gs->len: %"PRIu64, flag, index, type, gs->len);
		return index;
	}

	if (!check_msg_type(gs, index, flag, type))
		return index;

	assert((be16_to_cpu(hdr.beflags) & flag) == 0);
	hdr.beflags |= cpu_to_be16(flag);
	if (pwrite(gs->fd, &hdr.beflags, sizeof(hdr.beflags), index) != sizeof(hdr.beflags))
		status_failed(STATUS_FAIL_INTERNAL_ERROR,
			      "Failed writing flags to delete @%u: %s",
			      index, strerror(errno));

	return index + sizeof(struct gossip_hdr) + be16_to_cpu(hdr.belen);
}

void gossip_store_del(struct gossip_store *gs,
		      u64 offset,
		      int type)
{
	u32 next_index;

	assert(offset > sizeof(struct gossip_hdr));
	next_index = flag_by_index(gs, offset - sizeof(struct gossip_hdr),
				   GOSSIP_STORE_DELETED_BIT,
				   type);

	/* For a channel_announcement, we need to delete amount too */
	if (type == WIRE_CHANNEL_ANNOUNCEMENT)
		flag_by_index(gs, next_index,
			      GOSSIP_STORE_DELETED_BIT,
			      WIRE_GOSSIP_STORE_CHANNEL_AMOUNT);
}

void gossip_store_flag(struct gossip_store *gs,
		       u64 offset,
		       u16 flag,
		       int type)
{
	assert(offset > sizeof(struct gossip_hdr));

	flag_by_index(gs, offset - sizeof(struct gossip_hdr), flag, type);
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

	assert(offset > sizeof(struct gossip_hdr));
	msg = gossip_store_get_with_hdr(tmpctx, gs, offset - sizeof(hdr), &hdr);
	if (pread(gs->fd, &hdr, sizeof(hdr), offset - sizeof(hdr)) != sizeof(hdr)) {
		status_broken("gossip_store overrun during set_timestamp @%"PRIu64
			      " gs->len: %"PRIu64, offset, gs->len);
		return;
	}

	/* Change timestamp and crc */
	hdr.timestamp = cpu_to_be32(timestamp);
	hdr.crc = cpu_to_be32(crc32c(timestamp, msg, tal_bytelen(msg)));

	if (pwrite(gs->fd, &hdr, sizeof(hdr), offset - sizeof(hdr)) != sizeof(hdr))
		status_failed(STATUS_FAIL_INTERNAL_ERROR,
			      "Failed writing header to re-timestamp @%"PRIu64": %s",
			      offset, strerror(errno));
}

u32 gossip_store_load(struct gossip_store *gs)
{
	struct gossip_hdr hdr;
	u32 msglen, checksum;
	u8 *msg;
	struct amount_sat satoshis;
	const char *bad;
	size_t stats[] = {0, 0, 0, 0};
	struct timeabs start = time_now();
	size_t deleted = 0;
	u8 *chan_ann = NULL;

	/* FIXME: Do compaction here, and check checksums, etc then.. */
	gs->writable = false;
	while (pread(gs->fd, &hdr, sizeof(hdr), gs->len) == sizeof(hdr)) {
		msglen = be16_to_cpu(hdr.len);
		checksum = be32_to_cpu(hdr.crc);
		msg = tal_arr(tmpctx, u8, msglen);

		if (pread(gs->fd, msg, msglen, gs->len+sizeof(hdr)) != msglen) {
			bad = "gossip_store: truncated file?";
			goto corrupt;
		}

		if (checksum != crc32c(be32_to_cpu(hdr.timestamp), msg, msglen)) {
			bad = tal_fmt(tmpctx, "Checksum verification failed: %08x should be %08x",
				      checksum, crc32c(be32_to_cpu(hdr.timestamp), msg, msglen));
			goto badmsg;
		}

		/* Skip deleted entries */
		if (be16_to_cpu(hdr.flags) & GOSSIP_STORE_DELETED_BIT) {
			deleted++;
			goto next;
		}

		switch (fromwire_peektype(msg)) {
		case WIRE_GOSSIP_STORE_CHANNEL_AMOUNT:
			if (!fromwire_gossip_store_channel_amount(msg,
								  &satoshis)) {
				bad = "Bad gossip_store_channel_amount";
				goto badmsg;
			}
			/* Previous channel_announcement may have been deleted */
			if (!chan_ann)
				break;
			chan_ann = NULL;
			stats[0]++;
			break;
		case WIRE_CHANNEL_ANNOUNCEMENT:
			if (chan_ann) {
				bad = "channel_announcement without amount";
				goto badmsg;
			}
			/* Save for channel_amount (next msg) (not tmpctx, it gets cleaned!) */
			chan_ann = tal_steal(gs, msg);
			break;
		case WIRE_GOSSIP_STORE_CHAN_DYING: {
			struct short_channel_id scid;
			u32 deadline;

			if (!fromwire_gossip_store_chan_dying(msg, &scid, &deadline)) {
				bad = "Bad gossip_store_chan_dying";
				goto badmsg;
			}
			if (!gossmap_manage_channel_dying(gs->daemon->gm, gs->len, deadline, scid)) {
				bad = "Invalid gossip_store_chan_dying";
				goto badmsg;
			}
			break;
		}
		case WIRE_CHANNEL_UPDATE:
			stats[1]++;
			break;
		case WIRE_NODE_ANNOUNCEMENT:
			stats[2]++;
			break;
		default:
			bad = "Unknown message";
			goto badmsg;
		}

	next:
		gs->len += sizeof(hdr) + msglen;
		clean_tmpctx();
	}

	if (chan_ann) {
		tal_free(chan_ann);
		bad = "dangling channel_announcement";
		goto corrupt;
	}

	goto out;

badmsg:
	bad = tal_fmt(tmpctx, "%s (%s)", bad, tal_hex(tmpctx, msg));

corrupt:
	status_broken("gossip_store: %s. Moving to %s.corrupt and truncating",
		      bad, GOSSIP_STORE_FILENAME);

	/* FIXME: Debug partial truncate case. */
	rename(GOSSIP_STORE_FILENAME, GOSSIP_STORE_FILENAME ".corrupt");
	close(gs->fd);
	gs->fd = open(GOSSIP_STORE_FILENAME, O_RDWR|O_TRUNC|O_CREAT, 0600);
	if (gs->fd < 0 || !write_all(gs->fd, &gs->version, sizeof(gs->version)))
		status_failed(STATUS_FAIL_INTERNAL_ERROR,
			      "Truncating new store file: %s", strerror(errno));
	gs->len = 1;
	gs->timestamp = 0;
out:
	gs->writable = true;
	status_debug("total store load time: %"PRIu64" msec",
		     time_to_msec(time_between(time_now(), start)));
	status_debug("gossip_store: Read %zu/%zu/%zu/%zu cannounce/cupdate/nannounce/cdelete from store (%zu deleted) in %"PRIu64" bytes",
		     stats[0], stats[1], stats[2], stats[3], deleted,
		     gs->len);

	return gs->timestamp;
}
