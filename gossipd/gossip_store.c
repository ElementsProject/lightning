#include "gossip_store.h"

#include <ccan/crc/crc.h>
#include <ccan/endian/endian.h>
#include <ccan/read_write_all/read_write_all.h>
#include <common/gossip_store.h>
#include <common/status.h>
#include <common/utils.h>
#include <errno.h>
#include <fcntl.h>
#include <gossipd/gen_gossip_peerd_wire.h>
#include <gossipd/gen_gossip_store.h>
#include <gossipd/gen_gossip_wire.h>
#include <stdio.h>
#include <unistd.h>
#include <wire/gen_peer_wire.h>
#include <wire/wire.h>

#define GOSSIP_STORE_FILENAME "gossip_store"
#define GOSSIP_STORE_TEMP_FILENAME "gossip_store.tmp"

struct gossip_store {
	/* This is false when we're loading */
	bool writable;

	int fd;
	u8 version;

	/* Offset of current EOF */
	u64 len;

	/* Counters for entries in the gossip_store entries. This is used to
	 * decide whether we should rewrite the on-disk store or not */
	size_t count;

	/* Handle to the routing_state to retrieve additional information,
	 * should it be needed */
	struct routing_state *rstate;

	/* Disable compaction if we encounter an error during a prior
	 * compaction */
	bool disable_compaction;
};

static void gossip_store_destroy(struct gossip_store *gs)
{
	close(gs->fd);
}

static bool append_msg(int fd, const u8 *msg, u64 *len)
{
	beint32_t hdr[2];
	u32 msglen;

	msglen = tal_count(msg);
	hdr[0] = cpu_to_be32(msglen);
	hdr[1] = cpu_to_be32(crc32c(0, msg, msglen));

	if (len)
		*len += sizeof(hdr) + msglen;

	return (write(fd, hdr, sizeof(hdr)) == sizeof(hdr) &&
		write(fd, msg, msglen) == msglen);
}

static bool upgrade_gs(struct gossip_store *gs)
{
	beint32_t hdr[2];
	size_t off = gs->len;
	int newfd;
	const u8 newversion = GOSSIP_STORE_VERSION;

	if (gs->version != 3)
		return false;

	newfd = open(GOSSIP_STORE_TEMP_FILENAME,
		     O_RDWR|O_APPEND|O_CREAT|O_TRUNC,
		     0600);
	if (newfd < 0) {
		status_broken("gossip_store: can't create temp %s: %s",
			       GOSSIP_STORE_TEMP_FILENAME, strerror(errno));
		return false;
	}

	if (!write_all(newfd, &newversion, sizeof(newversion))) {
		status_broken("gossip_store: can't write header to %s: %s",
			       GOSSIP_STORE_TEMP_FILENAME, strerror(errno));
		close(newfd);
		return false;
	}

	while (pread(gs->fd, hdr, sizeof(hdr), off) == sizeof(hdr)) {
		u32 msglen, checksum;
		u8 *msg, *gossip_msg;
		struct amount_sat satoshis;

		msglen = be32_to_cpu(hdr[0]);
		checksum = be32_to_cpu(hdr[1]);
		msg = tal_arr(tmpctx, u8, msglen);

		if (pread(gs->fd, msg, msglen, off+sizeof(hdr)) != msglen) {
			status_unusual("gossip_store: truncated file @%zu?",
				       off + sizeof(hdr));
			goto fail;
		}

		if (checksum != crc32c(0, msg, msglen)) {
			status_unusual("gossip_store: checksum failed");
			goto fail;
		}

		/* These need to be appended with channel size */
		if (fromwire_gossip_store_v3_channel_announcement(msg, msg,
								  &gossip_msg,
								  &satoshis)) {
			u8 *amt = towire_gossip_store_channel_amount(msg,
								     satoshis);
			if (!append_msg(newfd, gossip_msg, NULL))
				goto write_fail;
			if (!append_msg(newfd, amt, NULL))
				goto write_fail;
		/* These are extracted and copied verbatim */
		} else if (fromwire_gossip_store_v3_channel_update(msg, msg,
								   &gossip_msg)
			   || fromwire_gossip_store_v3_node_announcement(msg,
									 msg,
									 &gossip_msg)
			   || fromwire_gossip_store_v3_local_add_channel(msg,
									 msg,
									 &gossip_msg)) {
			if (!append_msg(newfd, gossip_msg, NULL))
				goto write_fail;
		} else {
			/* Just copy into new store. */
			if (write(newfd, hdr, sizeof(hdr)) != sizeof(hdr)
			    || write(newfd, msg, tal_bytelen(msg)) !=
			    tal_bytelen(msg))
				goto write_fail;
		}
		off += sizeof(hdr) + msglen;
		clean_tmpctx();
	}

	if (rename(GOSSIP_STORE_TEMP_FILENAME, GOSSIP_STORE_FILENAME) == -1) {
		status_broken(
		    "Error swapping compacted gossip_store into place: %s",
		    strerror(errno));
		goto fail;
	}

	status_info("Upgraded gossip_store from version %u to %u",
		    gs->version, newversion);
	close(gs->fd);
	gs->fd = newfd;
	gs->version = newversion;
	return true;

write_fail:
	status_unusual("gossip_store: write failed for upgrade: %s",
		       strerror(errno));
fail:
	close(newfd);
	return false;
}

struct gossip_store *gossip_store_new(struct routing_state *rstate)
{
	struct gossip_store *gs = tal(rstate, struct gossip_store);
	gs->count = 0;
	gs->writable = true;
	gs->fd = open(GOSSIP_STORE_FILENAME, O_RDWR|O_APPEND|O_CREAT, 0600);
	gs->rstate = rstate;
	gs->disable_compaction = false;
	gs->len = sizeof(gs->version);

	tal_add_destructor(gs, gossip_store_destroy);

	/* Try to read the version, write it if this is a new file, or truncate
	 * if the version doesn't match */
	if (read(gs->fd, &gs->version, sizeof(gs->version))
	    == sizeof(gs->version)) {
		/* Version match?  All good */
		if (gs->version == GOSSIP_STORE_VERSION)
			return gs;

		if (upgrade_gs(gs))
			return gs;

		status_unusual("Gossip store version %u not %u: removing",
			       gs->version, GOSSIP_STORE_VERSION);
		if (ftruncate(gs->fd, 0) != 0)
			status_failed(STATUS_FAIL_INTERNAL_ERROR,
				      "Truncating store: %s", strerror(errno));
	}
	/* Empty file, write version byte */
	gs->version = GOSSIP_STORE_VERSION;
	if (write(gs->fd, &gs->version, sizeof(gs->version))
	    != sizeof(gs->version))
		status_failed(STATUS_FAIL_INTERNAL_ERROR,
			      "Writing version to store: %s", strerror(errno));
	return gs;
}

/* Copy a whole message from one gossip_store to another.  Returns
 * total msg length including header, or 0 on error. */
static size_t copy_message(int in_fd, int out_fd, unsigned offset)
{
	beint32_t belen, becsum;
	u32 msglen;
	u8 *msg;

	/* FIXME: optimize both read and allocation */
	if (lseek(in_fd, offset, SEEK_SET) < 0
	    || read(in_fd, &belen, sizeof(belen)) != sizeof(belen)
	    || read(in_fd, &becsum, sizeof(becsum)) != sizeof(becsum)) {
		status_broken("Failed reading header from to gossip store @%u"
			      ": %s",
			      offset, strerror(errno));
		return 0;
	}

	msglen = be32_to_cpu(belen);
	msg = tal_arr(NULL, u8, sizeof(belen) + sizeof(becsum) + msglen);
	memcpy(msg, &belen, sizeof(belen));
	memcpy(msg + sizeof(belen), &becsum, sizeof(becsum));
	if (read(in_fd, msg + sizeof(belen) + sizeof(becsum), msglen)
	    != msglen) {
		status_broken("Failed reading %u from to gossip store @%u"
			      ": %s",
			      msglen, offset, strerror(errno));
		tal_free(msg);
		return 0;
	}

	if (write(out_fd, msg, msglen + sizeof(belen) + sizeof(becsum))
	    != msglen + sizeof(belen) + sizeof(becsum)) {
		status_broken("Failed writing to gossip store: %s",
			      strerror(errno));
		tal_free(msg);
		return 0;
	}

	tal_free(msg);
	return msglen + sizeof(belen) + sizeof(becsum);
}

/* Local unannounced channels don't appear in broadcast map, but we need to
 * remember them anyway, so we manually append to the store.
 *
 * Note these do *not* add to gs->count, since that's compared with
 * the broadcast map count.
*/
static bool add_local_unnannounced(int in_fd, int out_fd,
				   struct node *self,
				   u64 *len)
{
	struct chan_map_iter i;
	struct chan *c;

	for (c = first_chan(self, &i); c; c = next_chan(self, &i)) {
		struct node *peer = other_node(self, c);
		const u8 *msg;

		/* Ignore already announced. */
		if (is_chan_public(c))
			continue;

		msg = towire_gossipd_local_add_channel(tmpctx, &c->scid,
						       &peer->id, c->sat);
		if (!append_msg(out_fd, msg, len))
			return false;

		for (size_t i = 0; i < 2; i++) {
			size_t len_with_header;

			if (!is_halfchan_defined(&c->half[i]))
				continue;

			len_with_header = copy_message(in_fd, out_fd,
						       c->half[i].bcast.index);
			if (!len_with_header)
				return false;

			c->half[i].bcast.index = *len;

			*len += len_with_header;
		}
	}

	return true;
}

/* Returns bytes transferred, or 0 on error */
static size_t transfer_store_msg(int from_fd, size_t from_off, int to_fd,
				 int *type)
{
	beint32_t hdr[2];
	u32 msglen;
	u8 *msg;
	const u8 *p;
	size_t tmplen;

	if (pread(from_fd, hdr, sizeof(hdr), from_off) != sizeof(hdr)) {
		status_broken("Failed reading header from to gossip store @%zu"
			      ": %s",
			      from_off, strerror(errno));
		return 0;
	}

	msglen = be32_to_cpu(hdr[0]);
	/* FIXME: Reuse buffer? */
	msg = tal_arr(tmpctx, u8, sizeof(hdr) + msglen);
	memcpy(msg, hdr, sizeof(hdr));
	if (pread(from_fd, msg + sizeof(hdr), msglen, from_off + sizeof(hdr))
	    != msglen) {
		status_broken("Failed reading %u from to gossip store @%zu"
			      ": %s",
			      msglen, from_off, strerror(errno));
		return 0;
	}

	if (write(to_fd, msg, msglen + sizeof(hdr)) != msglen + sizeof(hdr)) {
		status_broken("Failed writing to gossip store: %s",
			      strerror(errno));
		return 0;
	}

	/* Can't use peektype here, since we have header on front */
	p = msg + sizeof(hdr);
	tmplen = msglen;
	*type = fromwire_u16(&p, &tmplen);
	if (!p)
		*type = -1;
	tal_free(msg);
	return sizeof(hdr) + msglen;
}

/**
 * Rewrite the on-disk gossip store, compacting it along the way
 *
 * Creates a new file, writes all the updates from the `broadcast_state`, and
 * then atomically swaps the files.
 *
 * Returns the amount of shrinkage in @offset on success, otherwise @offset
 * is unchanged.
 */
bool gossip_store_compact(struct gossip_store *gs,
			  struct broadcast_state **bs,
			  u32 *offset)
{
	size_t count = 0;
	int fd;
	struct node *self;
	u64 len = sizeof(gs->version);
	struct broadcastable *bcast;
	struct broadcast_state *oldb = *bs;
	struct broadcast_state *newb;
	u32 idx = 0;

	if (gs->disable_compaction)
		return false;

	assert(oldb);
	status_trace(
	    "Compacting gossip_store with %zu entries, %zu of which are stale",
	    gs->count, gs->count - oldb->count);

	newb = new_broadcast_state(gs->rstate, gs, oldb->peers);
	fd = open(GOSSIP_STORE_TEMP_FILENAME, O_RDWR|O_APPEND|O_CREAT, 0600);

	if (fd < 0) {
		status_broken(
		    "Could not open file for gossip_store compaction");
		goto disable;
	}

	if (write(fd, &gs->version, sizeof(gs->version))
	    != sizeof(gs->version)) {
		status_broken("Writing version to store: %s", strerror(errno));
		goto unlink_disable;
	}

	/* Copy entries one at a time. */
	while ((bcast = next_broadcast_raw(oldb, &idx)) != NULL) {
		u64 old_index = bcast->index;
		int msgtype;
		size_t msg_len;

		msg_len = transfer_store_msg(gs->fd, bcast->index, fd, &msgtype);
		if (msg_len == 0)
			goto unlink_disable;

		broadcast_del(oldb, bcast);
		bcast->index = len;
		insert_broadcast_nostore(newb, bcast);
		len += msg_len;
		count++;

		/* channel_announcement always followed by amount: copy too */
		if (msgtype == WIRE_CHANNEL_ANNOUNCEMENT) {
			msg_len = transfer_store_msg(gs->fd, old_index + msg_len,
						     fd, &msgtype);
			if (msg_len == 0)
				goto unlink_disable;
			if (msgtype != WIRE_GOSSIP_STORE_CHANNEL_AMOUNT) {
				status_broken("gossip_store: unexpected type %u",
					      msgtype);
				goto unlink_disable;
			}
			len += msg_len;
			/* This amount field doesn't add to count. */
		}
	}

	/* Local unannounced channels are not in the store! */
	self = get_node(gs->rstate, &gs->rstate->local_id);
	if (self && !add_local_unnannounced(gs->fd, fd, self, &len)) {
		status_broken("Failed writing unannounced to gossip store: %s",
			      strerror(errno));
		goto unlink_disable;
	}

	if (rename(GOSSIP_STORE_TEMP_FILENAME, GOSSIP_STORE_FILENAME) == -1) {
		status_broken(
		    "Error swapping compacted gossip_store into place: %s",
		    strerror(errno));
		goto unlink_disable;
	}

	status_trace(
	    "Compaction completed: dropped %zu messages, new count %zu, len %"PRIu64,
	    gs->count - count, count, len);
	gs->count = count;
	*offset = gs->len - len;
	gs->len = len;
	close(gs->fd);
	gs->fd = fd;

	tal_free(oldb);
	*bs = newb;
	return true;

unlink_disable:
	unlink(GOSSIP_STORE_TEMP_FILENAME);
disable:
	status_trace("Encountered an error while compacting, disabling "
		     "future compactions.");
	gs->disable_compaction = true;
	tal_free(newb);
	return false;
}

bool gossip_store_maybe_compact(struct gossip_store *gs,
				struct broadcast_state **bs,
				u32 *offset)
{
	*offset = 0;

	/* Don't compact while loading! */
	if (!gs->writable)
		return false;
	if (gs->count < 1000)
		return false;
	if (gs->count < (*bs)->count * 1.25)
		return false;

	return gossip_store_compact(gs, bs, offset);
}

u64 gossip_store_add(struct gossip_store *gs, const u8 *gossip_msg,
		     const u8 *addendum)
{
	u64 off = gs->len;

	/* Should never get here during loading! */
	assert(gs->writable);

	if (!append_msg(gs->fd, gossip_msg, &gs->len)) {
		status_broken("Failed writing to gossip store: %s",
			      strerror(errno));
		return 0;
	}
	if (addendum && !append_msg(gs->fd, addendum, &gs->len)) {
		status_broken("Failed writing addendum to gossip store: %s",
			      strerror(errno));
		return 0;
	}

	gs->count++;
	return off;
}

void gossip_store_add_channel_delete(struct gossip_store *gs,
				     const struct short_channel_id *scid)
{
	u8 *msg = towire_gossip_store_channel_delete(NULL, scid);

	/* Should never get here during loading! */
	assert(gs->writable);

	if (!append_msg(gs->fd, msg, &gs->len))
		status_failed(STATUS_FAIL_INTERNAL_ERROR,
			      "Failed writing channel_delete to gossip store: %s",
			      strerror(errno));
	tal_free(msg);
}

const u8 *gossip_store_get(const tal_t *ctx,
			   struct gossip_store *gs,
			   u64 offset)
{
	return gossip_store_read(ctx, gs->fd, offset);
}

int gossip_store_readonly_fd(struct gossip_store *gs)
{
	return open(GOSSIP_STORE_FILENAME, O_RDONLY);
}

void gossip_store_load(struct routing_state *rstate, struct gossip_store *gs)
{
	beint32_t hdr[2];
	u32 msglen, checksum;
	u8 *msg;
	struct amount_sat satoshis;
	struct short_channel_id scid;
	const char *bad;
	size_t stats[] = {0, 0, 0, 0};
	struct timeabs start = time_now();
	const u8 *chan_ann = NULL;
	u64 chan_ann_off;

	gs->writable = false;
	while (pread(gs->fd, hdr, sizeof(hdr), gs->len) == sizeof(hdr)) {
		msglen = be32_to_cpu(hdr[0]);
		checksum = be32_to_cpu(hdr[1]);
		msg = tal_arr(tmpctx, u8, msglen);

		if (pread(gs->fd, msg, msglen, gs->len+sizeof(hdr)) != msglen) {
			status_unusual("gossip_store: truncated file?");
			goto truncate_nomsg;
		}

		if (checksum != crc32c(0, msg, msglen)) {
			bad = "Checksum verification failed";
			goto truncate;
		}

		switch (fromwire_peektype(msg)) {
		case WIRE_GOSSIP_STORE_CHANNEL_AMOUNT:
			if (!fromwire_gossip_store_channel_amount(msg,
								  &satoshis)) {
				bad = "Bad gossip_store_channel_amount";
				goto truncate;
			}
			/* Should follow channel_announcement */
			if (!chan_ann) {
				bad = "gossip_store_channel_amount without"
					" channel_announcement";
				goto truncate;
			}
			if (!routing_add_channel_announcement(rstate,
							      take(chan_ann),
							      satoshis,
							      chan_ann_off)) {
				bad = "Bad channel_announcement";
				goto truncate;
			}
			chan_ann = NULL;
			stats[0]++;
			break;
		case WIRE_CHANNEL_ANNOUNCEMENT:
			if (chan_ann) {
				bad = "channel_announcement without amount";
				goto truncate;
			}
			/* Save for channel_amount (next msg) */
			chan_ann = tal_steal(gs, msg);
			chan_ann_off = gs->len;
			break;
		case WIRE_CHANNEL_UPDATE:
			if (!routing_add_channel_update(rstate,
							take(msg), gs->len)) {
				bad = "Bad channel_update";
				goto truncate;
			}
			stats[1]++;
			break;
		case WIRE_NODE_ANNOUNCEMENT:
			if (!routing_add_node_announcement(rstate,
							   take(msg), gs->len)) {
				bad = "Bad node_announcement";
				goto truncate;
			}
			stats[2]++;
			break;
		case WIRE_GOSSIP_STORE_CHANNEL_DELETE:
			if (!fromwire_gossip_store_channel_delete(msg, &scid)) {
				bad = "Bad channel_delete";
				goto truncate;
			}
			struct chan *c = get_channel(rstate, &scid);
			if (!c) {
				bad = "Bad channel_delete scid";
				goto truncate;
			}
			free_chan(rstate, c);
			stats[3]++;
			break;
		case WIRE_GOSSIPD_LOCAL_ADD_CHANNEL:
			if (!handle_local_add_channel(rstate, msg)) {
				bad = "Bad local_add_channel";
				goto truncate;
			}
			break;
		default:
			bad = "Unknown message";
			goto truncate;
		}
		gs->len += sizeof(hdr) + msglen;

		if (fromwire_peektype(msg) != WIRE_GOSSIP_STORE_CHANNEL_AMOUNT)
			gs->count++;
		clean_tmpctx();
	}
	goto out;

truncate:
	status_unusual("gossip_store: %s (%s) truncating to %"PRIu64,
		       bad, tal_hex(msg, msg), gs->len);
truncate_nomsg:
	/* FIXME: We would like to truncate to known_good, except we would
	 * miss channel_delete msgs.  If we put block numbers into the store
	 * as we process them, we can know how far we need to roll back if we
	 * truncate the store */
	if (ftruncate(gs->fd, gs->len) != 0)
		status_failed(STATUS_FAIL_INTERNAL_ERROR,
			      "Truncating store: %s", strerror(errno));
out:
	status_trace("total store load time: %"PRIu64" msec",
		     time_to_msec(time_between(time_now(), start)));
	status_trace("gossip_store: Read %zu/%zu/%zu/%zu cannounce/cupdate/nannounce/cdelete from store in %"PRIu64" bytes",
		     stats[0], stats[1], stats[2], stats[3],
		     gs->len);
	gs->writable = true;
}
