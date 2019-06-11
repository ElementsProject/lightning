#include "gossip_store.h"

#include <ccan/array_size/array_size.h>
#include <ccan/crc/crc.h>
#include <ccan/endian/endian.h>
#include <ccan/noerr/noerr.h>
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
#include <sys/uio.h>
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
	 * decide whether we should rewrite the on-disk store or not.
	 * Note: count includes deleted. */
	size_t count, deleted;

	/* Handle to the routing_state to retrieve additional information,
	 * should it be needed */
	struct routing_state *rstate;

	/* This is daemon->peers for handling to update_peers_broadcast_index */
	struct list_head *peers;

	/* Disable compaction if we encounter an error during a prior
	 * compaction */
	bool disable_compaction;
};

static void gossip_store_destroy(struct gossip_store *gs)
{
	close(gs->fd);
}

static bool append_msg(int fd, const u8 *msg, u32 timestamp, u64 *len)
{
	struct gossip_hdr hdr;
	u32 msglen;
	struct iovec iov[2];

	msglen = tal_count(msg);
	hdr.len = cpu_to_be32(msglen);
	hdr.crc = cpu_to_be32(crc32c(timestamp, msg, msglen));
	hdr.timestamp = cpu_to_be32(timestamp);

	if (len)
		*len += sizeof(hdr) + msglen;

	/* Use writev so it will appear in store atomically */
	iov[0].iov_base = &hdr;
	iov[0].iov_len = sizeof(hdr);
	iov[1].iov_base = (void *)msg;
	iov[1].iov_len = msglen;
	return writev(fd, iov, ARRAY_SIZE(iov)) == sizeof(hdr) + msglen;
}

struct gossip_store *gossip_store_new(struct routing_state *rstate,
				      struct list_head *peers)
{
	struct gossip_store *gs = tal(rstate, struct gossip_store);
	gs->count = gs->deleted = 0;
	gs->writable = true;
	gs->fd = open(GOSSIP_STORE_FILENAME, O_RDWR|O_APPEND|O_CREAT, 0600);
	gs->rstate = rstate;
	gs->disable_compaction = false;
	gs->len = sizeof(gs->version);
	gs->peers = peers;

	tal_add_destructor(gs, gossip_store_destroy);

	/* Try to read the version, write it if this is a new file, or truncate
	 * if the version doesn't match */
	if (read(gs->fd, &gs->version, sizeof(gs->version))
	    == sizeof(gs->version)) {
		/* Version match?  All good */
		if (gs->version == GOSSIP_STORE_VERSION)
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

/* Returns bytes transferred, or 0 on error */
static size_t transfer_store_msg(int from_fd, size_t from_off, int to_fd,
				 int *type)
{
	struct gossip_hdr hdr;
	u32 msglen;
	u8 *msg;
	const u8 *p;
	size_t tmplen;

	*type = -1;
	if (pread(from_fd, &hdr, sizeof(hdr), from_off) != sizeof(hdr)) {
		status_broken("Failed reading header from to gossip store @%zu"
			      ": %s",
			      from_off, strerror(errno));
		return 0;
	}

	msglen = be32_to_cpu(hdr.len);
	if (msglen & GOSSIP_STORE_LEN_DELETED_BIT) {
		status_broken("Can't transfer deleted msg from gossip store @%zu",
			      from_off);
		return 0;
	}

	/* FIXME: Reuse buffer? */
	msg = tal_arr(tmpctx, u8, sizeof(hdr) + msglen);
	memcpy(msg, &hdr, sizeof(hdr));
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

/* We keep a htable map of old gossip_store offsets to new ones. */
struct offset_map {
	size_t from, to;
};

static size_t offset_map_key(const struct offset_map *omap)
{
	return omap->from;
}

static size_t hash_offset(size_t from)
{
	/* Crappy fast hash is "good enough" */
	return (from >> 5) ^ from;
}

static bool offset_map_eq(const struct offset_map *omap, const size_t from)
{
	return omap->from == from;
}
HTABLE_DEFINE_TYPE(struct offset_map,
		   offset_map_key, hash_offset, offset_map_eq, offmap);

static void move_broadcast(struct offmap *offmap,
			   struct broadcastable *bcast,
			   const char *what)
{
	struct offset_map *omap;

	if (!bcast->index)
		return;

	omap = offmap_get(offmap, bcast->index);
	if (!omap)
		status_failed(STATUS_FAIL_INTERNAL_ERROR,
			      "Could not relocate %s at offset %u",
			      what, bcast->index);
	bcast->index = omap->to;
	offmap_del(offmap, omap);
}

static void destroy_offmap(struct offmap *offmap)
{
	offmap_clear(offmap);
}

/**
 * Rewrite the on-disk gossip store, compacting it along the way
 *
 * Creates a new file, writes all the updates from the `broadcast_state`, and
 * then atomically swaps the files.
 */
bool gossip_store_compact(struct gossip_store *gs)
{
	size_t count = 0, deleted = 0;
	int fd;
	u64 off, len = sizeof(gs->version), idx;
	struct offmap *offmap;
	struct gossip_hdr hdr;
	struct offmap_iter oit;
	struct node_map_iter nit;
	struct offset_map *omap;

	if (gs->disable_compaction)
		return false;

	status_trace(
	    "Compacting gossip_store with %zu entries, %zu of which are stale",
	    gs->count, gs->deleted);

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

	/* Walk old file, copy everything and remember new offsets. */
	offmap = tal(tmpctx, struct offmap);
	offmap_init_sized(offmap, gs->count);
	tal_add_destructor(offmap, destroy_offmap);

	/* Start by writing all channel announcements and updates. */
	off = 1;
	while (pread(gs->fd, &hdr, sizeof(hdr), off) == sizeof(hdr)) {
		u32 msglen, wlen;
		int msgtype;

		msglen = (be32_to_cpu(hdr.len) & ~GOSSIP_STORE_LEN_DELETED_BIT);
		if (be32_to_cpu(hdr.len) & GOSSIP_STORE_LEN_DELETED_BIT) {
			off += sizeof(hdr) + msglen;
			deleted++;
			continue;
		}

		count++;
		wlen = transfer_store_msg(gs->fd, off, fd, &msgtype);
		if (wlen == 0)
			goto unlink_disable;

		/* We track location of all these message types. */
		if (msgtype == WIRE_GOSSIPD_LOCAL_ADD_CHANNEL
		    || msgtype == WIRE_GOSSIP_STORE_PRIVATE_UPDATE
		    || msgtype == WIRE_CHANNEL_ANNOUNCEMENT
		    || msgtype == WIRE_CHANNEL_UPDATE
		    || msgtype == WIRE_NODE_ANNOUNCEMENT) {
			omap = tal(offmap, struct offset_map);
			omap->from = off;
			omap->to = len;
			offmap_add(offmap, omap);
		}
		len += wlen;
		off += wlen;
	}

	/* OK, now we've written file successfully, we can move broadcasts. */
	/* Remap node announcements. */
	for (struct node *n = node_map_first(gs->rstate->nodes, &nit);
	     n;
	     n = node_map_next(gs->rstate->nodes, &nit)) {
		move_broadcast(offmap, &n->bcast, "node_announce");
	}

	/* Remap channel announcements and updates */
	for (struct chan *c = uintmap_first(&gs->rstate->chanmap, &idx);
	     c;
	     c = uintmap_after(&gs->rstate->chanmap, &idx)) {
		move_broadcast(offmap, &c->bcast, "channel_announce");
		move_broadcast(offmap, &c->half[0].bcast, "channel_update");
		move_broadcast(offmap, &c->half[1].bcast, "channel_update");
	}

	/* That should be everything. */
	omap = offmap_first(offmap, &oit);
	if (omap)
		status_failed(STATUS_FAIL_INTERNAL_ERROR,
			      "gossip_store: Entry at %zu->%zu not updated?",
			      omap->from, omap->to);

	if (count != gs->count - gs->deleted) {
		status_broken("Expected %zu msgs in new gossip store, got %zu",
			      gs->count - gs->deleted, count);
		goto unlink_disable;
	}

	if (deleted != gs->deleted) {
		status_broken("Expected %zu deleted msgs in old gossip store, got %zu",
			      gs->deleted, deleted);
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
	    deleted, count, len);
	gs->count = count;
	gs->deleted = 0;
	off = gs->len - len;
	gs->len = len;
	close(gs->fd);
	gs->fd = fd;

	update_peers_broadcast_index(gs->peers, off);
	return true;

unlink_disable:
	unlink(GOSSIP_STORE_TEMP_FILENAME);
disable:
	status_trace("Encountered an error while compacting, disabling "
		     "future compactions.");
	gs->disable_compaction = true;
	return false;
}

static void gossip_store_maybe_compact(struct gossip_store *gs)
{
	/* Don't compact while loading! */
	if (!gs->writable)
		return;
	if (gs->count < 1000)
		return;
	if (gs->deleted < gs->count / 4)
		return;

	gossip_store_compact(gs);
}

u64 gossip_store_add(struct gossip_store *gs, const u8 *gossip_msg,
		     u32 timestamp,
		     const u8 *addendum)
{
	u64 off = gs->len;

	/* Should never get here during loading! */
	assert(gs->writable);

	if (!append_msg(gs->fd, gossip_msg, timestamp, &gs->len)) {
		status_broken("Failed writing to gossip store: %s",
			      strerror(errno));
		return 0;
	}
	if (addendum && !append_msg(gs->fd, addendum, 0, &gs->len)) {
		status_broken("Failed writing addendum to gossip store: %s",
			      strerror(errno));
		return 0;
	}

	gs->count++;
	if (addendum)
		gs->count++;
	return off;
}

u64 gossip_store_add_private_update(struct gossip_store *gs, const u8 *update)
{
	/* A local update for an unannounced channel: not broadcastable, but
	 * otherwise the same as a normal channel_update */
	const u8 *pupdate = towire_gossip_store_private_update(tmpctx, update);
	return gossip_store_add(gs, pupdate, 0, NULL);
}

void gossip_store_delete(struct gossip_store *gs,
			 struct broadcastable *bcast,
			 int type)
{
	beint32_t belen;
	int flags;

	if (!bcast->index)
		return;

	/* Should never get here during loading! */
	assert(gs->writable);

#if DEVELOPER
	const u8 *msg = gossip_store_get(tmpctx, gs, bcast->index);
	assert(fromwire_peektype(msg) == type);
#endif
	if (pread(gs->fd, &belen, sizeof(belen), bcast->index) != sizeof(belen))
		status_failed(STATUS_FAIL_INTERNAL_ERROR,
			      "Failed reading len to delete @%u: %s",
			      bcast->index, strerror(errno));

	assert((be32_to_cpu(belen) & GOSSIP_STORE_LEN_DELETED_BIT) == 0);
	belen |= cpu_to_be32(GOSSIP_STORE_LEN_DELETED_BIT);
	/* From man pwrite(2):
	 *
	 * BUGS
	 *  POSIX requires that opening a file with the O_APPEND flag  should
	 *  have no  effect  on the location at which pwrite() writes data.
	 *  However, on Linux, if a file is opened with O_APPEND, pwrite()
	 *  appends data to  the end of the file, regardless of the value of
	 *  offset.
	 */
	flags = fcntl(gs->fd, F_GETFL);
	fcntl(gs->fd, F_SETFL, flags & ~O_APPEND);
	if (pwrite(gs->fd, &belen, sizeof(belen), bcast->index) != sizeof(belen))
		status_failed(STATUS_FAIL_INTERNAL_ERROR,
			      "Failed writing len to delete @%u: %s",
			      bcast->index, strerror(errno));
	fcntl(gs->fd, F_SETFL, flags);
	gs->deleted++;

	/* Reset index. */
	bcast->index = 0;

	gossip_store_maybe_compact(gs);
}

const u8 *gossip_store_get(const tal_t *ctx,
			   struct gossip_store *gs,
			   u64 offset)
{
	struct gossip_hdr hdr;
	u32 msglen, checksum;
	u8 *msg;

	if (offset == 0)
		status_failed(STATUS_FAIL_INTERNAL_ERROR,
			      "gossip_store: can't access offset %"PRIu64,
			      offset);
	if (pread(gs->fd, &hdr, sizeof(hdr), offset) != sizeof(hdr)) {
		status_failed(STATUS_FAIL_INTERNAL_ERROR,
			      "gossip_store: can't read hdr offset %"PRIu64
			      "/%"PRIu64": %s",
			      offset, gs->len, strerror(errno));
	}

	/* FIXME: We should skip over these deleted entries! */
	msglen = be32_to_cpu(hdr.len) & ~GOSSIP_STORE_LEN_DELETED_BIT;
	checksum = be32_to_cpu(hdr.crc);
	msg = tal_arr(ctx, u8, msglen);
	if (pread(gs->fd, msg, msglen, offset + sizeof(hdr)) != msglen)
		status_failed(STATUS_FAIL_INTERNAL_ERROR,
			      "gossip_store: can't read len %u offset %"PRIu64
			      "/%"PRIu64, msglen, offset, gs->len);

	if (checksum != crc32c(be32_to_cpu(hdr.timestamp), msg, msglen))
		status_failed(STATUS_FAIL_INTERNAL_ERROR,
			      "gossip_store: bad checksum offset %"PRIu64": %s",
			      offset, tal_hex(tmpctx, msg));

	return msg;
}

const u8 *gossip_store_get_private_update(const tal_t *ctx,
					  struct gossip_store *gs,
					  u64 offset)
{
	const u8 *pmsg = gossip_store_get(tmpctx, gs, offset);
	u8 *msg;

	if (!fromwire_gossip_store_private_update(ctx, pmsg, &msg))
		status_failed(STATUS_FAIL_INTERNAL_ERROR,
			      "Failed to decode private update @%"PRIu64": %s",
			      offset, tal_hex(tmpctx, pmsg));
	return msg;
}

int gossip_store_readonly_fd(struct gossip_store *gs)
{
	int fd = open(GOSSIP_STORE_FILENAME, O_RDONLY);

	/* Skip over version header */
	if (fd != -1 && lseek(fd, 1, SEEK_SET) != 1) {
		close_noerr(fd);
		fd = -1;
	}
	return fd;
}

bool gossip_store_load(struct routing_state *rstate, struct gossip_store *gs)
{
	struct gossip_hdr hdr;
	u32 msglen, checksum;
	u8 *msg;
	struct amount_sat satoshis;
	const char *bad;
	size_t stats[] = {0, 0, 0, 0};
	struct timeabs start = time_now();
	const u8 *chan_ann = NULL;
	bool contents_ok;
	u32 last_timestamp = 0;
	u64 chan_ann_off = 0; /* Spurious gcc-9 (Ubuntu 9-20190402-1ubuntu1) 9.0.1 20190402 (experimental) warning */

	gs->writable = false;
	while (pread(gs->fd, &hdr, sizeof(hdr), gs->len) == sizeof(hdr)) {
		msglen = be32_to_cpu(hdr.len) & ~GOSSIP_STORE_LEN_DELETED_BIT;
		checksum = be32_to_cpu(hdr.crc);
		msg = tal_arr(tmpctx, u8, msglen);

		if (pread(gs->fd, msg, msglen, gs->len+sizeof(hdr)) != msglen) {
			status_unusual("gossip_store: truncated file?");
			goto truncate_nomsg;
		}

		if (checksum != crc32c(be32_to_cpu(hdr.timestamp), msg, msglen)) {
			bad = "Checksum verification failed";
			goto truncate;
		}

		/* Skip deleted entries */
		if (be32_to_cpu(hdr.len) & GOSSIP_STORE_LEN_DELETED_BIT) {
			gs->deleted++;
			goto next;
		}

		switch (fromwire_peektype(msg)) {
		case WIRE_GOSSIP_STORE_CHANNEL_AMOUNT:
			if (!fromwire_gossip_store_channel_amount(msg,
								  &satoshis)) {
				bad = "Bad gossip_store_channel_amount";
				goto truncate;
			}
			/* Previous channel_announcement may have been deleted */
			if (!chan_ann)
				break;
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
			/* If we have a channel_announcement, that's a reasonable
			 * timestamp to use. */
			last_timestamp = be32_to_cpu(hdr.timestamp);
			break;
		case WIRE_GOSSIP_STORE_PRIVATE_UPDATE:
			if (!fromwire_gossip_store_private_update(tmpctx, msg, &msg)) {
				bad = "invalid gossip_store_private_update";
				goto truncate;
			}
			/* fall thru */
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
		case WIRE_GOSSIPD_LOCAL_ADD_CHANNEL:
			if (!handle_local_add_channel(rstate, msg, gs->len)) {
				bad = "Bad local_add_channel";
				goto truncate;
			}
			break;
		default:
			bad = "Unknown message";
			goto truncate;
		}

		gs->count++;
	next:
		gs->len += sizeof(hdr) + msglen;
		clean_tmpctx();
	}

	/* If last timestamp is within 24 hours, say we're OK. */
	contents_ok = (last_timestamp >= time_now().ts.tv_sec - 24*3600);
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
	contents_ok = false;
out:
	gs->writable = true;
	/* If we ever truncated, we might have a dangling channel_announce */
	if (chan_ann) {
		struct broadcastable bcast;
		bcast.index = chan_ann_off;
		status_unusual("Deleting un-updated channel_announcement @%"
			       PRIu64, chan_ann_off);
		gossip_store_delete(gs, &bcast, WIRE_CHANNEL_ANNOUNCEMENT);
	}
	status_trace("total store load time: %"PRIu64" msec",
		     time_to_msec(time_between(time_now(), start)));
	status_trace("gossip_store: Read %zu/%zu/%zu/%zu cannounce/cupdate/nannounce/cdelete from store (%zu deleted) in %"PRIu64" bytes",
		     stats[0], stats[1], stats[2], stats[3], gs->deleted,
		     gs->len);

	return contents_ok;
}
