#include "config.h"
#include <ccan/array_size/array_size.h>
#include <ccan/crc32c/crc32c.h>
#include <ccan/noerr/noerr.h>
#include <ccan/read_write_all/read_write_all.h>
#include <ccan/tal/str/str.h>
#include <common/gossip_store.h>
#include <common/private_channel_announcement.h>
#include <common/status.h>
#include <errno.h>
#include <fcntl.h>
#include <gossipd/gossip_store.h>
#include <gossipd/gossip_store_wiregen.h>
#include <sys/stat.h>
#include <sys/uio.h>
#include <unistd.h>
#include <wire/peer_wire.h>

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

static bool append_msg(int fd, const u8 *msg, u32 timestamp,
		       bool push, u64 *len)
{
	struct gossip_hdr hdr;
	u32 msglen;
	struct iovec iov[2];

	/* Don't ever overwrite the version header! */
	assert(*len);

	msglen = tal_count(msg);
	hdr.len = cpu_to_be32(msglen);
	if (push)
		hdr.len |= CPU_TO_BE32(GOSSIP_STORE_LEN_PUSH_BIT);
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

#ifdef COMPAT_V082
static u8 *mk_private_channelmsg(const tal_t *ctx,
				 struct routing_state *rstate,
				 const struct short_channel_id *scid,
				 const struct node_id *remote_node_id,
				 struct amount_sat sat,
				 const u8 *features)
{
	const u8 *ann = private_channel_announcement(tmpctx, scid,
						     &rstate->local_id,
						     remote_node_id,
						     features);

	return towire_gossip_store_private_channel(ctx, sat, ann);
}

/* The upgrade from version 7 is trivial */
static bool can_upgrade(u8 oldversion)
{
	return oldversion == 7 || oldversion == 8;
}

static bool upgrade_field(u8 oldversion,
			  struct routing_state *rstate,
			  u8 **msg)
{
	assert(can_upgrade(oldversion));

	if (fromwire_peektype(*msg) == WIRE_GOSSIPD_LOCAL_ADD_CHANNEL_OBS
	    && oldversion == 7) {
		/* Append two 0 bytes, for (empty) feature bits */
		tal_resizez(msg, tal_bytelen(*msg) + 2);
	}

	/* We turn these (v8) into a WIRE_GOSSIP_STORE_PRIVATE_CHANNEL */
	if (fromwire_peektype(*msg) == WIRE_GOSSIPD_LOCAL_ADD_CHANNEL_OBS) {
		struct short_channel_id scid;
		struct node_id remote_node_id;
		struct amount_sat satoshis;
		u8 *features;
		u8 *storemsg;

		if (!fromwire_gossipd_local_add_channel_obs(tmpctx, *msg,
							&scid,
							&remote_node_id,
							&satoshis,
							&features))
			return false;

		storemsg = mk_private_channelmsg(tal_parent(*msg),
						 rstate,
						 &scid,
						 &remote_node_id,
						 satoshis,
						 features);
		tal_free(*msg);
		*msg = storemsg;
	}
	return true;
}
#else
static bool can_upgrade(u8 oldversion)
{
	return false;
}

static bool upgrade_field(u8 oldversion,
			  struct routing_state *rstate,
			  u8 **msg)
{
	abort();
}
#endif /* !COMPAT_V082 */

/* Read gossip store entries, copy non-deleted ones.  This code is written
 * as simply and robustly as possible! */
static u32 gossip_store_compact_offline(struct routing_state *rstate)
{
	size_t count = 0, deleted = 0;
	int old_fd, new_fd;
	u64 oldlen, newlen;
	struct gossip_hdr hdr;
	u8 oldversion, version = GOSSIP_STORE_VERSION;
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

		msglen = (be32_to_cpu(hdr.len) & GOSSIP_STORE_LEN_MASK);
		msg = tal_arr(NULL, u8, msglen);
		if (!read_all(old_fd, msg, msglen)) {
			status_broken("gossip_store_compact_offline: reading msg len %zu from store: %s",
				      msglen, strerror(errno));
			tal_free(msg);
			goto close_and_delete;
		}

		if (be32_to_cpu(hdr.len) & GOSSIP_STORE_LEN_DELETED_BIT) {
			deleted++;
			tal_free(msg);
			continue;
		}

		if (oldversion != version) {
			if (!upgrade_field(oldversion, rstate, &msg)) {
				tal_free(msg);
				goto close_and_delete;
			}

			/* Recalc msglen and header */
			msglen = tal_bytelen(msg);
			hdr.len = cpu_to_be32(msglen);
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
		   0, false, &oldlen);
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

struct gossip_store *gossip_store_new(struct routing_state *rstate,
				      struct list_head *peers)
{
	struct gossip_store *gs = tal(rstate, struct gossip_store);
	gs->count = gs->deleted = 0;
	gs->writable = true;
	gs->timestamp = gossip_store_compact_offline(rstate);
	gs->fd = open(GOSSIP_STORE_FILENAME, O_RDWR|O_CREAT, 0600);
	if (gs->fd < 0)
		status_failed(STATUS_FAIL_INTERNAL_ERROR,
			      "Opening gossip_store store: %s",
			      strerror(errno));
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
		/* Subtle: we are at offset 1, move back to start! */
		if (lseek(gs->fd, 0, SEEK_SET) != 0)
			status_failed(STATUS_FAIL_INTERNAL_ERROR,
				      "Seeking to start of store: %s",
				      strerror(errno));
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
static size_t transfer_store_msg(int from_fd, size_t from_off,
				 int to_fd, size_t to_off,
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

	/* Ignore any non-length bits (e.g. push) */
	msglen &= GOSSIP_STORE_LEN_MASK;

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

	if (pwrite(to_fd, msg, msglen + sizeof(hdr), to_off)
	    != msglen + sizeof(hdr)) {
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

	status_debug(
	    "Compacting gossip_store with %zu entries, %zu of which are stale",
	    gs->count, gs->deleted);

	fd = open(GOSSIP_STORE_TEMP_FILENAME, O_RDWR|O_TRUNC|O_CREAT, 0600);

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

		msglen = (be32_to_cpu(hdr.len) & GOSSIP_STORE_LEN_MASK);
		if (be32_to_cpu(hdr.len) & GOSSIP_STORE_LEN_DELETED_BIT) {
			off += sizeof(hdr) + msglen;
			deleted++;
			continue;
		}

		count++;
		wlen = transfer_store_msg(gs->fd, off, fd, len, &msgtype);
		if (wlen == 0)
			goto unlink_disable;

		/* We track location of all these message types. */
		if (msgtype == WIRE_GOSSIP_STORE_PRIVATE_CHANNEL
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

	if (count != gs->count - gs->deleted)
		status_failed(STATUS_FAIL_INTERNAL_ERROR,
			      "gossip_store: Expected %zu msgs in new"
			      " gossip store, got %zu",
			      gs->count - gs->deleted, count);

	if (deleted != gs->deleted)
		status_failed(STATUS_FAIL_INTERNAL_ERROR,
			      "gossip_store: Expected %zu deleted msgs in old"
			      " gossip store, got %zu",
			      gs->deleted, deleted);

	if (rename(GOSSIP_STORE_TEMP_FILENAME, GOSSIP_STORE_FILENAME) == -1)
		status_failed(STATUS_FAIL_INTERNAL_ERROR,
			      "Error swapping compacted gossip_store into place:"
			      " %s",
			      strerror(errno));

	status_debug(
	    "Compaction completed: dropped %zu messages, new count %zu, len %"PRIu64,
	    deleted, count, len);

	/* Write end marker now new one is ready */
	append_msg(gs->fd, towire_gossip_store_ended(tmpctx, len),
		   0, false, &gs->len);

	gs->count = count;
	gs->deleted = 0;
	gs->len = len;
	close(gs->fd);
	gs->fd = fd;

	return true;

unlink_disable:
	unlink(GOSSIP_STORE_TEMP_FILENAME);
disable:
	status_debug("Encountered an error while compacting, disabling "
		     "future compactions.");
	gs->disable_compaction = true;
	return false;
}

u64 gossip_store_add(struct gossip_store *gs, const u8 *gossip_msg,
		     u32 timestamp, bool push,
		     const u8 *addendum)
{
	u64 off = gs->len;

	/* Should never get here during loading! */
	assert(gs->writable);

	if (!append_msg(gs->fd, gossip_msg, timestamp, push, &gs->len)) {
		status_broken("Failed writing to gossip store: %s",
			      strerror(errno));
		return 0;
	}
	if (addendum && !append_msg(gs->fd, addendum, 0, false, &gs->len)) {
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
	return gossip_store_add(gs, pupdate, 0, false, NULL);
}

/* Returns index of following entry. */
static u32 delete_by_index(struct gossip_store *gs, u32 index, int type)
{
	beint32_t belen;

	/* Should never get here during loading! */
	assert(gs->writable);

	/* Should never try to overwrite version */
	assert(index);

#if DEVELOPER
	const u8 *msg = gossip_store_get(tmpctx, gs, index);
	assert(fromwire_peektype(msg) == type);
#endif

	if (pread(gs->fd, &belen, sizeof(belen), index) != sizeof(belen))
		status_failed(STATUS_FAIL_INTERNAL_ERROR,
			      "Failed reading len to delete @%u: %s",
			      index, strerror(errno));

	assert((be32_to_cpu(belen) & GOSSIP_STORE_LEN_DELETED_BIT) == 0);
	belen |= cpu_to_be32(GOSSIP_STORE_LEN_DELETED_BIT);
	if (pwrite(gs->fd, &belen, sizeof(belen), index) != sizeof(belen))
		status_failed(STATUS_FAIL_INTERNAL_ERROR,
			      "Failed writing len to delete @%u: %s",
			      index, strerror(errno));
	gs->deleted++;

	return index + sizeof(struct gossip_hdr)
		+ (be32_to_cpu(belen) & GOSSIP_STORE_LEN_MASK);
}

void gossip_store_delete(struct gossip_store *gs,
			 struct broadcastable *bcast,
			 int type)
{
	u32 next_index;

	if (!bcast->index)
		return;

	next_index = delete_by_index(gs, bcast->index, type);

	/* Reset index. */
	bcast->index = 0;

	/* For a channel_announcement, we need to delete amount too */
	if (type == WIRE_CHANNEL_ANNOUNCEMENT)
		delete_by_index(gs, next_index,
				WIRE_GOSSIP_STORE_CHANNEL_AMOUNT);
}

void gossip_store_mark_channel_deleted(struct gossip_store *gs,
				       const struct short_channel_id *scid)
{
	gossip_store_add(gs, towire_gossip_store_delete_chan(tmpctx, scid),
			 0, false, NULL);
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

	if (be32_to_cpu(hdr.len) & GOSSIP_STORE_LEN_DELETED_BIT)
		status_failed(STATUS_FAIL_INTERNAL_ERROR,
			      "gossip_store: get delete entry offset %"PRIu64
			      "/%"PRIu64"",
			      offset, gs->len);

	msglen = (be32_to_cpu(hdr.len) & GOSSIP_STORE_LEN_MASK);
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

u32 gossip_store_load(struct routing_state *rstate, struct gossip_store *gs)
{
	struct gossip_hdr hdr;
	u32 msglen, checksum;
	u8 *msg;
	struct amount_sat satoshis;
	const char *bad;
	size_t stats[] = {0, 0, 0, 0};
	struct timeabs start = time_now();
	u8 *chan_ann = NULL;
	u64 chan_ann_off = 0; /* Spurious gcc-9 (Ubuntu 9-20190402-1ubuntu1) 9.0.1 20190402 (experimental) warning */

	gs->writable = false;
	while (pread(gs->fd, &hdr, sizeof(hdr), gs->len) == sizeof(hdr)) {
		msglen = be32_to_cpu(hdr.len) & GOSSIP_STORE_LEN_MASK;
		checksum = be32_to_cpu(hdr.crc);
		msg = tal_arr(tmpctx, u8, msglen);

		if (pread(gs->fd, msg, msglen, gs->len+sizeof(hdr)) != msglen) {
			bad = "gossip_store: truncated file?";
			goto corrupt;
		}

		if (checksum != crc32c(be32_to_cpu(hdr.timestamp), msg, msglen)) {
			bad = "Checksum verification failed";
			goto badmsg;
		}

		/* Skip deleted entries */
		if (be32_to_cpu(hdr.len) & GOSSIP_STORE_LEN_DELETED_BIT) {
			/* Count includes deleted! */
			gs->count++;
			gs->deleted++;
			goto next;
		}

		switch (fromwire_peektype(msg)) {
		case WIRE_GOSSIP_STORE_PRIVATE_CHANNEL: {
			u8 *chan_ann;
			struct amount_sat sat;
			if (!fromwire_gossip_store_private_channel(msg, msg,
								   &sat,
								   &chan_ann)) {
				bad = "Bad private_channel";
				goto badmsg;
			}

			if (!routing_add_private_channel(rstate, NULL,
							 sat, chan_ann,
							 gs->len)) {
				bad = "Bad add_private_channel";
				goto badmsg;
			}
			stats[0]++;
			break;
		}
		case WIRE_GOSSIP_STORE_CHANNEL_AMOUNT:
			if (!fromwire_gossip_store_channel_amount(msg,
								  &satoshis)) {
				bad = "Bad gossip_store_channel_amount";
				goto badmsg;
			}
			/* Previous channel_announcement may have been deleted */
			if (!chan_ann)
				break;
			if (!routing_add_channel_announcement(rstate,
							      take(chan_ann),
							      satoshis,
							      chan_ann_off,
							      NULL)) {
				bad = "Bad channel_announcement";
				goto badmsg;
			}
			chan_ann = NULL;
			stats[0]++;
			break;
		case WIRE_CHANNEL_ANNOUNCEMENT:
			if (chan_ann) {
				bad = "channel_announcement without amount";
				goto badmsg;
			}
			/* Save for channel_amount (next msg) */
			chan_ann = tal_steal(gs, msg);
			chan_ann_off = gs->len;
			break;
		case WIRE_GOSSIP_STORE_PRIVATE_UPDATE:
			if (!fromwire_gossip_store_private_update(tmpctx, msg, &msg)) {
				bad = "invalid gossip_store_private_update";
				goto badmsg;
			}
			/* fall thru */
		case WIRE_CHANNEL_UPDATE:
			if (!routing_add_channel_update(rstate,
							take(msg), gs->len,
							NULL, false)) {
				bad = "Bad channel_update";
				goto badmsg;
			}
			stats[1]++;
			break;
		case WIRE_NODE_ANNOUNCEMENT:
			if (!routing_add_node_announcement(rstate,
							   take(msg), gs->len,
							   NULL, NULL)) {
				bad = "Bad node_announcement";
				goto badmsg;
			}
			stats[2]++;
			break;
		default:
			bad = "Unknown message";
			goto badmsg;
		}

		gs->count++;
	next:
		gs->len += sizeof(hdr) + msglen;
		clean_tmpctx();
	}

	if (chan_ann) {
		bad = "dangling channel_announcement";
		goto corrupt;
	}

	bad = unfinalized_entries(tmpctx, rstate);
	if (bad)
		goto corrupt;

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
	remove_all_gossip(rstate);
	gs->count = gs->deleted = 0;
	gs->len = 1;
	gs->timestamp = 0;
out:
	gs->writable = true;
	status_debug("total store load time: %"PRIu64" msec",
		     time_to_msec(time_between(time_now(), start)));
	status_debug("gossip_store: Read %zu/%zu/%zu/%zu cannounce/cupdate/nannounce/cdelete from store (%zu deleted) in %"PRIu64" bytes",
		     stats[0], stats[1], stats[2], stats[3], gs->deleted,
		     gs->len);

	return gs->timestamp;
}
