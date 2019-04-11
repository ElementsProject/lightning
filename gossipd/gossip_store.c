#include "gossip_store.h"

#include <ccan/crc/crc.h>
#include <ccan/endian/endian.h>
#include <ccan/read_write_all/read_write_all.h>
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

static u8 *gossip_store_wrap_channel_announcement(const tal_t *ctx,
						  struct routing_state *rstate,
						  const u8 *gossip_msg)
{
	secp256k1_ecdsa_signature node_signature_1, node_signature_2;
	secp256k1_ecdsa_signature bitcoin_signature_1, bitcoin_signature_2;
	u8 *features;
	struct bitcoin_blkid chain_hash;
	struct short_channel_id scid;
	struct node_id node_id_1;
	struct node_id node_id_2;
	struct pubkey bitcoin_key_1;
	struct pubkey bitcoin_key_2;

	/* Which channel are we talking about here? */
	if (!fromwire_channel_announcement(
		tmpctx, gossip_msg, &node_signature_1, &node_signature_2,
		&bitcoin_signature_1, &bitcoin_signature_2, &features,
		&chain_hash, &scid, &node_id_1, &node_id_2, &bitcoin_key_1,
		&bitcoin_key_2))
		status_failed(STATUS_FAIL_INTERNAL_ERROR,
			      "Error parsing channel_announcement");

	struct chan *chan = get_channel(rstate, &scid);
	assert(chan && amount_sat_greater(chan->sat, AMOUNT_SAT(0)));

	u8 *msg = towire_gossip_store_channel_announcement(ctx, gossip_msg,
							   chan->sat);
	return msg;
}

/**
 * Wrap the raw gossip message and write it to fd
 *
 * @param fd File descriptor to write the wrapped message into
 * @param rstate Routing state if we need to look up channel capacity
 * @param gossip_msg The message to write
 * @param len The length to increase by amount written.
 * @return true if the message was wrapped and written
 */
static bool gossip_store_append(int fd,
				struct routing_state *rstate,
				const u8 *gossip_msg,
				u64 *len)
{
	int t =  fromwire_peektype(gossip_msg);
	u32 msglen;
	beint32_t checksum, belen;
	const u8 *msg;

	if (t == WIRE_CHANNEL_ANNOUNCEMENT)
		msg = gossip_store_wrap_channel_announcement(tmpctx, rstate, gossip_msg);
	else if(t == WIRE_CHANNEL_UPDATE)
		msg = towire_gossip_store_channel_update(tmpctx, gossip_msg);
	else if(t == WIRE_NODE_ANNOUNCEMENT)
		msg = towire_gossip_store_node_announcement(tmpctx, gossip_msg);
	else if(t == WIRE_GOSSIPD_LOCAL_ADD_CHANNEL)
		msg = towire_gossip_store_local_add_channel(tmpctx, gossip_msg);
	else if(t == WIRE_GOSSIP_STORE_CHANNEL_DELETE)
		msg = gossip_msg;
	else {
		status_trace("Unexpected message passed to gossip_store: %s",
			     wire_type_name(t));
		return false;
	}

	msglen = tal_count(msg);
	belen = cpu_to_be32(msglen);
	checksum = cpu_to_be32(crc32c(0, msg, msglen));

	*len += sizeof(belen) + sizeof(checksum) + msglen;

	return (write(fd, &belen, sizeof(belen)) == sizeof(belen) &&
		write(fd, &checksum, sizeof(checksum)) == sizeof(checksum) &&
		write(fd, msg, msglen) == msglen);
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
				   struct routing_state *rstate,
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
		if (!gossip_store_append(out_fd, rstate, msg, len))
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
		beint32_t hdr[2];
		u32 msglen;
		u8 *msg;

		if (pread(gs->fd, hdr, sizeof(hdr), bcast->index) != sizeof(hdr)) {
			status_broken("Failed reading header from to gossip store @%u"
				      ": %s",
				      bcast->index, strerror(errno));
			goto unlink_disable;
		}

		msglen = be32_to_cpu(hdr[0]);
		/* FIXME: Reuse buffer? */
		msg = tal_arr(tmpctx, u8, sizeof(hdr) + msglen);
		memcpy(msg, hdr, sizeof(hdr));
		if (pread(gs->fd, msg + sizeof(hdr), msglen,
			  bcast->index + sizeof(hdr))
		    != msglen) {
			status_broken("Failed reading %u from to gossip store @%u"
				      ": %s",
				      msglen, bcast->index, strerror(errno));
			goto unlink_disable;
		}

		broadcast_del(oldb, bcast);
		bcast->index = len;
		insert_broadcast_nostore(newb, bcast);

		if (write(fd, msg, msglen + sizeof(hdr))
		    != msglen + sizeof(hdr)) {
			status_broken("Failed writing to gossip store: %s",
				      strerror(errno));
			goto unlink_disable;
		}
		len += sizeof(hdr) + msglen;
		count++;
	}

	/* Local unannounced channels are not in the store! */
	self = get_node(gs->rstate, &gs->rstate->local_id);
	if (self && !add_local_unnannounced(gs->fd, fd, gs->rstate, self,
					    &len)) {
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

void gossip_store_maybe_compact(struct gossip_store *gs,
				struct broadcast_state **bs,
				u32 *offset)
{
	*offset = 0;

	/* Don't compact while loading! */
	if (!gs->writable)
		return;
	if (gs->count < 1000)
		return;
	if (gs->count < (*bs)->count * 1.25)
		return;

	gossip_store_compact(gs, bs, offset);
}

u64 gossip_store_add(struct gossip_store *gs, const u8 *gossip_msg)
{
	u64 off = gs->len;

	/* Should never get here during loading! */
	assert(gs->writable);

	if (!gossip_store_append(gs->fd, gs->rstate, gossip_msg, &gs->len)) {
		status_broken("Failed writing to gossip store: %s",
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

	if (!gossip_store_append(gs->fd, gs->rstate, msg, &gs->len))
		status_failed(STATUS_FAIL_INTERNAL_ERROR,
			      "Failed writing channel_delete to gossip store: %s",
			      strerror(errno));
	tal_free(msg);
}

const u8 *gossip_store_get(const tal_t *ctx,
			   struct gossip_store *gs,
			   u64 offset)
{
	beint32_t hdr[2];
	u32 msglen, checksum;
	u8 *msg, *gossip_msg;
	struct amount_sat satoshis;

	if (offset == 0 || offset > gs->len)
		status_failed(STATUS_FAIL_INTERNAL_ERROR,
			      "gossip_store: can't access offset %"PRIu64
			      ", store len %"PRIu64,
			      offset, gs->len);
	if (pread(gs->fd, hdr, sizeof(hdr), offset) != sizeof(hdr)) {
		status_failed(STATUS_FAIL_INTERNAL_ERROR,
			      "gossip_store: can't read hdr offset %"PRIu64
			      ", store len %"PRIu64": %s",
			      offset, gs->len, strerror(errno));
	}

	msglen = be32_to_cpu(hdr[0]);
	checksum = be32_to_cpu(hdr[1]);
	msg = tal_arr(tmpctx, u8, msglen);
	if (pread(gs->fd, msg, msglen, offset + sizeof(hdr)) != msglen)
		status_failed(STATUS_FAIL_INTERNAL_ERROR,
			      "gossip_store: can't read len %u offset %"PRIu64
			      ", store len %"PRIu64,
			      msglen, offset, gs->len);

	if (checksum != crc32c(0, msg, msglen))
		status_failed(STATUS_FAIL_INTERNAL_ERROR,
			      "gossip_store: bad checksum offset %"PRIu64
			      ", store len %"PRIu64,
			      offset, gs->len);

	/* Now try decoding it */
	if (!fromwire_gossip_store_node_announcement(ctx, msg, &gossip_msg)
	    && !fromwire_gossip_store_channel_announcement(ctx, msg,
							   &gossip_msg,
							   &satoshis)
	    && !fromwire_gossip_store_channel_update(ctx, msg, &gossip_msg)) {
		status_failed(STATUS_FAIL_INTERNAL_ERROR,
			      "gossip_store: bad message %s offset %"PRIu64
			      " from store len %"PRIu64,
			      tal_hex(tmpctx, msg), offset, gs->len);
	}
	return gossip_msg;
}

void gossip_store_load(struct routing_state *rstate, struct gossip_store *gs)
{
	beint32_t hdr[2];
	u32 msglen, checksum;
	u8 *msg, *gossip_msg;
	struct amount_sat satoshis;
	struct short_channel_id scid;
	const char *bad;
	size_t stats[] = {0, 0, 0, 0};
	struct timeabs start = time_now();

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

		if (fromwire_gossip_store_channel_announcement(msg, msg,
							       &gossip_msg,
							       &satoshis)) {
			if (!routing_add_channel_announcement(rstate,
							      take(gossip_msg),
							      satoshis,
							      gs->len)) {
				bad = "Bad channel_announcement";
				goto truncate;
			}
			stats[0]++;
		} else if (fromwire_gossip_store_channel_update(msg, msg,
								&gossip_msg)) {
			if (!routing_add_channel_update(rstate,
							take(gossip_msg),
							gs->len)) {
				bad = "Bad channel_update";
				goto truncate;
			}
			stats[1]++;
		} else if (fromwire_gossip_store_node_announcement(msg, msg,
								   &gossip_msg)) {
			if (!routing_add_node_announcement(rstate,
							   take(gossip_msg),
							   gs->len)) {
				bad = "Bad node_announcement";
				goto truncate;
			}
			stats[2]++;
		} else if (fromwire_gossip_store_channel_delete(msg, &scid)) {
			struct chan *c = get_channel(rstate, &scid);
			if (!c) {
				bad = "Bad channel_delete";
				goto truncate;
			}
			tal_free(c);
			stats[3]++;
		} else if (fromwire_gossip_store_local_add_channel(
			       msg, msg, &gossip_msg)) {
			handle_local_add_channel(rstate, gossip_msg);
		} else {
			bad = "Unknown message";
			goto truncate;
		}
		gs->len += sizeof(hdr) + msglen;
		gs->count++;
		clean_tmpctx();
	}
	goto out;

truncate:
	status_unusual("gossip_store: %s (%s) truncating to %"PRIu64,
		       bad, tal_hex(msg, msg), (u64)1);
truncate_nomsg:
	/* FIXME: We would like to truncate to known_good, except we would
	 * miss channel_delete msgs.  If we put block numbers into the store
	 * as we process them, we can know how far we need to roll back if we
	 * truncate the store */
	if (ftruncate(gs->fd, 1) != 0)
		status_failed(STATUS_FAIL_INTERNAL_ERROR,
			      "Truncating store: %s", strerror(errno));
out:
#if DEVELOPER
	status_info("total store load time: %"PRIu64" msec (%zu entries, %zu bytes)",
		    time_to_msec(time_between(time_now(), start)),
		    stats[0] + stats[1] + stats[2] + stats[3],
		    (size_t)gs->len);
#else
	status_trace("total store load time: %"PRIu64" msec",
		     time_to_msec(time_between(time_now(), start)));
#endif
	status_trace("gossip_store: Read %zu/%zu/%zu/%zu cannounce/cupdate/nannounce/cdelete from store in %"PRIu64" bytes",
		     stats[0], stats[1], stats[2], stats[3],
		     gs->len);
	gs->writable = true;
}
