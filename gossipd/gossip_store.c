#include "gossip_store.h"

#include <ccan/crc/crc.h>
#include <ccan/endian/endian.h>
#include <ccan/read_write_all/read_write_all.h>
#include <common/status.h>
#include <common/utils.h>
#include <errno.h>
#include <fcntl.h>
#include <gossipd/gen_gossip_store.h>
#include <gossipd/gen_gossip_wire.h>
#include <stdio.h>
#include <unistd.h>
#include <wire/gen_peer_wire.h>
#include <wire/wire.h>

#define GOSSIP_STORE_FILENAME "gossip_store"
#define GOSSIP_STORE_TEMP_FILENAME "gossip_store.tmp"
static u8 gossip_store_version = 0x02;

struct gossip_store {
	int fd;
	u8 version;

	/* Counters for entries in the gossip_store entries. This is used to
	 * decide whether we should rewrite the on-disk store or not */
	size_t count;

	/* The broadcast struct we source messages from when rewriting the
	 * gossip_store */
	struct broadcast_state *broadcast;

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

struct gossip_store *gossip_store_new(const tal_t *ctx,
				      struct routing_state *rstate,
				      struct broadcast_state *broadcast)
{
	struct gossip_store *gs = tal(ctx, struct gossip_store);
	gs->count = 0;
	gs->fd = open(GOSSIP_STORE_FILENAME, O_RDWR|O_APPEND|O_CREAT, 0600);
	gs->broadcast = broadcast;
	gs->rstate = rstate;
	gs->disable_compaction = false;

	tal_add_destructor(gs, gossip_store_destroy);

	/* Try to read the version, write it if this is a new file, or truncate
	 * if the version doesn't match */
	if (read(gs->fd, &gs->version, sizeof(gs->version))
	    == sizeof(gs->version)) {
		/* Version match?  All good */
		if (gs->version == gossip_store_version)
			return gs;

		status_unusual("Gossip store version %u not %u: removing",
			       gs->version, gossip_store_version);
		if (ftruncate(gs->fd, 0) != 0)
			status_failed(STATUS_FAIL_INTERNAL_ERROR,
				      "Truncating store: %s", strerror(errno));
	}
	/* Empty file, write version byte */
	gs->version = gossip_store_version;
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
	struct pubkey node_id_1;
	struct pubkey node_id_2;
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
	assert(chan && chan->satoshis > 0);

	u8 *msg = towire_gossip_store_channel_announcement(ctx, gossip_msg,
							   chan->satoshis);
	return msg;
}

/**
 * Wrap the raw gossip message and write it to fd
 *
 * @param fd File descriptor to write the wrapped message into
 * @param gossip_msg The message to write
 * @return true if the message was wrapped and written
 */
static bool gossip_store_append(int fd, struct routing_state *rstate, const u8 *gossip_msg)
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
	else if(t == WIRE_GOSSIP_LOCAL_ADD_CHANNEL)
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

	return (write(fd, &belen, sizeof(belen)) == sizeof(belen) &&
		write(fd, &checksum, sizeof(checksum)) == sizeof(checksum) &&
		write(fd, msg, msglen) == msglen);
}

/**
 * Rewrite the on-disk gossip store, compacting it along the way
 *
 * Creates a new file, writes all the updates from the `broadcast_state`, and
 * then atomically swaps the files.
 */

static void gossip_store_compact(struct gossip_store *gs)
{
	size_t count = 0;
	u64 index = 0;
	int fd;
	const u8 *msg;

	assert(gs->broadcast);
	status_trace(
	    "Compacting gossip_store with %zu entries, %zu of which are stale",
	    gs->count, gs->count - gs->broadcast->count);

	fd = open(GOSSIP_STORE_TEMP_FILENAME, O_RDWR|O_APPEND|O_CREAT, 0600);

	if (fd < 0) {
		status_broken(
		    "Could not open file for gossip_store compaction");
		goto disable;
	}

	if (write(fd, &gossip_store_version, sizeof(gossip_store_version))
	    != sizeof(gossip_store_version)) {
		status_broken("Writing version to store: %s", strerror(errno));
		goto unlink_disable;
	}

	while ((msg = next_broadcast(gs->broadcast, 0, UINT32_MAX, &index)) != NULL) {
		if (!gossip_store_append(fd, gs->rstate, msg)) {
			status_broken("Failed writing to gossip store: %s",
				      strerror(errno));
			goto unlink_disable;

		}
		count++;
	}

	if (rename(GOSSIP_STORE_TEMP_FILENAME, GOSSIP_STORE_FILENAME) == -1) {
		status_broken(
		    "Error swapping compacted gossip_store into place: %s",
		    strerror(errno));
		goto unlink_disable;
	}

	status_trace(
	    "Compaction completed: dropped %zu messages, new count %zu",
	    gs->count - count, count);
	gs->count = count;
	close(gs->fd);
	gs->fd = fd;
	return;

unlink_disable:
	unlink(GOSSIP_STORE_TEMP_FILENAME);
disable:
	status_trace("Encountered an error while compacting, disabling "
		     "future compactions.");
	gs->disable_compaction = true;
}

void gossip_store_add(struct gossip_store *gs, const u8 *gossip_msg)
{
	/* Only give error message once. */
	if (gs->fd == -1)
		return;

	if (!gossip_store_append(gs->fd, gs->rstate, gossip_msg)) {
		status_broken("Failed writing to gossip store: %s",
			      strerror(errno));
		gs->fd = -1;
	}

	gs->count++;
	if (gs->count >= 1000 && gs->count > gs->broadcast->count * 1.25 &&
	    !gs->disable_compaction)
		gossip_store_compact(gs);
}

void gossip_store_add_channel_delete(struct gossip_store *gs,
				     const struct short_channel_id *scid)
{
	u8 *msg = towire_gossip_store_channel_delete(NULL, scid);
	gossip_store_append(gs->fd, gs->rstate, msg);
}

void gossip_store_load(struct routing_state *rstate, struct gossip_store *gs)
{
	beint32_t belen, becsum;
	u32 msglen, checksum;
	u8 *msg, *gossip_msg;
	u64 satoshis;
	struct short_channel_id scid;
	/* We set/check version byte on creation */
	off_t known_good = 1;
	const char *bad;
	size_t stats[] = {0, 0, 0, 0};
	int fd = gs->fd;
	gs->fd = -1;

	if (lseek(fd, known_good, SEEK_SET) < 0) {
		status_unusual("gossip_store: lseek failure");
		goto truncate_nomsg;
	}
	while (read(fd, &belen, sizeof(belen)) == sizeof(belen) &&
	       read(fd, &becsum, sizeof(becsum)) == sizeof(becsum)) {
		msglen = be32_to_cpu(belen);
		checksum = be32_to_cpu(becsum);
		msg = tal_arr(gs, u8, msglen);

		if (read(fd, msg, msglen) != msglen) {
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
							      gossip_msg,
							      satoshis)) {
				bad = "Bad channel_announcement";
				goto truncate;
			}
			stats[0]++;
		} else if (fromwire_gossip_store_channel_update(msg, msg,
								&gossip_msg)) {
			if (!routing_add_channel_update(rstate, gossip_msg)) {
				bad = "Bad channel_update";
				goto truncate;
			}
			stats[1]++;
		} else if (fromwire_gossip_store_node_announcement(msg, msg,
								   &gossip_msg)) {
			if (!routing_add_node_announcement(rstate, gossip_msg)) {
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
		known_good += sizeof(belen) + msglen;
		gs->count++;
		tal_free(msg);
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
	if (ftruncate(fd, 1) != 0)
		status_failed(STATUS_FAIL_INTERNAL_ERROR,
			      "Truncating store: %s", strerror(errno));
out:
	status_trace("gossip_store: Read %zu/%zu/%zu/%zu cannounce/cupdate/nannounce/cdelete from store in %"PRIu64" bytes",
		     stats[0], stats[1], stats[2], stats[3],
		     (u64)known_good);
	gs->fd = fd;
}
