#include <ccan/array_size/array_size.h>
/*~ Welcome to the gossip daemon: keeper of maps!
 *
 * This is the last "global" daemon; it has three purposes.
 *
 * 1. To determine routes for payments when lightningd asks.
 * 2. The second purpose is to receive gossip from peers (via their
 *    per-peer daemons) and send it out to them.
 * 3. Talk to `connectd` to to answer address queries for nodes.
 *
 * The gossip protocol itself is fairly simple, but has some twists which
 * add complexity to this daemon.
 */
#include <ccan/asort/asort.h>
#include <ccan/bitmap/bitmap.h>
#include <ccan/build_assert/build_assert.h>
#include <ccan/cast/cast.h>
#include <ccan/container_of/container_of.h>
#include <ccan/crypto/hkdf_sha256/hkdf_sha256.h>
#include <ccan/crypto/siphash24/siphash24.h>
#include <ccan/endian/endian.h>
#include <ccan/fdpass/fdpass.h>
#include <ccan/io/fdpass/fdpass.h>
#include <ccan/io/io.h>
#include <ccan/list/list.h>
#include <ccan/mem/mem.h>
#include <ccan/noerr/noerr.h>
#include <ccan/take/take.h>
#include <ccan/tal/str/str.h>
#include <ccan/timer/timer.h>
#include <common/bech32.h>
#include <common/bech32_util.h>
#include <common/cryptomsg.h>
#include <common/daemon_conn.h>
#include <common/decode_short_channel_ids.h>
#include <common/features.h>
#include <common/ping.h>
#include <common/pseudorand.h>
#include <common/status.h>
#include <common/subdaemon.h>
#include <common/timeout.h>
#include <common/type_to_string.h>
#include <common/utils.h>
#include <common/version.h>
#include <common/wire_error.h>
#include <common/wireaddr.h>
#include <connectd/gen_connect_gossip_wire.h>
#include <errno.h>
#include <fcntl.h>
#include <gossipd/broadcast.h>
#include <gossipd/gen_gossip_peerd_wire.h>
#include <gossipd/gen_gossip_wire.h>
#include <gossipd/routing.h>
#include <hsmd/gen_hsm_wire.h>
#include <inttypes.h>
#include <lightningd/gossip_msg.h>
#include <netdb.h>
#include <netinet/in.h>
#include <secp256k1_ecdh.h>
#include <sodium/randombytes.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>
#include <unistd.h>
#include <wire/gen_peer_wire.h>
#include <wire/wire_io.h>
#include <wire/wire_sync.h>
#include <zlib.h>

/* We talk to `hsmd` to sign our gossip messages with the node key */
#define HSM_FD 3
/* connectd asks us for help finding nodes, and gossip fds for new peers */
#define CONNECTD_FD 4

/* In developer mode we provide hooks for whitebox testing */
#if DEVELOPER
static u32 max_scids_encode_bytes = -1U;
static bool suppress_gossip = false;
#endif

/*~ The core daemon structure: */
struct daemon {
	/* Who am I?  Helps us find ourself in the routing map. */
	struct pubkey id;

	/* Peers we are gossiping to: id is unique */
	struct list_head peers;

	/* Connection to lightningd. */
	struct daemon_conn *master;

	/* Connection to connect daemon. */
	struct daemon_conn *connectd;

	/* Routing information */
	struct routing_state *rstate;

	/* Timers: we batch gossip, and also refresh announcements */
	struct timers timers;

	/* How often we flush gossip (60 seconds unless DEVELOPER override) */
	u32 broadcast_interval_msec;

	/* Global features to list in node_announcement. */
	u8 *globalfeatures;

	/* Alias (not NUL terminated) and favorite color for node_announcement */
	u8 alias[32];
	u8 rgb[3];

	/* What addresses we can actually announce. */
	struct wireaddr *announcable;
};

/* This represents each peer we're gossiping with */
struct peer {
	/* daemon->peers */
	struct list_node list;

	/* parent pointer. */
	struct daemon *daemon;

	/* The ID of the peer (always unique) */
	struct pubkey id;

	/* The two features gossip cares about (so far) */
	bool gossip_queries_feature, initial_routing_sync_feature;

	/* High water mark for the staggered broadcast */
	u64 broadcast_index;

	/* Timestamp range the peer asked us to filter gossip by */
	u32 gossip_timestamp_min, gossip_timestamp_max;

	/* Are there outstanding queries on short_channel_ids? */
	const struct short_channel_id *scid_queries;
	size_t scid_query_idx;

	/* Are there outstanding node_announcements from scid_queries? */
	struct pubkey *scid_query_nodes;
	size_t scid_query_nodes_idx;

	/* If this is NULL, we're syncing gossip now. */
	struct oneshot *gossip_timer;

	/* How many query responses are we expecting? */
	size_t num_scid_queries_outstanding;

	/* How many pongs are we expecting? */
	size_t num_pings_outstanding;

	/* Map of outstanding channel_range requests. */
	bitmap *query_channel_blocks;
	/* What we're querying: [range_first_blocknum, range_end_blocknum) */
	u32 range_first_blocknum, range_end_blocknum;
	u32 range_blocks_remaining;
	struct short_channel_id *query_channel_scids;

	/* The daemon_conn used to queue messages to/from the peer. */
	struct daemon_conn *dc;
};

/*~ A channel consists of a `struct half_chan` for each direction, each of
 * which has a `flags` word from the `channel_update`; bit 1 is
 * ROUTING_FLAGS_DISABLED in the `channel_update`.  But we also keep a local
 * whole-channel flag which indicates it's not available; we use this when a
 * peer disconnects, and generate a `channel_update` to tell the world lazily
 * when someone asks. */
static void peer_disable_channels(struct daemon *daemon, struct node *node)
{
	/* If this peer had a channel with us, mark it disabled. */
	for (size_t i = 0; i < tal_count(node->chans); i++) {
		struct chan *c = node->chans[i];
		if (pubkey_eq(&other_node(node, c)->id, &daemon->id))
			c->local_disabled = true;
	}
}

/*~ Destroy a peer, usually because the per-peer daemon has exited.
 *
 * Were you wondering why we call this "destroy_peer" and not "peer_destroy"?
 * I thought not!  But while CCAN modules are required to keep to their own
 * prefix namespace, leading to unnatural word order, we couldn't stomach that
 * for our own internal use.  We use 'find_foo', 'destroy_foo' and 'new_foo'.
 */
static void destroy_peer(struct peer *peer)
{
	struct node *node;

	/* Remove it from the peers list */
	list_del_from(&peer->daemon->peers, &peer->list);

	/* If we have a channel with this peer, disable it. */
	node = get_node(peer->daemon->rstate, &peer->id);
	if (node)
		peer_disable_channels(peer->daemon, node);

	/* This is tricky: our lifetime is tied to the daemon_conn; it's our
	 * parent, so we are freed if it is, but we need to free it if we're
	 * freed manually.  tal_free() treats this as a noop if it's already
	 * being freed */
	tal_free(peer->dc);
}

/* Search for a peer. */
static struct peer *find_peer(struct daemon *daemon, const struct pubkey *id)
{
	struct peer *peer;

	list_for_each(&daemon->peers, peer, list)
		if (pubkey_eq(&peer->id, id))
			return peer;
	return NULL;
}

/* Queue a gossip message for the peer: we wrap every gossip message; the
 * subdaemon simply unwraps and sends.  Note that we don't wrap messages
 * coming from the subdaemon to gossipd, because gossipd has to process the
 * messages anyway (and it doesn't trust the subdaemon); the subdaemon
 * trusts gossipd and will forward whatever it's told to. */
static void queue_peer_msg(struct peer *peer, const u8 *msg TAKES)
{
	const u8 *send = towire_gossipd_send_gossip(NULL, msg);
	/* Autogenerated functions don't take(), so we do here */
	if (taken(msg))
		tal_free(msg);
	daemon_conn_send(peer->dc, take(send));
}

/* This pokes daemon_conn, which calls dump_gossip: the NULL gossip_timer
 * tells it that the gossip timer has expired and it should send any queued
 * gossip messages. */
static void wake_gossip_out(struct peer *peer)
{
	/* If we were waiting, we're not any more */
	peer->gossip_timer = tal_free(peer->gossip_timer);

	/* Notify the daemon_conn-write loop */
	daemon_conn_wake(peer->dc);
}

/* BOLT #7:
 *
 * There are several messages which contain a long array of
 * `short_channel_id`s (called `encoded_short_ids`) so we utilize a
 * simple compression scheme: the first byte indicates the encoding, the
 * rest contains the data.
 */
static u8 *encode_short_channel_ids_start(const tal_t *ctx)
{
	u8 *encoded = tal_arr(ctx, u8, 0);
	towire_u8(&encoded, SHORTIDS_ZLIB);
	return encoded;
}

/* Marshal a single short_channel_id */
static void encode_add_short_channel_id(u8 **encoded,
					const struct short_channel_id *scid)
{
	towire_short_channel_id(encoded, scid);
}

/* Greg Maxwell asked me privately about using zlib for communicating a set,
 * and suggested that we'd be better off using Golomb-Rice coding a-la BIP
 * 158.  However, naively using Rice encoding isn't a win: we have to get
 * more complex and use separate streams.  The upside is that it's between
 * 2 and 5 times smaller (assuming optimal Rice encoding + gzip).  We can add
 * that later. */
static u8 *zencode_scids(const tal_t *ctx, const u8 *scids, size_t len)
{
	u8 *z;
	int err;
	unsigned long compressed_len = len;

	/* Prefer to fail if zlib makes it larger */
	z = tal_arr(ctx, u8, len);
	err = compress2(z, &compressed_len, scids, len, Z_BEST_COMPRESSION);
	if (err == Z_OK) {
		status_trace("short_ids compressed %zu into %lu",
			     len, compressed_len);
		tal_resize(&z, compressed_len);
		return z;
	}
	status_trace("short_ids compress %zu returned %i:"
		     " not compresssing", len, err);
	return NULL;
}

/* Once we've assembled */
static bool encode_short_channel_ids_end(u8 **encoded, size_t max_bytes)
{
	u8 *z;

	/* First byte says what encoding we want. */
	switch ((enum scid_encode_types)(*encoded)[0]) {
	case SHORTIDS_ZLIB:
		/* compress */
		z = zencode_scids(tmpctx, *encoded + 1, tal_count(*encoded) - 1);
		if (z) {
			/* If successful, copy over and trimp */
			tal_resize(encoded, 1 + tal_count(z));
			memcpy((*encoded) + 1, z, tal_count(z));
			goto check_length;
		}
		/* Otherwise, change first byte to 'uncompressed' */
		(*encoded)[0] = SHORTIDS_UNCOMPRESSED;
		/* Fall thru */
	case SHORTIDS_UNCOMPRESSED:
		goto check_length;
	}

	status_failed(STATUS_FAIL_INTERNAL_ERROR,
		      "Unknown short_ids encoding %u", (*encoded)[0]);

check_length:
#if DEVELOPER
	if (tal_count(*encoded) > max_scids_encode_bytes)
		return false;
#endif
	return tal_count(*encoded) <= max_bytes;
}

/* BOLT #7:
 *
 * An endpoint node:
 *   - if the `gossip_queries` feature is negotiated:
 * 	- MUST NOT relay any gossip messages unless explicitly requested.
 */
static void setup_gossip_range(struct peer *peer)
{
	u8 *msg;

	/*~ Without the `gossip_queries` feature, gossip flows automatically. */
	if (!peer->gossip_queries_feature)
		return;

	/*~ We need to ask for something to start the gossip flowing: we ask
	 * for everything from 1970 to 2106; this is horribly naive.  We
	 * should be much smarter about requesting only what we don't already
	 * have. */
	msg = towire_gossip_timestamp_filter(peer,
					     &peer->daemon->rstate->chain_hash,
					     0, UINT32_MAX);
	queue_peer_msg(peer, take(msg));
}

/* Create a node_announcement with the given signature. It may be NULL in the
 * case we need to create a provisional announcement for the HSM to sign.
 * This is called twice: once with the dummy signature to get it signed and a
 * second time to build the full packet with the signature. The timestamp is
 * handed in rather than using time_now() internally, since that could change
 * between the dummy creation and the call with a signature. */
static u8 *create_node_announcement(const tal_t *ctx, struct daemon *daemon,
				    secp256k1_ecdsa_signature *sig,
				    u32 timestamp)
{
	u8 *addresses = tal_arr(tmpctx, u8, 0);
	u8 *announcement;
	size_t i;
	if (!sig) {
		sig = tal(tmpctx, secp256k1_ecdsa_signature);
		memset(sig, 0, sizeof(*sig));
	}
	for (i = 0; i < tal_count(daemon->announcable); i++)
		towire_wireaddr(&addresses, &daemon->announcable[i]);

	announcement =
	    towire_node_announcement(ctx, sig, daemon->globalfeatures, timestamp,
				     &daemon->id, daemon->rgb, daemon->alias,
				     addresses);
	return announcement;
}

/*~ This routine created a `node_announcement` for our node, and hands it to
 * the routing.c code like any other `node_announcement`.  Such announcements
 * are only accepted if there is an announced channel associated with that node
 * (to prevent spam), so we only call this once we've announced a channel. */
static void send_node_announcement(struct daemon *daemon)
{
	u32 timestamp = time_now().ts.tv_sec;
	secp256k1_ecdsa_signature sig;
	u8 *msg, *nannounce, *err;
	s64 last_timestamp;
	struct node *self = get_node(daemon->rstate, &daemon->id);

	/* BOLT #7:
	 *
	 * The origin node:
	 *   - MUST set `timestamp` to be greater than that of any previous
	 *   `node_announcement` it has previously created.
	 */
	if (self)
		last_timestamp = self->last_timestamp;
	else
		/* last_timestamp is carefully a s64, so this works */
		last_timestamp = -1;

	if (timestamp <= last_timestamp)
		timestamp = last_timestamp + 1;

	/* Get an unsigned one. */
	nannounce = create_node_announcement(tmpctx, daemon, NULL, timestamp);

	/* Ask hsmd to sign it (synchronous) */
	if (!wire_sync_write(HSM_FD, take(towire_hsm_node_announcement_sig_req(NULL, nannounce))))
		status_failed(STATUS_FAIL_MASTER_IO, "Could not write to HSM: %s", strerror(errno));

	msg = wire_sync_read(tmpctx, HSM_FD);
	if (!fromwire_hsm_node_announcement_sig_reply(msg, &sig))
		status_failed(STATUS_FAIL_MASTER_IO, "HSM returned an invalid node_announcement sig");

	/* We got the signature for out provisional node_announcement back
	 * from the HSM, create the real announcement and forward it to
	 * gossipd so it can take care of forwarding it. */
	nannounce = create_node_announcement(NULL, daemon, &sig, timestamp);

	/* This injects it into the routing code in routing.c; it should not
	 * reject it! */
	err = handle_node_announcement(daemon->rstate, take(nannounce));
	if (err)
		status_failed(STATUS_FAIL_INTERNAL_ERROR,
			      "rejected own node announcement: %s",
			      tal_hex(tmpctx, err));
}

/* Return true if the only change would be the timestamp. */
static bool node_announcement_redundant(struct daemon *daemon)
{
	struct node *n = get_node(daemon->rstate, &daemon->id);
	if (!n)
		return false;

	if (n->last_timestamp == -1)
		return false;

	if (tal_count(n->addresses) != tal_count(daemon->announcable))
		return false;

	for (size_t i = 0; i < tal_count(n->addresses); i++)
		if (!wireaddr_eq(&n->addresses[i], &daemon->announcable[i]))
			return false;

	BUILD_ASSERT(ARRAY_SIZE(daemon->alias) == ARRAY_SIZE(n->alias));
	if (!memeq(daemon->alias, ARRAY_SIZE(daemon->alias),
		   n->alias, ARRAY_SIZE(n->alias)))
		return false;

	BUILD_ASSERT(ARRAY_SIZE(daemon->rgb) == ARRAY_SIZE(n->rgb_color));
	if (!memeq(daemon->rgb, ARRAY_SIZE(daemon->rgb),
		   n->rgb_color, ARRAY_SIZE(n->rgb_color)))
		return false;

	if (!memeq(daemon->globalfeatures, tal_count(daemon->globalfeatures),
		   n->globalfeatures, tal_count(n->globalfeatures)))
		return false;

	return true;
}

/* Should we announce our own node?  Called at strategic places. */
static void maybe_send_own_node_announce(struct daemon *daemon)
{
	/* We keep an internal flag in the routing code to say we've announced
	 * a local channel.  The alternative would be to have it make a
	 * callback, but when we start up we don't want to make multiple
	 * announcments, so we use this approach for now. */
	if (!daemon->rstate->local_channel_announced)
		return;

	if (node_announcement_redundant(daemon))
		return;

	send_node_announcement(daemon);
	daemon->rstate->local_channel_announced = false;
}

/*~Routines to handle gossip messages from peer, forwarded by subdaemons.
 *-----------------------------------------------------------------------
 *
 * It's not the subdaemon's fault if they're malformed or invalid; so these
 * all return an error packet which gets sent back to the subdaemon in that
 * case.
 */

/* The routing code checks that it's basically valid, returning an
 * error message for the peer or NULL.  NULL means it's OK, but the
 * message might be redundant, in which case scid is also NULL.
 * Otherwise `scid` gives us the short_channel_id claimed by the
 * message, and puts the announcemnt on an internal 'pending'
 * queue.  We'll send a request to lightningd to look it up, and continue
 * processing in `handle_txout_reply`. */
static const u8 *handle_channel_announcement_msg(struct peer *peer,
						 const u8 *msg)
{
	const struct short_channel_id *scid;
	const u8 *err;

	/* If it's OK, tells us the short_channel_id to lookup */
	err = handle_channel_announcement(peer->daemon->rstate, msg, &scid);
	if (err)
		return err;
	else if (scid)
		daemon_conn_send(peer->daemon->master,
				 take(towire_gossip_get_txout(NULL, scid)));
	return NULL;
}

static u8 *handle_channel_update_msg(struct peer *peer, const u8 *msg)
{
	/* Hand the channel_update to the routing code */
	u8 *err = handle_channel_update(peer->daemon->rstate, msg, "subdaemon");
	if (err)
		return err;

	/*~ As a nasty compromise in the spec, we only forward channel_announce
	 * once we have a channel_update; the channel isn't *usable* for
	 * routing until you have both anyway.  For this reason, we might have
	 * just sent out our own channel_announce, so we check if it's time to
	 * send a node_announcement too. */
	maybe_send_own_node_announce(peer->daemon);
	return NULL;
}

/*~ The peer can ask about an array of short channel ids: we don't assemble the
 * reply immediately but process them one at a time in dump_gossip which is
 * called when there's nothing more important to send. */
static const u8 *handle_query_short_channel_ids(struct peer *peer, const u8 *msg)
{
	struct routing_state *rstate = peer->daemon->rstate;
	struct bitcoin_blkid chain;
	u8 *encoded;
	struct short_channel_id *scids;

	if (!fromwire_query_short_channel_ids(tmpctx, msg, &chain, &encoded)) {
		return towire_errorfmt(peer, NULL,
				       "Bad query_short_channel_ids %s",
				       tal_hex(tmpctx, msg));
	}

	if (!bitcoin_blkid_eq(&rstate->chain_hash, &chain)) {
		status_trace("%s sent query_short_channel_ids chainhash %s",
			     type_to_string(tmpctx, struct pubkey, &peer->id),
			     type_to_string(tmpctx, struct bitcoin_blkid, &chain));
		return NULL;
	}

	/* BOLT #7:
	 *
	 * - if it has not sent `reply_short_channel_ids_end` to a
	 *   previously received `query_short_channel_ids` from this
         *   sender:
	 *    - MAY fail the connection.
	 */
	if (peer->scid_queries || peer->scid_query_nodes) {
		return towire_errorfmt(peer, NULL,
				       "Bad concurrent query_short_channel_ids");
	}

	scids = decode_short_ids(tmpctx, encoded);
	if (!scids) {
		return towire_errorfmt(peer, NULL,
				       "Bad query_short_channel_ids encoding %s",
				       tal_hex(tmpctx, encoded));
	}

	/* BOLT #7:
	 *
	 * - MUST respond to each known `short_channel_id` with a
	 *   `channel_announcement` and the latest `channel_update`s for each end
	 *    - SHOULD NOT wait for the next outgoing gossip flush to send
	 *      these.
	 */
	peer->scid_queries = tal_steal(peer, scids);
	peer->scid_query_idx = 0;
	peer->scid_query_nodes = tal_arr(peer, struct pubkey, 0);

	/* Notify the daemon_conn-write loop to invoke create_next_scid_reply */
	daemon_conn_wake(peer->dc);
	return NULL;
}

/*~ The peer can specify a timestamp range; gossip outside this range won't be
 * sent any more, and we'll start streaming gossip in this range.  This is
 * only supposed to be used if we negotiate the `gossip_queries` in which case
 * the first send triggers the first gossip to be sent.
*/
static u8 *handle_gossip_timestamp_filter(struct peer *peer, const u8 *msg)
{
	struct bitcoin_blkid chain_hash;
	u32 first_timestamp, timestamp_range;

	if (!fromwire_gossip_timestamp_filter(msg, &chain_hash,
					      &first_timestamp,
					      &timestamp_range)) {
		return towire_errorfmt(peer, NULL,
				       "Bad gossip_timestamp_filter %s",
				       tal_hex(tmpctx, msg));
	}

	if (!bitcoin_blkid_eq(&peer->daemon->rstate->chain_hash, &chain_hash)) {
		status_trace("%s sent gossip_timestamp_filter chainhash %s",
			     type_to_string(tmpctx, struct pubkey, &peer->id),
			     type_to_string(tmpctx, struct bitcoin_blkid,
					    &chain_hash));
		return NULL;
	}

	/* We initialize the timestamps to "impossible" values so we can
	 * detect that this is the first filter: in this case, we gossip sync
	 * immediately. */
	if (peer->gossip_timestamp_min > peer->gossip_timestamp_max)
		wake_gossip_out(peer);

	/* FIXME: We don't index by timestamp, so this forces a brute
	 * search!  But keeping in correct order is v. hard. */
	peer->gossip_timestamp_min = first_timestamp;
	peer->gossip_timestamp_max = first_timestamp + timestamp_range - 1;
	/* In case they overflow. */
	if (peer->gossip_timestamp_max < peer->gossip_timestamp_min)
		peer->gossip_timestamp_max = UINT32_MAX;
	peer->broadcast_index = 0;
	return NULL;
}

/*~ We can send multiple replies when the peer queries for all channels in
 * a given range of blocks; each one indicates the range of blocks it covers. */
static void reply_channel_range(struct peer *peer,
				u32 first_blocknum, u32 number_of_blocks,
				const u8 *encoded)
{
	/* BOLT #7:
	 *
	 * - For each `reply_channel_range`:
	 *   - MUST set with `chain_hash` equal to that of `query_channel_range`,
	 *   - MUST encode a `short_channel_id` for every open channel it
	 *     knows in blocks `first_blocknum` to `first_blocknum` plus
	 *     `number_of_blocks` minus one.
	 *   - MUST limit `number_of_blocks` to the maximum number of blocks
         *     whose results could fit in `encoded_short_ids`
	 *   - if does not maintain up-to-date channel information for
	 *     `chain_hash`:
	 *     - MUST set `complete` to 0.
	 *   - otherwise:
	 *     - SHOULD set `complete` to 1.
	 */
	u8 *msg = towire_reply_channel_range(NULL,
					     &peer->daemon->rstate->chain_hash,
					     first_blocknum,
					     number_of_blocks,
					     1, encoded);
	queue_peer_msg(peer, take(msg));
}

/*~ When we need to send an array of channels, it might go over our 64k packet
 * size.  If it doesn't, we recurse, splitting in two, etc.  Each message
 * indicates what blocks it contains, so the recipient knows when we're
 * finished. */
static void queue_channel_ranges(struct peer *peer,
				 u32 first_blocknum, u32 number_of_blocks)
{
	struct routing_state *rstate = peer->daemon->rstate;
	u8 *encoded = encode_short_channel_ids_start(tmpctx);
	struct short_channel_id scid;

	/* BOLT #7:
	 *
	 * 1. type: 264 (`reply_channel_range`) (`gossip_queries`)
	 * 2. data:
	 *   * [`32`:`chain_hash`]
	 *   * [`4`:`first_blocknum`]
	 *   * [`4`:`number_of_blocks`]
	 *   * [`1`:`complete`]
	 *   * [`2`:`len`]
	 *   * [`len`:`encoded_short_ids`]
	 */
	const size_t reply_overhead = 32 + 4 + 4 + 1 + 2;
	const size_t max_encoded_bytes = 65535 - 2 - reply_overhead;

	/* Avoid underflow: we don't use block 0 anyway */
	if (first_blocknum == 0)
		mk_short_channel_id(&scid, 1, 0, 0);
	else
		mk_short_channel_id(&scid, first_blocknum, 0, 0);
	scid.u64--;

	/* We keep a `uintmap` of `short_channel_id` to `struct chan *`.
	 * Unlike a htable, it's efficient to iterate through, but it only
	 * works because each short_channel_id is basically a 64-bit unsigned
	 * integer.
	 *
	 * First we iteraate and gather all the short channel ids. */
	while (uintmap_after(&rstate->chanmap, &scid.u64)) {
		u32 blocknum = short_channel_id_blocknum(&scid);
		if (blocknum >= first_blocknum + number_of_blocks)
			break;

		encode_add_short_channel_id(&encoded, &scid);
	}

	/* If we can encode that, fine: send it */
	if (encode_short_channel_ids_end(&encoded, max_encoded_bytes)) {
		reply_channel_range(peer, first_blocknum, number_of_blocks,
				    encoded);
		return;
	}

	/* It wouldn't all fit: divide in half */
	/* We assume we can always send one block! */
	if (number_of_blocks <= 1) {
		/* We always assume we can send 1 blocks worth */
		status_broken("Could not fit scids for single block %u",
			      first_blocknum);
		return;
	}
	status_debug("queue_channel_ranges full: splitting %u+%u and %u+%u",
		     first_blocknum,
		     number_of_blocks / 2,
		     first_blocknum + number_of_blocks / 2,
		     number_of_blocks - number_of_blocks / 2);
	queue_channel_ranges(peer, first_blocknum, number_of_blocks / 2);
	queue_channel_ranges(peer, first_blocknum + number_of_blocks / 2,
			     number_of_blocks - number_of_blocks / 2);
}

/*~ The peer can ask for all channels is a series of blocks.  We reply with one
 * or more messages containing the short_channel_ids. */
static u8 *handle_query_channel_range(struct peer *peer, const u8 *msg)
{
	struct bitcoin_blkid chain_hash;
	u32 first_blocknum, number_of_blocks;

	if (!fromwire_query_channel_range(msg, &chain_hash,
					  &first_blocknum, &number_of_blocks)) {
		return towire_errorfmt(peer, NULL,
				       "Bad query_channel_range %s",
				       tal_hex(tmpctx, msg));
	}

	/* FIXME: if they ask for the wrong chain, we should not ignore it,
	 * but give an empty response with the `complete` flag unset? */
	if (!bitcoin_blkid_eq(&peer->daemon->rstate->chain_hash, &chain_hash)) {
		status_trace("%s sent query_channel_range chainhash %s",
			     type_to_string(tmpctx, struct pubkey, &peer->id),
			     type_to_string(tmpctx, struct bitcoin_blkid,
					    &chain_hash));
		return NULL;
	}

	/* This checks for 32-bit overflow! */
	if (first_blocknum + number_of_blocks < first_blocknum) {
		return towire_errorfmt(peer, NULL,
				       "query_channel_range overflow %u+%u",
				       first_blocknum, number_of_blocks);
	}

	queue_channel_ranges(peer, first_blocknum, number_of_blocks);
	return NULL;
}

/*~ This is the reply we get when we send query_channel_range; we keep
 * expecting them until the entire range we asked for is covered. */
static const u8 *handle_reply_channel_range(struct peer *peer, const u8 *msg)
{
	struct bitcoin_blkid chain;
	u8 complete;
	u32 first_blocknum, number_of_blocks, start, end;
	u8 *encoded;
	struct short_channel_id *scids;
	size_t n;
	unsigned long b;

	if (!fromwire_reply_channel_range(tmpctx, msg, &chain, &first_blocknum,
					  &number_of_blocks, &complete,
					  &encoded)) {
		return towire_errorfmt(peer, NULL,
				       "Bad reply_channel_range %s",
				       tal_hex(tmpctx, msg));
	}

	if (!bitcoin_blkid_eq(&peer->daemon->rstate->chain_hash, &chain)) {
		return towire_errorfmt(peer, NULL,
				       "reply_channel_range for bad chain: %s",
				       tal_hex(tmpctx, msg));
	}

	if (!peer->query_channel_blocks) {
		return towire_errorfmt(peer, NULL,
				       "reply_channel_range without query: %s",
				       tal_hex(tmpctx, msg));
	}

	/* Beware overflow! */
	if (first_blocknum + number_of_blocks < first_blocknum) {
		return towire_errorfmt(peer, NULL,
				       "reply_channel_range invalid %u+%u",
				       first_blocknum, number_of_blocks);
	}

	scids = decode_short_ids(tmpctx, encoded);
	if (!scids) {
		return towire_errorfmt(peer, NULL,
				       "Bad reply_channel_range encoding %s",
				       tal_hex(tmpctx, encoded));
	}

	status_debug("peer %s reply_channel_range %u+%u (of %u+%u) %zu scids",
		     type_to_string(tmpctx, struct pubkey, &peer->id),
		     first_blocknum, number_of_blocks,
		     peer->range_first_blocknum,
		     peer->range_end_blocknum - peer->range_first_blocknum,
		     tal_count(scids));

	/* BOLT #7:
	 *
	 * The receiver of `query_channel_range`:
	 *...
	 *  - MUST respond with one or more `reply_channel_range` whose
	 *    combined range cover the requested `first_blocknum` to
	 *    `first_blocknum` plus `number_of_blocks` minus one.
	 */
	/* ie. They can be outside range we asked, but they must overlap! */
	if (first_blocknum + number_of_blocks <= peer->range_first_blocknum
	    || first_blocknum >= peer->range_end_blocknum) {
		return towire_errorfmt(peer, NULL,
				       "reply_channel_range invalid %u+%u for query %u+%u",
				       first_blocknum, number_of_blocks,
				       peer->range_first_blocknum,
				       peer->range_end_blocknum
				       - peer->range_first_blocknum);
	}

	start = first_blocknum;
	end = first_blocknum + number_of_blocks;
	/* Trim to make it a subset of what we want. */
	if (start < peer->range_first_blocknum)
		start = peer->range_first_blocknum;
	if (end > peer->range_end_blocknum)
		end = peer->range_end_blocknum;

	/* We keep a bitmap of what blocks have been covered by replies: bit 0
	 * represents block peer->range_first_blocknum */
	b = bitmap_ffs(peer->query_channel_blocks,
		       start - peer->range_first_blocknum,
		       end - peer->range_first_blocknum);
	if (b != end - peer->range_first_blocknum) {
		return towire_errorfmt(peer, NULL,
				       "reply_channel_range %u+%u already have block %lu",
				       first_blocknum, number_of_blocks,
				       peer->range_first_blocknum + b);
	}

	/* Mark that short_channel_ids for this block have been received */
	bitmap_fill_range(peer->query_channel_blocks,
			  start - peer->range_first_blocknum,
			  end - peer->range_first_blocknum);
	peer->range_blocks_remaining -= end - start;

	/* Add scids */
	n = tal_count(peer->query_channel_scids);
	tal_resize(&peer->query_channel_scids, n + tal_count(scids));
	memcpy(peer->query_channel_scids + n, scids, tal_bytelen(scids));

	/* Still more to go? */
	if (peer->range_blocks_remaining)
		return NULL;

	/* All done, send reply to lightningd: that's currently the only thing
	 * which triggers this (for testing).  Eventually we might start probing
	 * for gossip information on our own. */
	msg = towire_gossip_query_channel_range_reply(NULL,
						      first_blocknum,
						      number_of_blocks,
						      complete,
						      peer->query_channel_scids);
	daemon_conn_send(peer->daemon->master, take(msg));
	peer->query_channel_scids = tal_free(peer->query_channel_scids);
	peer->query_channel_blocks = tal_free(peer->query_channel_blocks);
	return NULL;
}

/*~ For simplicity, all pings and pongs are forwarded to us here in gossipd. */
static u8 *handle_ping(struct peer *peer, const u8 *ping)
{
	u8 *pong;

	/* This checks the ping packet and makes a pong reply if needed; peer
	 * can specify it doesn't want a response, to simulate traffic. */
	if (!check_ping_make_pong(NULL, ping, &pong))
		return towire_errorfmt(peer, NULL, "Bad ping");

	if (pong)
		queue_peer_msg(peer, take(pong));
	return NULL;
}

/*~ When we get a pong, we tell lightningd about it (it's probably a response
 * to the `ping` JSON RPC command). */
static const u8 *handle_pong(struct peer *peer, const u8 *pong)
{
	const char *err = got_pong(pong, &peer->num_pings_outstanding);

	if (err)
		return towire_errorfmt(peer, NULL, "%s", err);

	daemon_conn_send(peer->daemon->master,
			 take(towire_gossip_ping_reply(NULL, &peer->id, true,
						       tal_count(pong))));
	return NULL;
}

/*~ When we ask about an array of short_channel_ids, we get all channel &
 * node announcements and channel updates which the peer knows.  There's an
 * explicit end packet; this is needed to differentiate between 'I'm slow'
 * and 'I don't know those channels'. */
static u8 *handle_reply_short_channel_ids_end(struct peer *peer, const u8 *msg)
{
	struct bitcoin_blkid chain;
	u8 complete;

	if (!fromwire_reply_short_channel_ids_end(msg, &chain, &complete)) {
		return towire_errorfmt(peer, NULL,
				       "Bad reply_short_channel_ids_end %s",
				       tal_hex(tmpctx, msg));
	}

	if (!bitcoin_blkid_eq(&peer->daemon->rstate->chain_hash, &chain)) {
		return towire_errorfmt(peer, NULL,
				       "reply_short_channel_ids_end for bad chain: %s",
				       tal_hex(tmpctx, msg));
	}

	if (peer->num_scid_queries_outstanding == 0) {
		return towire_errorfmt(peer, NULL,
				       "unexpected reply_short_channel_ids_end: %s",
				       tal_hex(tmpctx, msg));
	}

	peer->num_scid_queries_outstanding--;
	/* We tell lightningd: this is because we currently only ask for
	 * query_short_channel_ids when lightningd asks. */
	msg = towire_gossip_scids_reply(msg, true, complete);
	daemon_conn_send(peer->daemon->master, take(msg));
	return NULL;
}

/*~ Arbitrary ordering function of pubkeys.
 *
 * Note that we could use memcmp() here: even if they had somehow different
 * bitwise representations for the same key, we copied them all from struct
 * node which should make them unique.  Even if not (say, a node vanished
 * and reappeared) we'd just end up sending two node_announcement for the
 * same node.
 */
static int pubkey_order(const struct pubkey *k1, const struct pubkey *k2,
			void *unused UNUSED)
{
	return pubkey_cmp(k1, k2);
}

static void uniquify_node_ids(struct pubkey **ids)
{
	size_t dst, src;

	/* BOLT #7:
	 *
	 * - MUST follow with any `node_announcement`s for each
	 *   `channel_announcement`
	 *
	 *   - SHOULD avoid sending duplicate `node_announcements` in
	 *     response to a single `query_short_channel_ids`.
	 */
	/* ccan/asort is a typesafe qsort wrapper: like most ccan modules
	 * it eschews exposing 'void *' pointers and ensures that the
	 * callback function and its arguments match types correctly. */
	asort(*ids, tal_count(*ids), pubkey_order, NULL);

	/* Compact the array */
	for (dst = 0, src = 0; src < tal_count(*ids); src++) {
		if (dst && pubkey_eq(&(*ids)[dst-1], &(*ids)[src]))
			continue;
		(*ids)[dst++] = (*ids)[src];
	}

	/* And trim to length, so tal_count() gives correct answer. */
	tal_resize(ids, dst);
}

/*~ We are fairly careful to avoid the peer DoSing us with channel queries:
 * this routine sends information about a single short_channel_id, unless
 * it's finished all of them. */
static void maybe_create_next_scid_reply(struct peer *peer)
{
	struct routing_state *rstate = peer->daemon->rstate;
	size_t i, num;
	bool sent = false;

	/* BOLT #7:
	 *
	 *   - MUST respond to each known `short_channel_id` with a
	 *     `channel_announcement` and the latest `channel_update`s for
	 *     each end
	 *     - SHOULD NOT wait for the next outgoing gossip flush
	 *       to send these.
	 */
	/* Search for next short_channel_id we know about. */
	num = tal_count(peer->scid_queries);
	for (i = peer->scid_query_idx; !sent && i < num; i++) {
		struct chan *chan;

		chan = get_channel(rstate, &peer->scid_queries[i]);
		if (!chan || !is_chan_announced(chan))
			continue;

		queue_peer_msg(peer, chan->channel_announce);
		if (chan->half[0].channel_update)
			queue_peer_msg(peer, chan->half[0].channel_update);
		if (chan->half[1].channel_update)
			queue_peer_msg(peer, chan->half[1].channel_update);

		/* Record node ids for later transmission of node_announcement */
		*tal_arr_expand(&peer->scid_query_nodes) = chan->nodes[0]->id;
		*tal_arr_expand(&peer->scid_query_nodes) = chan->nodes[1]->id;
		sent = true;
	}

	/* Just finished channels?  Remove duplicate nodes. */
	if (peer->scid_query_idx != num && i == num)
		uniquify_node_ids(&peer->scid_query_nodes);

	/* Update index for next time we're called. */
	peer->scid_query_idx = i;

	/* BOLT #7:
	 *
	 *  - MUST follow with any `node_announcement`s for each
	 *   `channel_announcement`
	 *    - SHOULD avoid sending duplicate `node_announcements` in response
	 *     to a single `query_short_channel_ids`.
	 */
	/* If we haven't sent anything above, we look for the next
	 * node_announcement to send. */
	num = tal_count(peer->scid_query_nodes);
	for (i = peer->scid_query_nodes_idx; !sent && i < num; i++) {
		const struct node *n;

		/* Not every node announces itself (we know it exists because
		 * of a channel_announcement, however) */
		n = get_node(rstate, &peer->scid_query_nodes[i]);
		if (!n || !n->node_announcement_index)
			continue;

		queue_peer_msg(peer, n->node_announcement);
		sent = true;
	}
	peer->scid_query_nodes_idx = i;

	/* All finished? */
	if (peer->scid_queries && peer->scid_query_nodes_idx == num) {
		/* BOLT #7:
		 *
		 * - MUST follow these responses with
		 *   `reply_short_channel_ids_end`.
		 *   - if does not maintain up-to-date channel information for
		 *     `chain_hash`:
		 *      - MUST set `complete` to 0.
		 *   - otherwise:
		 *      - SHOULD set `complete` to 1.
		 */
		/* FIXME: We consider ourselves to have complete knowledge. */
		u8 *end = towire_reply_short_channel_ids_end(peer,
							     &rstate->chain_hash,
							     true);
		queue_peer_msg(peer, take(end));

		/* We're done!  Clean up so we simply pass-through next time. */
		peer->scid_queries = tal_free(peer->scid_queries);
		peer->scid_query_idx = 0;
		peer->scid_query_nodes = tal_free(peer->scid_query_nodes);
		peer->scid_query_nodes_idx = 0;
	}
}

/*~ If we're supposed to be sending gossip, do so now. */
static void maybe_queue_gossip(struct peer *peer)
{
	const u8 *next;

	/* If the gossip timer is still running, don't send. */
	if (peer->gossip_timer)
		return;

#if DEVELOPER
	/* The dev_suppress_gossip RPC is used for testing. */
	if (suppress_gossip)
		return;
#endif

	/*~ We maintain an ordered map of gossip to broadcast, so each peer
	 * only needs to keep an index; this returns the next gossip message
	 * which is past the previous index and within the timestamp: it
	 * also updates `broadcast_index`. */
	next = next_broadcast(peer->daemon->rstate->broadcasts,
			      peer->gossip_timestamp_min,
			      peer->gossip_timestamp_max,
			      &peer->broadcast_index);

	if (next) {
		queue_peer_msg(peer, next);
		return;
	}

	/* BOLT #7:
	 *
	 * An endpoint node:
	 *...
	 *  - SHOULD flush outgoing gossip messages once every 60 seconds,
	 *    independently of the arrival times of the messages.
	 *    - Note: this results in staggered announcements that are unique
	 *      (not duplicated).
	 */

	/* Gossip is drained; we set up timer now, which is strictly-speaking
	 * more than 60 seconds if sending gossip took a long time.  But
	 * that's their fault for being slow! */
	peer->gossip_timer
		= new_reltimer(&peer->daemon->timers, peer,
			       /* The time is adjustable for testing */
			       time_from_msec(peer->daemon->broadcast_interval_msec),
			       wake_gossip_out, peer);
}

/*~ This is called when the outgoing queue is empty; gossip has lower priority
 * than just about anything else. */
static void dump_gossip(struct peer *peer)
{
	/* Do we have scid query replies to send? */
	maybe_create_next_scid_reply(peer);

	/* Queue any gossip we want to send */
	maybe_queue_gossip(peer);
}

/*~ This generates a `channel_update` message for one of our channels.  We do
 * this here, rather than in `channeld` because we (may) need to do it
 * ourselves anyway if channeld dies, or when we refresh it once a week. */
static void update_local_channel(struct daemon *daemon,
				 const struct chan *chan,
				 int direction,
				 bool disable,
				 u16 cltv_expiry_delta,
				 u64 htlc_minimum_msat,
				 u32 fee_base_msat,
				 u32 fee_proportional_millionths,
				 u64 htlc_maximum_msat,
				 const char *caller)
{
	secp256k1_ecdsa_signature dummy_sig;
	u8 *update, *msg;
	u32 timestamp = time_now().ts.tv_sec;
	u8 message_flags, channel_flags;

	/* So valgrind doesn't complain */
	memset(&dummy_sig, 0, sizeof(dummy_sig));

	/* BOLT #7:
	 *
	 * The origin node:
	 *...
	 *   - MUST set `timestamp` to greater than 0, AND to greater than any
	 *     previously-sent `channel_update` for this `short_channel_id`.
	 *     - SHOULD base `timestamp` on a UNIX timestamp.
	 */
	if (is_halfchan_defined(&chan->half[direction])
	    && timestamp == chan->half[direction].last_timestamp)
		timestamp++;

	/* BOLT #7:
	 *
	 * The `channel_flags` bitfield is used to indicate the direction of
	 * the channel: it identifies the node that this update originated
	 * from and signals various options concerning the channel. The
	 * following table specifies the meaning of its individual bits:
	 *
	 * | Bit Position  | Name        | Meaning                          |
	 * | ------------- | ----------- | -------------------------------- |
	 * | 0             | `direction` | Direction this update refers to. |
	 * | 1             | `disable`   | Disable the channel.             |
	 */
	channel_flags = direction;
	if (disable)
		channel_flags |= ROUTING_FLAGS_DISABLED;

	/* BOLT #7:
	 *
	 * The `message_flags` bitfield is used to indicate the presence of
	 * optional fields in the `channel_update` message:
	 *
	 *| Bit Position  | Name                      | Field                 |
	 *...
	 *| 0             | `option_channel_htlc_max` | `htlc_maximum_msat`   |
	 */
	message_flags = 0 | ROUTING_OPT_HTLC_MAX_MSAT;

	/* We create an update with a dummy signature, and hand to hsmd to get
	 * it signed. */
	update = towire_channel_update_option_channel_htlc_max(tmpctx, &dummy_sig,
				       &daemon->rstate->chain_hash,
				       &chan->scid,
				       timestamp,
				       message_flags, channel_flags,
				       cltv_expiry_delta,
				       htlc_minimum_msat,
				       fee_base_msat,
				       fee_proportional_millionths,
				       htlc_maximum_msat);

	/* Note that we treat the hsmd as synchronous.  This is simple (no
	 * callback hell)!, but may need to change to async if we ever want
	 * remote HSMs */
	if (!wire_sync_write(HSM_FD,
			     towire_hsm_cupdate_sig_req(tmpctx, update))) {
		status_failed(STATUS_FAIL_HSM_IO, "Writing cupdate_sig_req: %s",
			      strerror(errno));
	}

	msg = wire_sync_read(tmpctx, HSM_FD);
	if (!msg || !fromwire_hsm_cupdate_sig_reply(NULL, msg, &update)) {
		status_failed(STATUS_FAIL_HSM_IO,
			      "Reading cupdate_sig_req: %s",
			      strerror(errno));
	}

	/* BOLT #7:
	 *
	 * The origin node:
	 *   - MAY create a `channel_update` to communicate the channel
	 *   parameters to the final node, even though the channel has not yet
	 *   been announced
	 */
	if (!is_chan_public(chan)) {
		/* handle_channel_update will not put private updates in the
		 * broadcast list, but we send it direct to the peer (if we
		 * have one connected) now */
		struct peer *peer = find_peer(daemon,
					      &chan->nodes[!direction]->id);
		if (peer)
			queue_peer_msg(peer, update);
	}

	/* We feed it into routing.c like any other channel_update; it may
	 * discard it (eg. non-public channel), but it should not complain
	 * about it being invalid! */
	msg = handle_channel_update(daemon->rstate, take(update), caller);
	if (msg)
		status_failed(STATUS_FAIL_INTERNAL_ERROR,
			      "%s: rejected local channel update %s: %s",
			      caller,
			      /* Normally we must not touch something taken()
			       * but we're in deep trouble anyway, and
			       * handle_channel_update only tal_steals onto
			       * tmpctx, so it's actually OK. */
			      tal_hex(tmpctx, update),
			      tal_hex(tmpctx, msg));
}

/*~ We generate local channel updates lazily; most of the time we simply
 * toggle the `local_disabled` flag so we don't use it to route.  We never
 * change anything else after startup (yet!) */
static void maybe_update_local_channel(struct daemon *daemon,
				       struct chan *chan, int direction)
{
	const struct half_chan *hc = &chan->half[direction];

	/* Don't generate a channel_update for an uninitialized channel. */
	if (!hc->channel_update)
		return;

	/* Nothing to update? */
	/*~ Note the inversions here on both sides, which is cheap conversion to
	 * boolean for the RHS! */
	if (!chan->local_disabled == !(hc->channel_flags & ROUTING_FLAGS_DISABLED))
		return;

	update_local_channel(daemon, chan, direction,
			     chan->local_disabled,
			     hc->delay,
			     hc->htlc_minimum_msat,
			     hc->base_fee,
			     hc->proportional_fee,
			     hc->htlc_maximum_msat,
			     /* Note this magic C macro which expands to the
			      * function name, for debug messages */
			     __func__);
}

/*~ This helper figures out which direction of the channel is from-us; if
 * neither, it returns false.  This meets Linus' rule "Always return the error",
 * without doing some horrible 0/1/-1 return. */
static bool local_direction(struct daemon *daemon,
			    const struct chan *chan,
			    int *direction)
{
	for (*direction = 0; *direction < 2; (*direction)++) {
		if (pubkey_eq(&chan->nodes[*direction]->id, &daemon->id))
			return true;
	}
	return false;
}

/*~ This is when channeld asks us for a channel_update for a local channel.
 * It does that to fill in the error field when lightningd fails an HTLC and
 * sets the UPDATE bit in the error type.  lightningd is too important to
 * fetch this itself, so channeld does it (channeld has to talk to us for
 * other things anyway, so why not?). */
static bool handle_get_update(struct peer *peer, const u8 *msg)
{
	struct short_channel_id scid;
	struct chan *chan;
	const u8 *update;
	struct routing_state *rstate = peer->daemon->rstate;
	int direction;

	if (!fromwire_gossipd_get_update(msg, &scid)) {
		status_broken("peer %s sent bad gossip_get_update %s",
			      type_to_string(tmpctx, struct pubkey, &peer->id),
			      tal_hex(tmpctx, msg));
		return false;
	}

	/* It's possible that the channel has just closed (though v. unlikely) */
	chan = get_channel(rstate, &scid);
	if (!chan) {
		status_unusual("peer %s scid %s: unknown channel",
			       type_to_string(tmpctx, struct pubkey, &peer->id),
			       type_to_string(tmpctx, struct short_channel_id,
					      &scid));
		update = NULL;
		goto out;
	}

	/* We want the update that comes from our end. */
	if (!local_direction(peer->daemon, chan, &direction)) {
		status_unusual("peer %s scid %s: not our channel?",
			       type_to_string(tmpctx, struct pubkey, &peer->id),
			       type_to_string(tmpctx,
					      struct short_channel_id,
					      &scid));
		update = NULL;
		goto out;
	}

	/* Since we're going to send it out, make sure it's up-to-date. */
	maybe_update_local_channel(peer->daemon, chan, direction);

	/* It's possible this is NULL, if we've never sent a channel_update
	 * for that channel. */
	update = chan->half[direction].channel_update;
out:
	status_trace("peer %s schanid %s: %s update",
		     type_to_string(tmpctx, struct pubkey, &peer->id),
		     type_to_string(tmpctx, struct short_channel_id, &scid),
		     update ? "got" : "no");

	msg = towire_gossipd_get_update_reply(NULL, update);
	daemon_conn_send(peer->dc, take(msg));
	return true;
}

/*~ Return true if the channel information has changed.  This can only
* currently happen if the user restarts with different fee options, but we
* don't assume that. */
static bool halfchan_new_info(const struct half_chan *hc,
			      u16 cltv_delta, u64 htlc_minimum_msat,
			      u32 fee_base_msat, u32 fee_proportional_millionths,
			      u64 htlc_maximum_msat)
{
	if (!is_halfchan_defined(hc))
		return true;

	return hc->delay != cltv_delta
		|| hc->htlc_minimum_msat != htlc_minimum_msat
		|| hc->base_fee != fee_base_msat
		|| hc->proportional_fee != fee_proportional_millionths
		|| hc->htlc_maximum_msat != htlc_maximum_msat;
}

/*~ channeld asks us to update the local channel. */
static bool handle_local_channel_update(struct peer *peer, const u8 *msg)
{
	struct chan *chan;
	struct short_channel_id scid;
	bool disable;
	u16 cltv_expiry_delta;
	u64 htlc_minimum_msat;
	u64 htlc_maximum_msat;
	u32 fee_base_msat;
	u32 fee_proportional_millionths;
	int direction;

	/* FIXME: We should get scid from lightningd when setting up the
	 * connection, so no per-peer daemon can mess with channels other than
	 * its own! */
	if (!fromwire_gossipd_local_channel_update(msg,
						   &scid,
						   &disable,
						   &cltv_expiry_delta,
						   &htlc_minimum_msat,
						   &fee_base_msat,
						   &fee_proportional_millionths,
						   &htlc_maximum_msat)) {
		status_broken("peer %s bad local_channel_update %s",
			      type_to_string(tmpctx, struct pubkey, &peer->id),
			      tal_hex(tmpctx, msg));
		return false;
	}

	/* Can theoretically happen if channel just closed. */
	chan = get_channel(peer->daemon->rstate, &scid);
	if (!chan) {
		status_trace("peer %s local_channel_update for unknown %s",
			      type_to_string(tmpctx, struct pubkey, &peer->id),
			      type_to_string(tmpctx, struct short_channel_id,
					     &scid));
		return true;
	}

	/* You shouldn't be asking for a non-local channel though. */
	if (!local_direction(peer->daemon, chan, &direction)) {
		status_broken("peer %s bad local_channel_update for non-local %s",
			      type_to_string(tmpctx, struct pubkey, &peer->id),
			      type_to_string(tmpctx, struct short_channel_id,
					     &scid));
		return false;
	}

	/* We could change configuration on restart; update immediately.
	 * Or, if we're *enabling* an announced-disabled channel.
	 * Or, if it's an unannounced channel (only sending to peer). */
	if (halfchan_new_info(&chan->half[direction],
			      cltv_expiry_delta, htlc_minimum_msat,
			      fee_base_msat, fee_proportional_millionths,
			      htlc_maximum_msat)
	    || ((chan->half[direction].channel_flags & ROUTING_FLAGS_DISABLED)
		&& !disable)
	    || !is_chan_public(chan)) {
		update_local_channel(peer->daemon, chan, direction,
				     disable,
				     cltv_expiry_delta,
				     htlc_minimum_msat,
				     fee_base_msat,
				     fee_proportional_millionths,
				     htlc_maximum_msat,
				     __func__);
	}

	/* Normal case: just toggle local_disabled, and generate broadcast in
	 * maybe_update_local_channel when/if someone asks about it. */
	chan->local_disabled = disable;
	return true;
}

/*~ This is where the per-peer daemons send us messages.  It's either forwarded
 * gossip, or a request for information.  We deliberately use non-overlapping
 * message types so we can distinguish them. */
static struct io_plan *peer_msg_in(struct io_conn *conn,
				    const u8 *msg,
				    struct peer *peer)
{
	const u8 *err;
	bool ok;

	/* These are messages relayed from peer */
	switch ((enum wire_type)fromwire_peektype(msg)) {
	case WIRE_CHANNEL_ANNOUNCEMENT:
		err = handle_channel_announcement_msg(peer, msg);
		goto handled_relay;
	case WIRE_CHANNEL_UPDATE:
		err = handle_channel_update_msg(peer, msg);
		goto handled_relay;
	case WIRE_NODE_ANNOUNCEMENT:
		err = handle_node_announcement(peer->daemon->rstate, msg);
		goto handled_relay;
	case WIRE_QUERY_CHANNEL_RANGE:
		err = handle_query_channel_range(peer, msg);
		goto handled_relay;
	case WIRE_REPLY_CHANNEL_RANGE:
		err = handle_reply_channel_range(peer, msg);
		goto handled_relay;
	case WIRE_QUERY_SHORT_CHANNEL_IDS:
		err = handle_query_short_channel_ids(peer, msg);
		goto handled_relay;
	case WIRE_REPLY_SHORT_CHANNEL_IDS_END:
		err = handle_reply_short_channel_ids_end(peer, msg);
		goto handled_relay;
	case WIRE_GOSSIP_TIMESTAMP_FILTER:
		err = handle_gossip_timestamp_filter(peer, msg);
		goto handled_relay;
	case WIRE_PING:
		err = handle_ping(peer, msg);
		goto handled_relay;
	case WIRE_PONG:
		err = handle_pong(peer, msg);
		goto handled_relay;

	/* These are non-gossip messages (!is_msg_for_gossipd()) */
	case WIRE_INIT:
	case WIRE_ERROR:
	case WIRE_OPEN_CHANNEL:
	case WIRE_ACCEPT_CHANNEL:
	case WIRE_FUNDING_CREATED:
	case WIRE_FUNDING_SIGNED:
	case WIRE_FUNDING_LOCKED:
	case WIRE_SHUTDOWN:
	case WIRE_CLOSING_SIGNED:
	case WIRE_UPDATE_ADD_HTLC:
	case WIRE_UPDATE_FULFILL_HTLC:
	case WIRE_UPDATE_FAIL_HTLC:
	case WIRE_UPDATE_FAIL_MALFORMED_HTLC:
	case WIRE_COMMITMENT_SIGNED:
	case WIRE_REVOKE_AND_ACK:
	case WIRE_UPDATE_FEE:
	case WIRE_CHANNEL_REESTABLISH:
	case WIRE_ANNOUNCEMENT_SIGNATURES:
		status_broken("peer %s: relayed unexpected msg of type %s",
			      type_to_string(tmpctx, struct pubkey, &peer->id),
			      wire_type_name(fromwire_peektype(msg)));
		return io_close(conn);
	}

	/* Must be a gossip_peerd_wire_type asking us to do something. */
	switch ((enum gossip_peerd_wire_type)fromwire_peektype(msg)) {
	case WIRE_GOSSIPD_GET_UPDATE:
		ok = handle_get_update(peer, msg);
		goto handled_cmd;
	case WIRE_GOSSIPD_LOCAL_ADD_CHANNEL:
		ok = handle_local_add_channel(peer->daemon->rstate, msg);
		if (ok)
			gossip_store_add(peer->daemon->rstate->store, msg);
		goto handled_cmd;
	case WIRE_GOSSIPD_LOCAL_CHANNEL_UPDATE:
		ok = handle_local_channel_update(peer, msg);
		goto handled_cmd;

	/* These are the ones we send, not them */
	case WIRE_GOSSIPD_GET_UPDATE_REPLY:
	case WIRE_GOSSIPD_SEND_GOSSIP:
		break;
	}

	/* Anything else should not have been sent to us: close on it */
	status_broken("peer %s: unexpected cmd of type %i %s",
		      type_to_string(tmpctx, struct pubkey, &peer->id),
		      fromwire_peektype(msg),
		      gossip_peerd_wire_type_name(fromwire_peektype(msg)));
	return io_close(conn);

	/* Commands should always be OK. */
handled_cmd:
	if (!ok)
		return io_close(conn);
	goto done;

	/* Forwarded messages may be bad, so we have error which the per-peer
	 * daemon will forward to the peer. */
handled_relay:
	if (err)
		queue_peer_msg(peer, take(err));
done:
	return daemon_conn_read_next(conn, peer->dc);
}

/*~ This is where connectd tells us about a new peer, and we hand back an fd for
 * it to send us messages via peer_msg_in above */
static struct io_plan *connectd_new_peer(struct io_conn *conn,
					 struct daemon *daemon,
					 const u8 *msg)
{
	struct peer *peer = tal(conn, struct peer);
	int fds[2];

	if (!fromwire_gossip_new_peer(msg, &peer->id,
				      &peer->gossip_queries_feature,
				      &peer->initial_routing_sync_feature)) {
		status_broken("Bad new_peer msg from connectd: %s",
			      tal_hex(tmpctx, msg));
		return io_close(conn);
	}

	/* This can happen: we handle it gracefully, returning a `failed` msg. */
	if (socketpair(AF_LOCAL, SOCK_STREAM, 0, fds) != 0) {
		status_broken("Failed to create socketpair: %s",
			      strerror(errno));
		daemon_conn_send(daemon->connectd,
				 take(towire_gossip_new_peer_reply(NULL, false)));
		goto done;
	}

	/* We might not have noticed old peer is dead; kill it now. */
	tal_free(find_peer(daemon, &peer->id));

	/* Populate the rest of the peer info. */
	peer->daemon = daemon;
	peer->scid_queries = NULL;
	peer->scid_query_idx = 0;
	peer->scid_query_nodes = NULL;
	peer->scid_query_nodes_idx = 0;
	peer->num_scid_queries_outstanding = 0;
	peer->query_channel_blocks = NULL;
	peer->num_pings_outstanding = 0;
	peer->gossip_timer = NULL;

	/* We keep a list so we can find peer by id */
	list_add_tail(&peer->daemon->peers, &peer->list);
	tal_add_destructor(peer, destroy_peer);

	/* BOLT #7:
	 *
	 *   - if the `gossip_queries` feature is negotiated:
	 *	- MUST NOT relay any gossip messages unless explicitly requested.
	 */
	if (peer->gossip_queries_feature) {
		peer->broadcast_index = UINT64_MAX;
		/* Nothing in this "impossible" range */
		peer->gossip_timestamp_min = UINT32_MAX;
		peer->gossip_timestamp_max = 0;
	} else {
		/* BOLT #7:
		 *
		 * - upon receiving an `init` message with the
		 *   `initial_routing_sync` flag set to 1:
		 *   - SHOULD send gossip messages for all known channels and
		 *    nodes, as if they were just received.
		 * - if the `initial_routing_sync` flag is set to 0, OR if the
		 *   initial sync was completed:
		 *   - SHOULD resume normal operation, as specified in the
		 *     following [Rebroadcasting](#rebroadcasting) section.
		 */
		peer->gossip_timestamp_min = 0;
		peer->gossip_timestamp_max = UINT32_MAX;
		if (peer->initial_routing_sync_feature)
			peer->broadcast_index = 0;
		else
			peer->broadcast_index
				= peer->daemon->rstate->broadcasts->next_index;
	}

	/* This is the new connection: calls dump_gossip when nothing else to
	 * send. */
	peer->dc = daemon_conn_new(daemon, fds[0],
				   peer_msg_in, dump_gossip, peer);
	/* Free peer if conn closed (destroy_peer closes conn if peer freed) */
	tal_steal(peer->dc, peer);

	/* This sends the initial timestamp filter. */
	setup_gossip_range(peer);

	/* Start the gossip flowing. */
	wake_gossip_out(peer);

	/* Reply with success, and the new fd */
	daemon_conn_send(daemon->connectd,
			 take(towire_gossip_new_peer_reply(NULL, true)));
	daemon_conn_send_fd(daemon->connectd, fds[1]);

done:
	return daemon_conn_read_next(conn, daemon->connectd);
}

/*~ connectd can also ask us if we know any addresses for a given id. */
static struct io_plan *connectd_get_address(struct io_conn *conn,
					    struct daemon *daemon,
					    const u8 *msg)
{
	struct pubkey id;
	struct node *node;
	const struct wireaddr *addrs;

	if (!fromwire_gossip_get_addrs(msg, &id)) {
		status_broken("Bad gossip_get_addrs msg from connectd: %s",
			      tal_hex(tmpctx, msg));
		return io_close(conn);
	}

	node = get_node(daemon->rstate, &id);
	if (node)
		addrs = node->addresses;
	else
		addrs = NULL;

	daemon_conn_send(daemon->connectd,
			 take(towire_gossip_get_addrs_reply(NULL, addrs)));
	return daemon_conn_read_next(conn, daemon->connectd);
}

/*~ connectd's input handler is very simple. */
static struct io_plan *connectd_req(struct io_conn *conn,
				    const u8 *msg,
				    struct daemon *daemon)
{
	enum connect_gossip_wire_type t = fromwire_peektype(msg);

	switch (t) {
	case WIRE_GOSSIP_NEW_PEER:
		return connectd_new_peer(conn, daemon, msg);

	case WIRE_GOSSIP_GET_ADDRS:
		return connectd_get_address(conn, daemon, msg);

	/* We send these, don't receive them. */
	case WIRE_GOSSIP_NEW_PEER_REPLY:
	case WIRE_GOSSIP_GET_ADDRS_REPLY:
		break;
	}

	status_broken("Bad msg from connectd: %s",
		      tal_hex(tmpctx, msg));
	return io_close(conn);
}

/*~ This is our twice-weekly timer callback for refreshing our channels.  This
 * was added to the spec because people abandoned their channels without
 * closing them. */
static void gossip_send_keepalive_update(struct daemon *daemon,
					 const struct chan *chan,
					 const struct half_chan *hc)
{
	status_trace("Sending keepalive channel_update for %s",
		     type_to_string(tmpctx, struct short_channel_id,
				    &chan->scid));

	/* As a side-effect, this will create an update which matches the
	 * local_disabled state */
	update_local_channel(daemon, chan,
			     hc->channel_flags & ROUTING_FLAGS_DIRECTION,
			     chan->local_disabled,
			     hc->delay,
			     hc->htlc_minimum_msat,
			     hc->base_fee,
			     hc->proportional_fee,
			     hc->htlc_maximum_msat,
			     __func__);
}


/* BOLT #7:
 *
 * An endpoint node:
 *  - if a channel's latest `channel_update`s `timestamp` is older than two weeks
 *    (1209600 seconds):
 *     - MAY prune the channel.
 *     - MAY ignore the channel.
 */
static void gossip_refresh_network(struct daemon *daemon)
{
	u64 now = time_now().ts.tv_sec;
	/* Anything below this highwater mark could be pruned if not refreshed */
	s64 highwater = now - daemon->rstate->prune_timeout / 2;
	struct node *n;

	/* Schedule next run now (prune_timeout is 2 weeks) */
	new_reltimer(&daemon->timers, daemon,
		     time_from_sec(daemon->rstate->prune_timeout/4),
		     gossip_refresh_network, daemon);

	/* Find myself in the network */
	n = get_node(daemon->rstate, &daemon->id);
	if (n) {
		/* Iterate through all outgoing connection and check whether
		 * it's time to re-announce */
		for (size_t i = 0; i < tal_count(n->chans); i++) {
			struct half_chan *hc = half_chan_from(n, n->chans[i]);

			if (!is_halfchan_defined(hc)) {
				/* Connection is not announced yet, so don't even
				 * try to re-announce it */
				continue;
			}

			if (hc->last_timestamp > highwater) {
				/* No need to send a keepalive update message */
				continue;
			}

			if (!is_halfchan_enabled(hc)) {
				/* Only send keepalives for active connections */
				continue;
			}

			gossip_send_keepalive_update(daemon, n->chans[i], hc);
		}
	}

	/* Now we've refreshed our channels, we can prune without clobbering
	 * them */
	route_prune(daemon->rstate);
}

/* Disables all channels connected to our node. */
static void gossip_disable_local_channels(struct daemon *daemon)
{
	struct node *local_node = get_node(daemon->rstate, &daemon->id);

	/* We don't have a local_node, so we don't have any channels yet
	 * either */
	if (!local_node)
		return;

	for (size_t i = 0; i < tal_count(local_node->chans); i++)
		local_node->chans[i]->local_disabled = true;
}

/*~ Parse init message from lightningd: starts the daemon properly. */
static struct io_plan *gossip_init(struct io_conn *conn,
				   struct daemon *daemon,
				   const u8 *msg)
{
	struct bitcoin_blkid chain_hash;
	u32 update_channel_interval;

	if (!fromwire_gossipctl_init(daemon, msg,
				     /* 60,000 ms
				      * (unless --dev-broadcast-interval) */
				     &daemon->broadcast_interval_msec,
				     &chain_hash,
				     &daemon->id, &daemon->globalfeatures,
				     daemon->rgb,
				     daemon->alias,
				     /* 1 week in seconds
				      * (unless --dev-channel-update-interval) */
				     &update_channel_interval,
				     &daemon->announcable)) {
		master_badmsg(WIRE_GOSSIPCTL_INIT, msg);
	}

	/* Prune time (usually 2 weeks) is twice update time */
	daemon->rstate = new_routing_state(daemon, &chain_hash, &daemon->id,
					   update_channel_interval * 2);

	/* Load stored gossip messages */
	gossip_store_load(daemon->rstate, daemon->rstate->store);

	/* Now disable all local channels, they can't be connected yet. */
	gossip_disable_local_channels(daemon);

	/* If that announced channels, we can announce ourselves (options
	 * or addresses might have changed!) */
	maybe_send_own_node_announce(daemon);

	/* Start the weekly refresh timer. */
	new_reltimer(&daemon->timers, daemon,
		     time_from_sec(daemon->rstate->prune_timeout/4),
		     gossip_refresh_network, daemon);

	return daemon_conn_read_next(conn, daemon->master);
}

/*~ lightningd can ask for a route between nodes. */
static struct io_plan *getroute_req(struct io_conn *conn, struct daemon *daemon,
				    const u8 *msg)
{
	struct pubkey source, destination;
	u64 msatoshi;
	u32 final_cltv;
	u16 riskfactor;
	u8 *out;
	struct route_hop *hops;
	double fuzz;
	struct siphash_seed seed;

	/* To choose between variations, we need to know how much we're
	 * sending (eliminates too-small channels, and also effects the fees
	 * we'll pay), how to trade off more locktime vs. more fees, and how
	 * much cltv we need a the final node to give exact values for each
	 * intermediate hop, as well as how much random fuzz to inject to
	 * avoid being too predictable. */
	if (!fromwire_gossip_getroute_request(msg,
					      &source, &destination,
					      &msatoshi, &riskfactor,
					      &final_cltv, &fuzz, &seed))
		master_badmsg(WIRE_GOSSIP_GETROUTE_REQUEST, msg);

	status_trace("Trying to find a route from %s to %s for %"PRIu64" msatoshi",
		     pubkey_to_hexstr(tmpctx, &source),
		     pubkey_to_hexstr(tmpctx, &destination), msatoshi);

	/* routing.c does all the hard work; can return NULL. */
	hops = get_route(tmpctx, daemon->rstate, &source, &destination,
			 msatoshi, riskfactor, final_cltv,
			 fuzz, &seed);

	out = towire_gossip_getroute_reply(NULL, hops);
	daemon_conn_send(daemon->master, take(out));
	return daemon_conn_read_next(conn, daemon->master);
}

#define raw_pubkey(arr, id)				\
	do { BUILD_ASSERT(sizeof(arr) == sizeof(*id));	\
		memcpy(arr, id, sizeof(*id));		\
	} while(0)

/*~ When someone asks lightningd to `listchannels`, gossipd does the work:
 * marshalling the channel information for all channels into an array of
 * gossip_getchannels_entry, which lightningd converts to JSON.  Each channel
 * is represented by two half_chan; one in each direction.
 *
 * FIXME: I run a lightning node permanently under valgrind, and Christian ran
 * `listchannels` on it.  After about 15 minutes I simply rebooted.  There's
 * been some optimization since then, but blocking gossipd to marshall all the
 * channels will become in issue in future, I expect.  We may even hit the
 * 2^24 internal message limit.
 */
static void append_half_channel(struct gossip_getchannels_entry **entries,
				const struct chan *chan,
				int idx)
{
	const struct half_chan *c = &chan->half[idx];
	struct gossip_getchannels_entry *e;

	/* If we've never seen a channel_update for this direction... */
	if (!is_halfchan_defined(c))
		return;

	e = tal_arr_expand(entries);

	/* Our 'struct chan' contains two nodes: they are in pubkey_cmp order
	 * (ie. chan->nodes[0] is the lesser pubkey) and this is the same as
	 * the direction bit in `channel_update`s `channel_flags`.
	 *
	 * The halfchans are arranged so that half[0] src == nodes[0], and we
	 * use that here.  We also avoid using libsecp256k1 to translate the
	 * pubkeys to DER and back: that proves quite expensive, and we assume
	 * we're on the same architecture as lightningd, so we just send them
	 * raw in this case. */
	raw_pubkey(e->source, &chan->nodes[idx]->id);
	raw_pubkey(e->destination, &chan->nodes[!idx]->id);
	e->satoshis = chan->satoshis;
	e->channel_flags = c->channel_flags;
	e->message_flags = c->message_flags;
	e->local_disabled = chan->local_disabled;
	e->public = is_chan_public(chan);
	e->short_channel_id = chan->scid;
	e->last_update_timestamp = c->last_timestamp;
	e->base_fee_msat = c->base_fee;
	e->fee_per_millionth = c->proportional_fee;
	e->delay = c->delay;
}

/*~ Marshal (possibly) both channel directions into entries */
static void append_channel(struct gossip_getchannels_entry **entries,
			   const struct chan *chan)
{
	append_half_channel(entries, chan, 0);
	append_half_channel(entries, chan, 1);
}

/*~ This is where lightningd asks for all channels we know about. */
static struct io_plan *getchannels_req(struct io_conn *conn,
				       struct daemon *daemon,
				       const u8 *msg)
{
	u8 *out;
	struct gossip_getchannels_entry *entries;
	struct chan *chan;
	struct short_channel_id *scid;

	/* Note: scid is marked optional in gossip_wire.csv */
	if (!fromwire_gossip_getchannels_request(msg, msg, &scid))
		master_badmsg(WIRE_GOSSIP_GETCHANNELS_REQUEST, msg);

	entries = tal_arr(tmpctx, struct gossip_getchannels_entry, 0);
	/* They can ask about a particular channel by short_channel_id */
	if (scid) {
		chan = get_channel(daemon->rstate, scid);
		if (chan)
			append_channel(&entries, chan);
	} else {
		u64 idx;

		/* For the more general case, we just iterate through every
		 * short channel id. */
		for (chan = uintmap_first(&daemon->rstate->chanmap, &idx);
		     chan;
		     chan = uintmap_after(&daemon->rstate->chanmap, &idx)) {
			append_channel(&entries, chan);
		}
	}

	out = towire_gossip_getchannels_reply(NULL, entries);
	daemon_conn_send(daemon->master, take(out));
	return daemon_conn_read_next(conn, daemon->master);
}

/*~ Similarly, lightningd asks us for all nodes when it gets `listnodes` */
/* We keep pointers into n, assuming it won't change. */
static void append_node(const struct gossip_getnodes_entry ***entries,
			const struct node *n)
{
	struct gossip_getnodes_entry *e;

	*tal_arr_expand(entries) = e
		= tal(*entries, struct gossip_getnodes_entry);
	raw_pubkey(e->nodeid, &n->id);
	e->last_timestamp = n->last_timestamp;
	/* Timestamp on wire is an unsigned 32 bit: we use a 64-bit signed, so
	 * -1 means "we never received a channel_update". */
	if (e->last_timestamp < 0)
		return;

	e->globalfeatures = n->globalfeatures;
	e->addresses = n->addresses;
	BUILD_ASSERT(ARRAY_SIZE(e->alias) == ARRAY_SIZE(n->alias));
	BUILD_ASSERT(ARRAY_SIZE(e->color) == ARRAY_SIZE(n->rgb_color));
	memcpy(e->alias, n->alias, ARRAY_SIZE(e->alias));
	memcpy(e->color, n->rgb_color, ARRAY_SIZE(e->color));
}

/* Simply routine when they ask for `listnodes` */
static struct io_plan *getnodes(struct io_conn *conn, struct daemon *daemon,
				const u8 *msg)
{
	u8 *out;
	struct node *n;
	const struct gossip_getnodes_entry **nodes;
	struct pubkey *id;

	if (!fromwire_gossip_getnodes_request(tmpctx, msg, &id))
		master_badmsg(WIRE_GOSSIP_GETNODES_REQUEST, msg);

	/* Format of reply is the same whether they ask for a specific node
	 * (0 or one responses) or all nodes (0 or more) */
	nodes = tal_arr(tmpctx, const struct gossip_getnodes_entry *, 0);
	if (id) {
		n = get_node(daemon->rstate, id);
		if (n)
			append_node(&nodes, n);
	} else {
		struct node_map_iter i;
		n = node_map_first(daemon->rstate->nodes, &i);
		while (n != NULL) {
			append_node(&nodes, n);
			n = node_map_next(daemon->rstate->nodes, &i);
		}
	}
	out = towire_gossip_getnodes_reply(NULL, nodes);
	daemon_conn_send(daemon->master, take(out));
	return daemon_conn_read_next(conn, daemon->master);
}

/*~ We currently have a JSON command to ping a peer: it ends up here, where
 * gossipd generates the actual ping and sends it like any other gossip. */
static struct io_plan *ping_req(struct io_conn *conn, struct daemon *daemon,
				const u8 *msg)
{
	struct pubkey id;
	u16 num_pong_bytes, len;
	struct peer *peer;
	u8 *ping;

	if (!fromwire_gossip_ping(msg, &id, &num_pong_bytes, &len))
		master_badmsg(WIRE_GOSSIP_PING, msg);

	/* Even if lightningd were to check for valid ids, there's a race
	 * where it might vanish before we read this command; cleaner to
	 * handle it here with 'sent' = false. */
	peer = find_peer(daemon, &id);
	if (!peer) {
		daemon_conn_send(daemon->master,
				 take(towire_gossip_ping_reply(NULL, &id,
							       false, 0)));
		goto out;
	}

	/* It should never ask for an oversize ping. */
	ping = make_ping(peer, num_pong_bytes, len);
	if (tal_count(ping) > 65535)
		status_failed(STATUS_FAIL_MASTER_IO, "Oversize ping");

	queue_peer_msg(peer, take(ping));
	status_trace("sending ping expecting %sresponse",
		     num_pong_bytes >= 65532 ? "no " : "");

	/* BOLT #1:
	 *
	 * A node receiving a `ping` message:
	 *...
	 *  - if `num_pong_bytes` is less than 65532:
	 *    - MUST respond by sending a `pong` message, with `byteslen` equal
	 *      to `num_pong_bytes`.
	 *  - otherwise (`num_pong_bytes` is **not** less than 65532):
	 *    - MUST ignore the `ping`.
	 */
	if (num_pong_bytes >= 65532)
		daemon_conn_send(daemon->master,
				 take(towire_gossip_ping_reply(NULL, &id,
							       true, 0)));
	else
		/* We'll respond to lightningd once the pong comes in */
		peer->num_pings_outstanding++;

out:
	return daemon_conn_read_next(conn, daemon->master);
}

/*~ For routeboost, we offer payers a hint of what incoming channels might
 * have capacity for their payment.  To do this, lightningd asks for the
 * information about all channels to this node; but gossipd doesn't know about
 * current capacities, so lightningd selects which to use. */
static struct io_plan *get_incoming_channels(struct io_conn *conn,
					     struct daemon *daemon,
					     const u8 *msg)
{
	struct node *node;
	struct route_info *r = tal_arr(tmpctx, struct route_info, 0);

	if (!fromwire_gossip_get_incoming_channels(msg))
		master_badmsg(WIRE_GOSSIP_GET_INCOMING_CHANNELS, msg);

	node = get_node(daemon->rstate, &daemon->rstate->local_id);
	if (node) {
		for (size_t i = 0; i < tal_count(node->chans); i++) {
			const struct chan *c = node->chans[i];
			const struct half_chan *hc;
			struct route_info *ri;

			/* Don't leak private channels. */
			if (!is_chan_public(c))
				continue;

			hc = &c->half[half_chan_to(node, c)];

			if (!is_halfchan_enabled(hc))
				continue;

			ri = tal_arr_expand(&r);
			ri->pubkey = other_node(node, c)->id;
			ri->short_channel_id = c->scid;
			ri->fee_base_msat = hc->base_fee;
			ri->fee_proportional_millionths = hc->proportional_fee;
			ri->cltv_expiry_delta = hc->delay;
		}
	}

	msg = towire_gossip_get_incoming_channels_reply(NULL, r);
	daemon_conn_send(daemon->master, take(msg));

	return daemon_conn_read_next(conn, daemon->master);
}

#if DEVELOPER
/* FIXME: One day this will be called internally; for now it's just for
 * testing with dev_query_scids. */
static struct io_plan *query_scids_req(struct io_conn *conn,
				       struct daemon *daemon,
				       const u8 *msg)
{
	struct pubkey id;
	struct short_channel_id *scids;
	struct peer *peer;
	u8 *encoded;
	/* BOLT #7:
	 *
	 * 1. type: 261 (`query_short_channel_ids`) (`gossip_queries`)
	 * 2. data:
	 *     * [`32`:`chain_hash`]
	 *     * [`2`:`len`]
	 *     * [`len`:`encoded_short_ids`]
	 */
	const size_t reply_overhead = 32 + 2;
	const size_t max_encoded_bytes = 65535 - 2 - reply_overhead;

	if (!fromwire_gossip_query_scids(msg, msg, &id, &scids))
		master_badmsg(WIRE_GOSSIP_QUERY_SCIDS, msg);

	peer = find_peer(daemon, &id);
	if (!peer) {
		status_broken("query_scids: unknown peer %s",
			      type_to_string(tmpctx, struct pubkey, &id));
		goto fail;
	}

	if (!peer->gossip_queries_feature) {
		status_broken("query_scids: no gossip_query support in peer %s",
			      type_to_string(tmpctx, struct pubkey, &id));
		goto fail;
	}

	encoded = encode_short_channel_ids_start(tmpctx);
	for (size_t i = 0; i < tal_count(scids); i++)
		encode_add_short_channel_id(&encoded, &scids[i]);

	/* Because this is a dev command, we simply say this case is
	 * "too hard". */
	if (!encode_short_channel_ids_end(&encoded, max_encoded_bytes)) {
		status_broken("query_short_channel_ids: %zu is too many",
			      tal_count(scids));
		goto fail;
	}

	msg = towire_query_short_channel_ids(NULL, &daemon->rstate->chain_hash,
					     encoded);
	queue_peer_msg(peer, take(msg));
	peer->num_scid_queries_outstanding++;

	status_trace("sending query for %zu scids", tal_count(scids));
out:
	return daemon_conn_read_next(conn, daemon->master);

fail:
	daemon_conn_send(daemon->master,
			 take(towire_gossip_scids_reply(NULL, false, false)));
	goto out;
}

/* BOLT #7:
 *
 * ### The `gossip_timestamp_filter` Message
 *...
 * This message allows a node to constrain future gossip messages to
 * a specific range.  A node which wants any gossip messages would have
 * to send this, otherwise `gossip_queries` negotiation means no gossip
 * messages would be received.
 *
 * Note that this filter replaces any previous one, so it can be used
 * multiple times to change the gossip from a peer. */
/* This is the entry point for dev_send_timestamp_filter testing. */
static struct io_plan *send_timestamp_filter(struct io_conn *conn,
					     struct daemon *daemon,
					     const u8 *msg)
{
	struct pubkey id;
	u32 first, range;
	struct peer *peer;

	if (!fromwire_gossip_send_timestamp_filter(msg, &id, &first, &range))
		master_badmsg(WIRE_GOSSIP_SEND_TIMESTAMP_FILTER, msg);

	peer = find_peer(daemon, &id);
	if (!peer) {
		status_broken("send_timestamp_filter: unknown peer %s",
			      type_to_string(tmpctx, struct pubkey, &id));
		goto out;
	}

	if (!peer->gossip_queries_feature) {
		status_broken("send_timestamp_filter: no gossip_query support in peer %s",
			      type_to_string(tmpctx, struct pubkey, &id));
		goto out;
	}

	msg = towire_gossip_timestamp_filter(NULL, &daemon->rstate->chain_hash,
					     first, range);
	queue_peer_msg(peer, take(msg));
out:
	return daemon_conn_read_next(conn, daemon->master);
}

/* FIXME: One day this will be called internally; for now it's just for
 * testing with dev_query_channel_range. */
static struct io_plan *query_channel_range(struct io_conn *conn,
					   struct daemon *daemon,
					   const u8 *msg)
{
	struct pubkey id;
	u32 first_blocknum, number_of_blocks;
	struct peer *peer;

	if (!fromwire_gossip_query_channel_range(msg, &id, &first_blocknum,
						 &number_of_blocks))
		master_badmsg(WIRE_GOSSIP_QUERY_SCIDS, msg);

	peer = find_peer(daemon, &id);
	if (!peer) {
		status_broken("query_channel_range: unknown peer %s",
			      type_to_string(tmpctx, struct pubkey, &id));
		goto fail;
	}

	if (!peer->gossip_queries_feature) {
		status_broken("query_channel_range: no gossip_query support in peer %s",
			      type_to_string(tmpctx, struct pubkey, &id));
		goto fail;
	}

	if (peer->query_channel_blocks) {
		status_broken("query_channel_range: previous query active");
		goto fail;
	}

	status_debug("sending query_channel_range for blocks %u+%u",
		     first_blocknum, number_of_blocks);
	msg = towire_query_channel_range(NULL, &daemon->rstate->chain_hash,
					 first_blocknum, number_of_blocks);
	queue_peer_msg(peer, take(msg));
	peer->range_first_blocknum = first_blocknum;
	peer->range_end_blocknum = first_blocknum + number_of_blocks;
	peer->range_blocks_remaining = number_of_blocks;
	peer->query_channel_blocks = tal_arrz(peer, bitmap,
					      BITMAP_NWORDS(number_of_blocks));
	peer->query_channel_scids = tal_arr(peer, struct short_channel_id, 0);

out:
	return daemon_conn_read_next(conn, daemon->master);

fail:
	daemon_conn_send(daemon->master,
			 take(towire_gossip_query_channel_range_reply(NULL,
								      0, 0,
								      false,
								      NULL)));
	goto out;
}

/* This is a testing hack to allow us to artificially lower the maximum bytes
 * of short_channel_ids we'll encode, using dev_set_max_scids_encode_size. */
static struct io_plan *dev_set_max_scids_encode_size(struct io_conn *conn,
						     struct daemon *daemon,
						     const u8 *msg)
{
	if (!fromwire_gossip_dev_set_max_scids_encode_size(msg,
							   &max_scids_encode_bytes))
		master_badmsg(WIRE_GOSSIP_DEV_SET_MAX_SCIDS_ENCODE_SIZE, msg);

	status_trace("Set max_scids_encode_bytes to %u", max_scids_encode_bytes);
	return daemon_conn_read_next(conn, daemon->master);
}

/* Another testing hack */
static struct io_plan *dev_gossip_suppress(struct io_conn *conn,
					   struct daemon *daemon,
					   const u8 *msg)
{
	if (!fromwire_gossip_dev_suppress(msg))
		master_badmsg(WIRE_GOSSIP_DEV_SUPPRESS, msg);

	status_unusual("Suppressing all gossip");
	suppress_gossip = true;
	return daemon_conn_read_next(conn, daemon->master);
}
#endif /* DEVELOPER */

/*~ lightningd: so, tell me about this channel, so we can forward to it. */
static struct io_plan *get_channel_peer(struct io_conn *conn,
					struct daemon *daemon, const u8 *msg)
{
	struct short_channel_id scid;
	struct chan *chan;
	const struct pubkey *key;
	int direction;

	if (!fromwire_gossip_get_channel_peer(msg, &scid))
		master_badmsg(WIRE_GOSSIP_GET_CHANNEL_PEER, msg);

	chan = get_channel(daemon->rstate, &scid);
	if (!chan) {
		status_trace("Failed to resolve channel %s",
			     type_to_string(tmpctx, struct short_channel_id, &scid));
		key = NULL;
	} else if (local_direction(daemon, chan, &direction)) {
		key = &chan->nodes[!direction]->id;
	} else {
		status_trace("Resolved channel %s was not local",
			     type_to_string(tmpctx, struct short_channel_id,
					    &scid));
		key = NULL;
	}
	daemon_conn_send(daemon->master,
			 take(towire_gossip_get_channel_peer_reply(NULL, key)));
	return daemon_conn_read_next(conn, daemon->master);
}

/*~ We queue incoming channel_announcement pending confirmation from lightningd
 * that it really is an unspent output.  Here's its reply. */
static struct io_plan *handle_txout_reply(struct io_conn *conn,
					  struct daemon *daemon, const u8 *msg)
{
	struct short_channel_id scid;
	u8 *outscript;
	u64 satoshis;

	if (!fromwire_gossip_get_txout_reply(msg, msg, &scid, &satoshis, &outscript))
		master_badmsg(WIRE_GOSSIP_GET_TXOUT_REPLY, msg);

	/* Outscript is NULL if it's not an unspent output */
	handle_pending_cannouncement(daemon->rstate, &scid, satoshis, outscript);

	/* Anywhere we might have announced a channel, we check if it's time to
	 * announce ourselves (ie. if we just announced our own first channel) */
	maybe_send_own_node_announce(daemon);

	return daemon_conn_read_next(conn, daemon->master);
}

/*~ lightningd tells us when a payment has failed; we mark the channel (or
 * node) unusable here (maybe temporarily), and unpack and channel_update
 * contained in the error. */
static struct io_plan *handle_routing_failure(struct io_conn *conn,
					      struct daemon *daemon,
					      const u8 *msg)
{
	struct pubkey erring_node;
	struct short_channel_id erring_channel;
	u16 failcode;
	u8 *channel_update;

	if (!fromwire_gossip_routing_failure(msg,
					     msg,
					     &erring_node,
					     &erring_channel,
					     &failcode,
					     &channel_update))
		master_badmsg(WIRE_GOSSIP_ROUTING_FAILURE, msg);

	routing_failure(daemon->rstate,
			&erring_node,
			&erring_channel,
			(enum onion_type) failcode,
			channel_update);

	return daemon_conn_read_next(conn, daemon->master);
}

/*~ This allows lightningd to explicitly mark a channel temporarily unroutable.
 * This is used when we get an unparsable error, and we don't know who to blame;
 * lightningd uses this to marking routes unroutable at random... */
static struct io_plan *
handle_mark_channel_unroutable(struct io_conn *conn,
			       struct daemon *daemon,
			       const u8 *msg)
{
	struct short_channel_id channel;

	if (!fromwire_gossip_mark_channel_unroutable(msg, &channel))
		master_badmsg(WIRE_GOSSIP_MARK_CHANNEL_UNROUTABLE, msg);

	mark_channel_unroutable(daemon->rstate, &channel);

	return daemon_conn_read_next(conn, daemon->master);
}

/*~ This is where lightningd tells us that a channel's funding transaction has
 * been spent. */
static struct io_plan *handle_outpoint_spent(struct io_conn *conn,
					     struct daemon *daemon,
					     const u8 *msg)
{
	struct short_channel_id scid;
	struct chan *chan;
	struct routing_state *rstate = daemon->rstate;
	if (!fromwire_gossip_outpoint_spent(msg, &scid))
		master_badmsg(WIRE_GOSSIP_ROUTING_FAILURE, msg);

	chan = get_channel(rstate, &scid);
	if (chan) {
		status_trace(
		    "Deleting channel %s due to the funding outpoint being "
		    "spent",
		    type_to_string(msg, struct short_channel_id, &scid));
		/* Freeing is sufficient since everything else is allocated off
		 * of the channel and the destructor takes care of unregistering
		 * the channel */
		tal_free(chan);
		/* We put a tombstone marker in the channel store, so we don't
		 * have to replay blockchain spends on restart. */
		gossip_store_add_channel_delete(rstate->store, &scid);
	}

	return daemon_conn_read_next(conn, daemon->master);
}

/*~ This is sent by lightningd when it kicks off 'closingd': we disable it
 * in both directions.
 *
 * We'll leave it to handle_outpoint_spent to delete the channel from our view
 * once the close gets confirmed. This avoids having strange states in which the
 * channel is list in our peer list but won't be returned when listing public
 * channels. This does not send out updates since that's triggered by the peer
 * connection closing.
 */
static struct io_plan *handle_local_channel_close(struct io_conn *conn,
						  struct daemon *daemon,
						  const u8 *msg)
{
	struct short_channel_id scid;
	struct chan *chan;
	struct routing_state *rstate = daemon->rstate;
	if (!fromwire_gossip_local_channel_close(msg, &scid))
		master_badmsg(WIRE_GOSSIP_ROUTING_FAILURE, msg);

	chan = get_channel(rstate, &scid);
	if (chan)
		chan->local_disabled = true;
	return daemon_conn_read_next(conn, daemon->master);
}

/*~ This routine handles all the commands from lightningd. */
static struct io_plan *recv_req(struct io_conn *conn,
				const u8 *msg,
				struct daemon *daemon)
{
	enum gossip_wire_type t = fromwire_peektype(msg);

	switch (t) {
	case WIRE_GOSSIPCTL_INIT:
		return gossip_init(conn, daemon, msg);

	case WIRE_GOSSIP_GETNODES_REQUEST:
		return getnodes(conn, daemon, msg);

	case WIRE_GOSSIP_GETROUTE_REQUEST:
		return getroute_req(conn, daemon, msg);

	case WIRE_GOSSIP_GETCHANNELS_REQUEST:
		return getchannels_req(conn, daemon, msg);

	case WIRE_GOSSIP_GET_CHANNEL_PEER:
		return get_channel_peer(conn, daemon, msg);

	case WIRE_GOSSIP_GET_TXOUT_REPLY:
		return handle_txout_reply(conn, daemon, msg);

	case WIRE_GOSSIP_ROUTING_FAILURE:
		return handle_routing_failure(conn, daemon, msg);

	case WIRE_GOSSIP_MARK_CHANNEL_UNROUTABLE:
		return handle_mark_channel_unroutable(conn, daemon, msg);

	case WIRE_GOSSIP_OUTPOINT_SPENT:
		return handle_outpoint_spent(conn, daemon, msg);

	case WIRE_GOSSIP_LOCAL_CHANNEL_CLOSE:
		return handle_local_channel_close(conn, daemon, msg);

	case WIRE_GOSSIP_PING:
		return ping_req(conn, daemon, msg);

	case WIRE_GOSSIP_GET_INCOMING_CHANNELS:
		return get_incoming_channels(conn, daemon, msg);

#if DEVELOPER
	case WIRE_GOSSIP_QUERY_SCIDS:
		return query_scids_req(conn, daemon, msg);

	case WIRE_GOSSIP_SEND_TIMESTAMP_FILTER:
		return send_timestamp_filter(conn, daemon, msg);

	case WIRE_GOSSIP_QUERY_CHANNEL_RANGE:
		return query_channel_range(conn, daemon, msg);

	case WIRE_GOSSIP_DEV_SET_MAX_SCIDS_ENCODE_SIZE:
		return dev_set_max_scids_encode_size(conn, daemon, msg);
	case WIRE_GOSSIP_DEV_SUPPRESS:
		return dev_gossip_suppress(conn, daemon, msg);
#else
	case WIRE_GOSSIP_QUERY_SCIDS:
	case WIRE_GOSSIP_SEND_TIMESTAMP_FILTER:
	case WIRE_GOSSIP_QUERY_CHANNEL_RANGE:
	case WIRE_GOSSIP_DEV_SET_MAX_SCIDS_ENCODE_SIZE:
	case WIRE_GOSSIP_DEV_SUPPRESS:
		break;
#endif /* !DEVELOPER */

	/* We send these, we don't receive them */
	case WIRE_GOSSIP_GETNODES_REPLY:
	case WIRE_GOSSIP_GETROUTE_REPLY:
	case WIRE_GOSSIP_GETCHANNELS_REPLY:
	case WIRE_GOSSIP_PING_REPLY:
	case WIRE_GOSSIP_SCIDS_REPLY:
	case WIRE_GOSSIP_QUERY_CHANNEL_RANGE_REPLY:
	case WIRE_GOSSIP_GET_CHANNEL_PEER_REPLY:
	case WIRE_GOSSIP_GET_INCOMING_CHANNELS_REPLY:
	case WIRE_GOSSIP_GET_TXOUT:
		break;
	}

	/* Master shouldn't give bad requests. */
	status_failed(STATUS_FAIL_MASTER_IO, "%i: %s",
		      t, tal_hex(tmpctx, msg));
}

/* This is called when lightningd closes its connection to us.  We simply
 * exit. */
static void master_gone(struct daemon_conn *master UNUSED)
{
	daemon_shutdown();
	/* Can't tell master, it's gone. */
	exit(2);
}

int main(int argc, char *argv[])
{
	setup_locale();

	struct daemon *daemon;

	subdaemon_setup(argc, argv);

	daemon = tal(NULL, struct daemon);
	list_head_init(&daemon->peers);

	/* Note the use of time_mono() here.  That's a monotonic clock, which
	 * is really useful: it can only be used to measure relative events
	 * (there's no correspondence to time-since-Ken-grew-a-beard or
	 * anything), but unlike time_now(), this will never jump backwards by
	 * half a second and leave me wondering how my tests failed CI! */
	timers_init(&daemon->timers, time_mono());

	/* Our daemons always use STDIN for commands from lightningd. */
	daemon->master = daemon_conn_new(daemon, STDIN_FILENO,
					 recv_req, NULL, daemon);
	tal_add_destructor(daemon->master, master_gone);

	status_setup_async(daemon->master);

	/* connectd is already started, and uses this fd to ask us things. */
	daemon->connectd = daemon_conn_new(daemon, CONNECTD_FD,
					   connectd_req, NULL, daemon);

	/* This loop never exits.  io_loop() only returns if a timer has
	 * expired, or io_break() is called, or all fds are closed.  We don't
	 * use io_break and closing the lightningd fd calls master_gone()
	 * which exits. */
	for (;;) {
		struct timer *expired = NULL;
		io_loop(&daemon->timers, &expired);

		timer_expired(daemon, expired);
	}
}

/*~ Note that the actual routing stuff is in routing.c; you might want to
 * check that out later.
 *
 * But that's the last of the global daemons.   We now move on to the first of
 * the per-peer daemons: openingd/openingd.c.
 */
