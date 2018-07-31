#include <ccan/asort/asort.h>
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
#include <gossipd/gen_gossip_wire.h>
#include <gossipd/gossip.h>
#include <gossipd/routing.h>
#include <hsmd/client.h>
#include <hsmd/gen_hsm_client_wire.h>
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

#define HSM_FD 3
#define CONNECTD_FD 4

#if DEVELOPER
static u32 max_scids_encode_bytes = -1U;
static bool suppress_gossip = false;
#endif

struct local_update {
	/* daemon->local_updates */
	struct list_node list;

	/* Because we're handed to a one-arg timer */
	struct daemon *daemon;

	/* Which channel this is */
	struct short_channel_id scid;

	/* Which direction we own */
	int direction;

	u16 cltv_delta;
	u64 htlc_minimum_msat;
	u32 fee_base_msat, fee_proportional_millionths;
	bool disable;
};

struct daemon {
	/* Who am I? */
	struct pubkey id;

	/* Peers we have directly or indirectly: id is unique */
	struct list_head peers;

	/* Connection to main daemon. */
	struct daemon_conn master;

	/* Connection to connect daemon. */
	struct daemon_conn connectd;

	/* Routing information */
	struct routing_state *rstate;

	struct timers timers;

	u32 broadcast_interval;

	/* Global features to list in node_announcement. */
	u8 *globalfeatures;

	u8 alias[33];
	u8 rgb[3];

	/* What we can actually announce. */
	struct wireaddr *announcable;

	/* To make sure our node_announcement timestamps increase */
	u32 last_announce_timestamp;

	/* Unapplied local updates waiting for their timers. */
	struct list_head local_updates;
};

struct peer {
	struct daemon *daemon;

	/* daemon->peers */
	struct list_node list;

	/* The ID of the peer (not necessarily unique, in transit!) */
	struct pubkey id;

	bool gossip_queries_feature, initial_routing_sync_feature;

	/* High water mark for the staggered broadcast */
	u64 broadcast_index;

	/* Timestamp range to filter gossip by */
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
	u8 *query_channel_blocks;
	u32 first_channel_range;
	struct short_channel_id *query_channel_scids;

	/* FIXME: Doesn't need to be a pointer. */
	struct daemon_conn *remote;
};

/* FIXME: Reorder */
static void peer_disable_channels(struct daemon *daemon, struct node *node);
static u8 *create_channel_update(const tal_t *ctx,
				 struct routing_state *rstate,
				 const struct chan *chan,
				 int direction,
				 bool disable,
				 u16 cltv_expiry_delta,
				 u64 htlc_minimum_msat,
				 u32 fee_base_msat,
				 u32 fee_proportional_millionths);
static struct local_update *find_local_update(struct daemon *daemon,
					      const struct short_channel_id *scid);

static void destroy_peer(struct peer *peer)
{
	struct node *node;

	list_del_from(&peer->daemon->peers, &peer->list);
	node = get_node(peer->daemon->rstate, &peer->id);
	if (node)
		peer_disable_channels(peer->daemon, node);
}

static struct peer *find_peer(struct daemon *daemon, const struct pubkey *id)
{
	struct peer *peer;

	list_for_each(&daemon->peers, peer, list)
		if (pubkey_eq(&peer->id, id))
			return peer;
	return NULL;
}

static u8 *encode_short_channel_ids_start(const tal_t *ctx)
{
	u8 *encoded = tal_arr(ctx, u8, 0);
	towire_u8(&encoded, SHORTIDS_ZLIB);
	return encoded;
}

static void encode_add_short_channel_id(u8 **encoded,
					const struct short_channel_id *scid)
{
	towire_short_channel_id(encoded, scid);
}

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

static bool encode_short_channel_ids_end(u8 **encoded, size_t max_bytes)
{
	u8 *z;

	switch ((enum scid_encode_types)(*encoded)[0]) {
	case SHORTIDS_ZLIB:
		z = zencode_scids(tmpctx, *encoded + 1, tal_count(*encoded) - 1);
		if (z) {
			tal_resize(encoded, 1 + tal_count(z));
			memcpy((*encoded) + 1, z, tal_count(z));
			goto check_length;
		}
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

static void queue_peer_msg(struct peer *peer, const u8 *msg TAKES)
{
	const u8 *send = towire_gossip_send_gossip(NULL, msg);
	if (taken(msg))
		tal_free(msg);
	daemon_conn_send(peer->remote, take(send));
}

static void wake_gossip_out(struct peer *peer)
{
	/* If we were waiting, we're not any more */
	peer->gossip_timer = tal_free(peer->gossip_timer);

	/* Notify the daemon_conn-write loop */
	daemon_conn_wake(peer->remote);
}

static void peer_error(struct peer *peer, const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	status_trace("peer %s: %s",
		     type_to_string(tmpctx, struct pubkey, &peer->id),
		     tal_vfmt(tmpctx, fmt, ap));
	va_end(ap);

	/* Send error: we'll close after writing this. */
	va_start(ap, fmt);
	queue_peer_msg(peer, take(towire_errorfmtv(peer, NULL, fmt, ap)));
	va_end(ap);
}

static void setup_gossip_range(struct peer *peer)
{
	u8 *msg;

	if (!peer->gossip_queries_feature)
		return;

	/* Tell it to start gossip!  (And give us everything!) */
	msg = towire_gossip_timestamp_filter(peer,
					     &peer->daemon->rstate->chain_hash,
					     0, UINT32_MAX);
	queue_peer_msg(peer, take(msg));
}

static bool nonlocal_dump_gossip(struct io_conn *conn, struct daemon_conn *dc);

/* Create a node_announcement with the given signature. It may be NULL
 * in the case we need to create a provisional announcement for the
 * HSM to sign. This is typically called twice: once with the dummy
 * signature to get it signed and a second time to build the full
 * packet with the signature. The timestamp is handed in since that is
 * the only thing that may change between the dummy creation and the
 * call with a signature.*/
static u8 *create_node_announcement(const tal_t *ctx, struct daemon *daemon,
				    secp256k1_ecdsa_signature *sig,
				    u32 timestamp)
{
	u8 *addresses = tal_arr(ctx, u8, 0);
	u8 *announcement;
	size_t i;
	if (!sig) {
		sig = tal(ctx, secp256k1_ecdsa_signature);
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

static void send_node_announcement(struct daemon *daemon)
{
	u32 timestamp = time_now().ts.tv_sec;
	secp256k1_ecdsa_signature sig;
	u8 *msg, *nannounce, *err;

	/* Timestamps must move forward, or announce will be ignored! */
	if (timestamp <= daemon->last_announce_timestamp)
		timestamp = daemon->last_announce_timestamp + 1;
	daemon->last_announce_timestamp = timestamp;

	nannounce = create_node_announcement(tmpctx, daemon, NULL, timestamp);

	if (!wire_sync_write(HSM_FD, take(towire_hsm_node_announcement_sig_req(NULL, nannounce))))
		status_failed(STATUS_FAIL_MASTER_IO, "Could not write to HSM: %s", strerror(errno));

	msg = wire_sync_read(tmpctx, HSM_FD);
	if (!fromwire_hsm_node_announcement_sig_reply(msg, &sig))
		status_failed(STATUS_FAIL_MASTER_IO, "HSM returned an invalid node_announcement sig");

	/* We got the signature for out provisional node_announcement back
	 * from the HSM, create the real announcement and forward it to
	 * gossipd so it can take care of forwarding it. */
	nannounce = create_node_announcement(NULL, daemon, &sig, timestamp);
	err = handle_node_announcement(daemon->rstate, take(nannounce));
	if (err)
		status_failed(STATUS_FAIL_INTERNAL_ERROR,
			      "rejected own node announcement: %s",
			      tal_hex(tmpctx, err));
}

/* Should we announce our own node? */
static void maybe_send_own_node_announce(struct daemon *daemon)
{
	if (!daemon->rstate->local_channel_announced)
		return;

	/* FIXME: We may not need to retransmit here, if previous still valid. */
	send_node_announcement(daemon);
	daemon->rstate->local_channel_announced = false;
}

/**
 * Handle an incoming gossip message
 *
 * Returns wire formatted error if handling failed. The error contains the
 * details of the failures. The caller is expected to return the error to the
 * peer, or drop the error if the message did not come from a peer.
 */
static u8 *handle_gossip_msg(struct daemon *daemon, const u8 *msg,
			     const char *source)
{
	struct routing_state *rstate = daemon->rstate;
	int t = fromwire_peektype(msg);
	u8 *err;

	switch(t) {
	case WIRE_CHANNEL_ANNOUNCEMENT: {
		const struct short_channel_id *scid;
		/* If it's OK, tells us the short_channel_id to lookup */
		err = handle_channel_announcement(rstate, msg, &scid);
		if (err)
			return err;
		else if (scid)
			daemon_conn_send(&daemon->master,
					 take(towire_gossip_get_txout(NULL,
								      scid)));
		break;
	}

	case WIRE_NODE_ANNOUNCEMENT:
		err = handle_node_announcement(rstate, msg);
		if (err)
			return err;
		break;

	case WIRE_CHANNEL_UPDATE:
		err = handle_channel_update(rstate, msg, source);
		if (err)
			return err;
		/* In case we just announced a new local channel. */
		maybe_send_own_node_announce(daemon);
		break;
	}

	/* All good, no error to report */
	return NULL;
}

static void handle_query_short_channel_ids(struct peer *peer, u8 *msg)
{
	struct routing_state *rstate = peer->daemon->rstate;
	struct bitcoin_blkid chain;
	u8 *encoded;
	struct short_channel_id *scids;

	if (!fromwire_query_short_channel_ids(tmpctx, msg, &chain, &encoded)) {
		peer_error(peer, "Bad query_short_channel_ids %s",
			   tal_hex(tmpctx, msg));
		return;
	}

	if (!bitcoin_blkid_eq(&rstate->chain_hash, &chain)) {
		status_trace("%s sent query_short_channel_ids chainhash %s",
			     type_to_string(tmpctx, struct pubkey, &peer->id),
			     type_to_string(tmpctx, struct bitcoin_blkid, &chain));
		return;
	}

	/* BOLT #7:
	 *
	 * - if it has not sent `reply_short_channel_ids_end` to a
	 *   previously received `query_short_channel_ids` from this
         *   sender:
	 *    - MAY fail the connection.
	 */
	if (peer->scid_queries || peer->scid_query_nodes) {
		peer_error(peer, "Bad concurrent query_short_channel_ids");
		return;
	}

	scids = decode_short_ids(tmpctx, encoded);
	if (!scids) {
		peer_error(peer, "Bad query_short_channel_ids encoding %s",
			   tal_hex(tmpctx, encoded));
		return;
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

	/* Notify the daemon_conn-write loop */
	daemon_conn_wake(peer->remote);
}

static void handle_gossip_timestamp_filter(struct peer *peer, u8 *msg)
{
	struct bitcoin_blkid chain_hash;
	u32 first_timestamp, timestamp_range;

	if (!fromwire_gossip_timestamp_filter(msg, &chain_hash,
					      &first_timestamp,
					      &timestamp_range)) {
		peer_error(peer, "Bad gossip_timestamp_filter %s",
			   tal_hex(tmpctx, msg));
		return;
	}

	if (!bitcoin_blkid_eq(&peer->daemon->rstate->chain_hash, &chain_hash)) {
		status_trace("%s sent gossip_timestamp_filter chainhash %s",
			     type_to_string(tmpctx, struct pubkey, &peer->id),
			     type_to_string(tmpctx, struct bitcoin_blkid,
					    &chain_hash));
		return;
	}

	/* First time, start gossip sync immediately. */
	if (peer->gossip_timestamp_min > peer->gossip_timestamp_max)
		wake_gossip_out(peer);

	/* FIXME: We don't index by timestamp, so this forces a brute
	 * search! */
	peer->gossip_timestamp_min = first_timestamp;
	peer->gossip_timestamp_max = first_timestamp + timestamp_range - 1;
	if (peer->gossip_timestamp_max < peer->gossip_timestamp_min)
		peer->gossip_timestamp_max = UINT32_MAX;
	peer->broadcast_index = 0;
}

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

	while (uintmap_after(&rstate->chanmap, &scid.u64)) {
		u32 blocknum = short_channel_id_blocknum(&scid);
		if (blocknum >= first_blocknum + number_of_blocks)
			break;

		encode_add_short_channel_id(&encoded, &scid);
	}

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

static void handle_query_channel_range(struct peer *peer, u8 *msg)
{
	struct bitcoin_blkid chain_hash;
	u32 first_blocknum, number_of_blocks;

	if (!fromwire_query_channel_range(msg, &chain_hash,
					  &first_blocknum, &number_of_blocks)) {
		peer_error(peer, "Bad query_channel_range %s",
			   tal_hex(tmpctx, msg));
		return;
	}

	if (!bitcoin_blkid_eq(&peer->daemon->rstate->chain_hash, &chain_hash)) {
		status_trace("%s sent query_channel_range chainhash %s",
			     type_to_string(tmpctx, struct pubkey, &peer->id),
			     type_to_string(tmpctx, struct bitcoin_blkid,
					    &chain_hash));
		return;
	}

	if (first_blocknum + number_of_blocks < first_blocknum) {
		peer_error(peer, "query_channel_range overflow %u+%u",
			   first_blocknum, number_of_blocks);
		return;
	}
	queue_channel_ranges(peer, first_blocknum, number_of_blocks);
}

static void handle_ping(struct peer *peer, u8 *ping)
{
	u8 *pong;

	if (!check_ping_make_pong(NULL, ping, &pong)) {
		peer_error(peer, "Bad ping");
		return;
	}

	if (pong)
		queue_peer_msg(peer, take(pong));
}

static void handle_pong(struct peer *peer, const u8 *pong)
{
	const char *err = got_pong(pong, &peer->num_pings_outstanding);

	if (err) {
		peer_error(peer, "%s", err);
		return;
	}

	daemon_conn_send(&peer->daemon->master,
			 take(towire_gossip_ping_reply(NULL, true,
						       tal_count(pong))));
}

static void handle_reply_short_channel_ids_end(struct peer *peer, u8 *msg)
{
	struct bitcoin_blkid chain;
	u8 complete;

	if (!fromwire_reply_short_channel_ids_end(msg, &chain, &complete)) {
		peer_error(peer, "Bad reply_short_channel_ids_end %s",
			   tal_hex(tmpctx, msg));
		return;
	}

	if (!bitcoin_blkid_eq(&peer->daemon->rstate->chain_hash, &chain)) {
		peer_error(peer, "reply_short_channel_ids_end for bad chain: %s",
			   tal_hex(tmpctx, msg));
		return;
	}

	if (peer->num_scid_queries_outstanding == 0) {
		peer_error(peer, "unexpected reply_short_channel_ids_end: %s",
			   tal_hex(tmpctx, msg));
		return;
	}

	peer->num_scid_queries_outstanding--;
	msg = towire_gossip_scids_reply(msg, true, complete);
	daemon_conn_send(&peer->daemon->master, take(msg));
}

static void handle_reply_channel_range(struct peer *peer, u8 *msg)
{
	struct bitcoin_blkid chain;
	u8 complete;
	u32 first_blocknum, number_of_blocks;
	u8 *encoded, *p;
	struct short_channel_id *scids;
	size_t n;

	if (!fromwire_reply_channel_range(tmpctx, msg, &chain, &first_blocknum,
					  &number_of_blocks, &complete,
					  &encoded)) {
		peer_error(peer, "Bad reply_channel_range %s",
			   tal_hex(tmpctx, msg));
		return;
	}

	if (!bitcoin_blkid_eq(&peer->daemon->rstate->chain_hash, &chain)) {
		peer_error(peer, "reply_channel_range for bad chain: %s",
			   tal_hex(tmpctx, msg));
		return;
	}

	if (!peer->query_channel_blocks) {
		peer_error(peer, "reply_channel_range without query: %s",
			   tal_hex(tmpctx, msg));
		return;
	}

	if (first_blocknum + number_of_blocks < first_blocknum) {
		peer_error(peer, "reply_channel_range invalid %u+%u",
			   first_blocknum, number_of_blocks);
		return;
	}

	scids = decode_short_ids(tmpctx, encoded);
	if (!scids) {
		peer_error(peer, "Bad reply_channel_range encoding %s",
			   tal_hex(tmpctx, encoded));
		return;
	}

	n = first_blocknum - peer->first_channel_range;
	if (first_blocknum < peer->first_channel_range
	    || n + number_of_blocks > tal_count(peer->query_channel_blocks)) {
		peer_error(peer, "reply_channel_range invalid %u+%u for query %u+%u",
			   first_blocknum, number_of_blocks,
			   peer->first_channel_range,
			   tal_count(peer->query_channel_blocks));
		return;
	}

	p = memchr(peer->query_channel_blocks + n, 1, number_of_blocks);
	if (p) {
		peer_error(peer, "reply_channel_range %u+%u already have block %zu",
			   first_blocknum, number_of_blocks,
			   peer->first_channel_range + (p - peer->query_channel_blocks));
		return;
	}

	/* Mark these blocks received */
	memset(peer->query_channel_blocks + n, 1, number_of_blocks);

	/* Add scids */
	n = tal_count(peer->query_channel_scids);
	tal_resize(&peer->query_channel_scids, n + tal_count(scids));
	memcpy(peer->query_channel_scids + n, scids, tal_bytelen(scids));

	status_debug("peer %s reply_channel_range %u+%u (of %u+%zu) %zu scids",
		     type_to_string(tmpctx, struct pubkey, &peer->id),
		     first_blocknum, number_of_blocks,
		     peer->first_channel_range,
		     tal_count(peer->query_channel_blocks),
		     tal_count(scids));

	/* Still more to go? */
	if (memchr(peer->query_channel_blocks, 0,
		   tal_count(peer->query_channel_blocks)))
		return;

	/* All done, send reply */
	msg = towire_gossip_query_channel_range_reply(NULL,
						      first_blocknum,
						      number_of_blocks,
						      complete,
						      peer->query_channel_scids);
	daemon_conn_send(&peer->daemon->master, take(msg));
	peer->query_channel_scids = tal_free(peer->query_channel_scids);
	peer->query_channel_blocks = tal_free(peer->query_channel_blocks);
}

/* We keep a simple array of node ids while we're sending channel info */
static void append_query_node(struct peer *peer, const struct pubkey *id)
{
	size_t n;
	n = tal_count(peer->scid_query_nodes);
	tal_resize(&peer->scid_query_nodes, n+1);
	peer->scid_query_nodes[n] = *id;
}

/* Arbitrary ordering function of pubkeys.
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
	asort(*ids, tal_count(*ids), pubkey_order, NULL);

	for (dst = 0, src = 0; src < tal_count(*ids); src++) {
		if (dst && pubkey_eq(&(*ids)[dst-1], &(*ids)[src]))
			continue;
		(*ids)[dst++] = (*ids)[src];
	}
	tal_resize(ids, dst);
}

static bool create_next_scid_reply(struct peer *peer)
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
	num = tal_count(peer->scid_queries);
	for (i = peer->scid_query_idx; !sent && i < num; i++) {
		struct chan *chan;

		chan = get_channel(rstate, &peer->scid_queries[i]);
		if (!chan || !is_chan_public(chan))
			continue;

		queue_peer_msg(peer, chan->channel_announce);
		if (chan->half[0].channel_update)
			queue_peer_msg(peer, chan->half[0].channel_update);
		if (chan->half[1].channel_update)
			queue_peer_msg(peer, chan->half[1].channel_update);

		/* Record node ids for later transmission of node_announcement */
		append_query_node(peer, &chan->nodes[0]->id);
		append_query_node(peer, &chan->nodes[1]->id);
		sent = true;
	}

	/* Just finished channels?  Remove duplicate nodes. */
	if (peer->scid_query_idx != num && i == num)
		uniquify_node_ids(&peer->scid_query_nodes);
	peer->scid_query_idx = i;

	/* BOLT #7:
	 *
	 *  - MUST follow with any `node_announcement`s for each
	 *   `channel_announcement`
	 *    - SHOULD avoid sending duplicate `node_announcements` in response
	 *     to a single `query_short_channel_ids`.
	 */
	num = tal_count(peer->scid_query_nodes);
	for (i = peer->scid_query_nodes_idx; !sent && i < num; i++) {
		const struct node *n;

		n = get_node(rstate, &peer->scid_query_nodes[i]);
		if (!n || !n->node_announcement || !n->node_announcement_index)
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
		u8 *end = towire_reply_short_channel_ids_end(peer,
							     &rstate->chain_hash,
							     true);
		queue_peer_msg(peer, take(end));
		peer->scid_queries = tal_free(peer->scid_queries);
		peer->scid_query_idx = 0;
		peer->scid_query_nodes = tal_free(peer->scid_query_nodes);
		peer->scid_query_nodes_idx = 0;
	}

	return sent;
}

/* If we're supposed to be sending gossip, do so now. */
static bool maybe_queue_gossip(struct peer *peer)
{
	const u8 *next;

	if (peer->gossip_timer)
		return false;

#if DEVELOPER
	if (suppress_gossip)
		return false;
#endif

	next = next_broadcast(peer->daemon->rstate->broadcasts,
			      peer->gossip_timestamp_min,
			      peer->gossip_timestamp_max,
			      &peer->broadcast_index);

	if (next) {
		queue_peer_msg(peer, next);
		return true;
	}

	/* Gossip is drained.  Wait for next timer. */
	peer->gossip_timer
		= new_reltimer(&peer->daemon->timers, peer,
			       time_from_msec(peer->daemon->broadcast_interval),
			       wake_gossip_out, peer);
	return false;
}

static void handle_get_update(struct peer *peer, const u8 *msg)
{
	struct short_channel_id scid;
	struct chan *chan;
	const u8 *update;
	struct routing_state *rstate = peer->daemon->rstate;

	if (!fromwire_gossip_get_update(msg, &scid)) {
		status_trace("peer %s sent bad gossip_get_update %s",
			     type_to_string(tmpctx, struct pubkey, &peer->id),
			     tal_hex(tmpctx, msg));
		return;
	}

	chan = get_channel(rstate, &scid);
	if (!chan) {
		status_unusual("peer %s scid %s: unknown channel",
			       type_to_string(tmpctx, struct pubkey, &peer->id),
			       type_to_string(tmpctx, struct short_channel_id,
					      &scid));
		update = NULL;
	} else {
		struct local_update *l;

		/* We want the update that comes from our end. */
		if (pubkey_eq(&chan->nodes[0]->id, &peer->daemon->id))
			update = chan->half[0].channel_update;
		else if (pubkey_eq(&chan->nodes[1]->id, &peer->daemon->id))
			update = chan->half[1].channel_update;
		else {
			status_unusual("peer %s scid %s: not our channel?",
				       type_to_string(tmpctx, struct pubkey,
						      &peer->id),
				       type_to_string(tmpctx,
						      struct short_channel_id,
						      &scid));
			update = NULL;
			goto out;
		}

		/* We might have a pending update which overrides: always send
		 * that now, since this is used to populate errors which should
		 * contain the latest information. */
		l = find_local_update(peer->daemon, &scid);
		if (l)
			update = create_channel_update(tmpctx,
						       rstate,
						       chan, l->direction,
						       l->disable,
						       l->cltv_delta,
						       l->htlc_minimum_msat,
						       l->fee_base_msat,
						       l->fee_proportional_millionths);
	}

out:
	status_trace("peer %s schanid %s: %s update",
		     type_to_string(tmpctx, struct pubkey, &peer->id),
		     type_to_string(tmpctx, struct short_channel_id, &scid),
		     update ? "got" : "no");

	msg = towire_gossip_get_update_reply(NULL, update);
	daemon_conn_send(peer->remote, take(msg));
}

static u8 *create_channel_update(const tal_t *ctx,
				 struct routing_state *rstate,
				 const struct chan *chan,
				 int direction,
				 bool disable,
				 u16 cltv_expiry_delta,
				 u64 htlc_minimum_msat,
				 u32 fee_base_msat,
				 u32 fee_proportional_millionths)
{
	secp256k1_ecdsa_signature dummy_sig;
	u8 *update, *msg;
	u32 timestamp = time_now().ts.tv_sec;
	u16 flags;

	/* So valgrind doesn't complain */
	memset(&dummy_sig, 0, sizeof(dummy_sig));

	/* Don't send duplicate timestamps. */
	if (is_halfchan_defined(&chan->half[direction])
	    && timestamp == chan->half[direction].last_timestamp)
		timestamp++;

	flags = direction;
	if (disable)
		flags |= ROUTING_FLAGS_DISABLED;

	update = towire_channel_update(tmpctx, &dummy_sig,
				       &rstate->chain_hash,
				       &chan->scid,
				       timestamp,
				       flags, cltv_expiry_delta,
				       htlc_minimum_msat,
				       fee_base_msat,
				       fee_proportional_millionths);

	if (!wire_sync_write(HSM_FD,
			     towire_hsm_cupdate_sig_req(tmpctx, update))) {
		status_failed(STATUS_FAIL_HSM_IO, "Writing cupdate_sig_req: %s",
			      strerror(errno));
	}

	msg = wire_sync_read(tmpctx, HSM_FD);
	if (!msg || !fromwire_hsm_cupdate_sig_reply(ctx, msg, &update)) {
		status_failed(STATUS_FAIL_HSM_IO,
			      "Reading cupdate_sig_req: %s",
			      strerror(errno));
	}

	return update;
}

/* Return true if the only change would be the timestamp. */
static bool update_redundant(const struct half_chan *hc,
			   bool disable, u16 cltv_delta, u64 htlc_minimum_msat,
			   u32 fee_base_msat, u32 fee_proportional_millionths)
{
	if (!is_halfchan_defined(hc))
		return false;

	return !(hc->flags & ROUTING_FLAGS_DISABLED) == !disable
		&& hc->delay == cltv_delta
		&& hc->htlc_minimum_msat == htlc_minimum_msat
		&& hc->base_fee == fee_base_msat
		&& hc->proportional_fee == fee_proportional_millionths;
}

static struct local_update *find_local_update(struct daemon *daemon,
					      const struct short_channel_id *scid)
{
	struct local_update *i;

	list_for_each(&daemon->local_updates, i, list) {
		if (short_channel_id_eq(scid, &i->scid))
			return i;
	}
	return NULL;
}

/* Frees local_update */
static void apply_delayed_local_update(struct local_update *local_update)
{
	struct chan *chan;
	const struct half_chan *hc;
	u8 *cupdate, *err;

	/* Can theoretically happen if channel just closed. */
	chan = get_channel(local_update->daemon->rstate, &local_update->scid);
	if (!chan) {
		status_trace("Delayed local_channel_update for unknown %s",
			      type_to_string(tmpctx, struct short_channel_id,
					     &local_update->scid));
		tal_free(local_update);
		return;
	}

	/* Convenience variable */
	hc = &chan->half[local_update->direction];

	/* Avoid redundant updates on public channels: on non-public channels
	 * we'd need to consider pending updates, so don't bother. */
	if (is_chan_public(chan)
	    && update_redundant(hc,
				local_update->disable,
				local_update->cltv_delta,
				local_update->htlc_minimum_msat,
				local_update->fee_base_msat,
				local_update->fee_proportional_millionths)) {
		status_trace("Suppressing redundant channel update for %s:(%u) %s %"PRIu64"/%u vs %u/%u",
			     type_to_string(tmpctx, struct short_channel_id,
					    &local_update->scid),
			     local_update->direction,
			     is_halfchan_defined(hc)
			     ? (hc->flags & ROUTING_FLAGS_DISABLED ? "DISABLED" : "ACTIVE")
			     : "UNDEFINED",
			     hc->last_timestamp,
			     (u32)time_now().ts.tv_sec,
			     hc->flags,
			     local_update->disable);
		tal_free(local_update);
		return;
	}

	cupdate = create_channel_update(tmpctx, local_update->daemon->rstate,
					chan, local_update->direction,
					local_update->disable,
					local_update->cltv_delta,
					local_update->htlc_minimum_msat,
					local_update->fee_base_msat,
					local_update->fee_proportional_millionths);

	err = handle_channel_update(local_update->daemon->rstate, cupdate,
				    "apply_delayed_local_update");
	if (err)
		status_failed(STATUS_FAIL_INTERNAL_ERROR,
			      "Rejected local channel update %s: %s",
			      tal_hex(tmpctx, cupdate),
			      tal_hex(tmpctx, err));

	/* We always tell peer, even if it's not public yet */
	if (!is_chan_public(chan)) {
		struct peer *peer = find_peer(local_update->daemon,
					      &chan->nodes[!local_update
							   ->direction]->id);
		if (peer)
			queue_peer_msg(peer, take(cupdate));
	}

	status_trace("Channel update for %s(%u)%s",
		     type_to_string(tmpctx, struct short_channel_id,
				    &local_update->scid),
		     local_update->direction,
		     is_chan_public(chan) ? "" : " (private)");

	/* That channel_update might trigger our first channel_announcement */
	maybe_send_own_node_announce(local_update->daemon);
	tal_free(local_update);
}

static void destroy_local_update(struct local_update *local_update)
{
	list_del_from(&local_update->daemon->local_updates,
		      &local_update->list);
}

static void queue_local_update(struct daemon *daemon,
			       struct local_update *local_update)
{
	/* Free any old unapplied update. */
	tal_free(find_local_update(daemon, &local_update->scid));

	list_add_tail(&daemon->local_updates, &local_update->list);
	tal_add_destructor(local_update, destroy_local_update);

	/* Delay 1/4 a broadcast interval */
	new_reltimer(&daemon->timers, local_update,
		     time_from_msec(daemon->broadcast_interval/4),
		     apply_delayed_local_update, local_update);
}

static void handle_local_channel_update(struct peer *peer, const u8 *msg)
{
	struct chan *chan;
	struct local_update *local_update;
	const struct pubkey *my_id = &peer->daemon->rstate->local_id;

	local_update = tal(peer->daemon, struct local_update);
	local_update->daemon = peer->daemon;

	if (!fromwire_gossip_local_channel_update(msg,
						  &local_update->scid,
						  &local_update->disable,
						  &local_update->cltv_delta,
						  &local_update->htlc_minimum_msat,
						  &local_update->fee_base_msat,
						  &local_update->fee_proportional_millionths)) {
		status_broken("peer %s bad local_channel_update %s",
			      type_to_string(tmpctx, struct pubkey, &peer->id),
			      tal_hex(tmpctx, msg));
		tal_free(local_update);
		return;
	}

	/* Can theoretically happen if channel just closed. */
	chan = get_channel(peer->daemon->rstate, &local_update->scid);
	if (!chan) {
		status_trace("peer %s local_channel_update for unknown %s",
			      type_to_string(tmpctx, struct pubkey, &peer->id),
			      type_to_string(tmpctx, struct short_channel_id,
					     &local_update->scid));
		tal_free(local_update);
		return;
	}

	if (pubkey_eq(&chan->nodes[0]->id, my_id))
		local_update->direction = 0;
	else if (pubkey_eq(&chan->nodes[1]->id, my_id))
		local_update->direction = 1;
	else {
		status_broken("peer %s bad local_channel_update for non-local %s",
			      type_to_string(tmpctx, struct pubkey, &peer->id),
			      type_to_string(tmpctx, struct short_channel_id,
					     &local_update->scid));
		tal_free(local_update);
		return;
	}

	/* channeld has reconnected, remove local disable. */
	chan->local_disabled = false;
	queue_local_update(peer->daemon, local_update);
}

/**
 * owner_msg_in - Called by the `peer->remote` upon receiving a
 * message
 */
static struct io_plan *owner_msg_in(struct io_conn *conn,
				    struct daemon_conn *dc)
{
	struct peer *peer = dc->ctx;
	u8 *msg = dc->msg_in, *err;

	int type = fromwire_peektype(msg);
	if (type == WIRE_CHANNEL_ANNOUNCEMENT || type == WIRE_CHANNEL_UPDATE ||
	    type == WIRE_NODE_ANNOUNCEMENT) {
		err = handle_gossip_msg(peer->daemon, dc->msg_in, "subdaemon");
		if (err)
			queue_peer_msg(peer, take(err));
	} else if (type == WIRE_QUERY_SHORT_CHANNEL_IDS) {
		handle_query_short_channel_ids(peer, dc->msg_in);
	} else if (type == WIRE_REPLY_SHORT_CHANNEL_IDS_END) {
		handle_reply_short_channel_ids_end(peer, dc->msg_in);
	} else if (type == WIRE_GOSSIP_TIMESTAMP_FILTER) {
		handle_gossip_timestamp_filter(peer, dc->msg_in);
	} else if (type == WIRE_GOSSIP_GET_UPDATE) {
		handle_get_update(peer, dc->msg_in);
	} else if (type == WIRE_GOSSIP_LOCAL_ADD_CHANNEL) {
		gossip_store_add(peer->daemon->rstate->store, dc->msg_in);
		handle_local_add_channel(peer->daemon->rstate, dc->msg_in);
	} else if (type == WIRE_GOSSIP_LOCAL_CHANNEL_UPDATE) {
		handle_local_channel_update(peer, dc->msg_in);
	} else if (type == WIRE_QUERY_CHANNEL_RANGE) {
		handle_query_channel_range(peer, dc->msg_in);
	} else if (type == WIRE_REPLY_CHANNEL_RANGE) {
		handle_reply_channel_range(peer, dc->msg_in);
	} else if (type == WIRE_PING) {
		handle_ping(peer, dc->msg_in);
	} else if (type == WIRE_PONG) {
		handle_pong(peer, dc->msg_in);
	} else {
		status_broken("peer %s: send us unknown msg of type %s",
			      type_to_string(tmpctx, struct pubkey, &peer->id),
			      gossip_wire_type_name(type));
		return io_close(conn);
	}

	return daemon_conn_read_next(conn, dc);
}

static void free_peer(struct io_conn *conn, struct daemon_conn *dc)
{
	struct peer *peer = dc->ctx;

	tal_free(peer);
}

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

	if (socketpair(AF_LOCAL, SOCK_STREAM, 0, fds) != 0) {
		status_broken("Failed to create socketpair: %s",
			      strerror(errno));
		daemon_conn_send(&daemon->connectd,
				 take(towire_gossip_new_peer_reply(NULL, false)));
		goto done;
	}

	/* We might not have noticed old peer is dead; kill it now. */
	tal_free(find_peer(daemon, &peer->id));

	peer->daemon = daemon;
	peer->remote = tal(peer, struct daemon_conn);
	daemon_conn_init(peer, peer->remote, fds[0], owner_msg_in, free_peer);
	peer->remote->msg_queue_cleared_cb = nonlocal_dump_gossip;

	peer->scid_queries = NULL;
	peer->scid_query_idx = 0;
	peer->scid_query_nodes = NULL;
	peer->scid_query_nodes_idx = 0;
	peer->num_scid_queries_outstanding = 0;
	peer->query_channel_blocks = NULL;
	peer->num_pings_outstanding = 0;
	peer->gossip_timer = NULL;

	list_add_tail(&peer->daemon->peers, &peer->list);
	tal_add_destructor(peer, destroy_peer);

	/* BOLT #7:
	 *
	 *   - if the `gossip_queries` feature is negotiated:
	 *	- MUST NOT relay any gossip messages unless explicitly requested.
	 */
	if (peer->gossip_queries_feature) {
		peer->broadcast_index = UINT64_MAX;
		/* Nothing in this range */
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

	/* Start the gossip flowing. */
	wake_gossip_out(peer);

	setup_gossip_range(peer);

	/* Reply with success, and the new fd */
	daemon_conn_send(&daemon->connectd,
			 take(towire_gossip_new_peer_reply(NULL, true)));
	daemon_conn_send_fd(&daemon->connectd, fds[1]);

done:
	return daemon_conn_read_next(conn, &daemon->connectd);
}

/**
 * nonlocal_dump_gossip - catch the nonlocal peer up with the latest gossip.
 *
 * Registered as `msg_queue_cleared_cb` by the `peer->remote`.
 */
static bool nonlocal_dump_gossip(struct io_conn *conn, struct daemon_conn *dc)
{
	struct peer *peer = dc->ctx;

	/* Do we have scid query replies to send? */
	if (create_next_scid_reply(peer))
		return true;

	/* Otherwise queue any gossip we want to send */
	return maybe_queue_gossip(peer);
}

static struct io_plan *getroute_req(struct io_conn *conn, struct daemon *daemon,
				    u8 *msg)
{
	struct pubkey source, destination;
	u64 msatoshi;
	u32 final_cltv;
	u16 riskfactor;
	u8 *out;
	struct route_hop *hops;
	double fuzz;
	struct siphash_seed seed;

	fromwire_gossip_getroute_request(msg,
					 &source, &destination,
					 &msatoshi, &riskfactor, &final_cltv,
					 &fuzz, &seed);
	status_trace("Trying to find a route from %s to %s for %"PRIu64" msatoshi",
		     pubkey_to_hexstr(tmpctx, &source),
		     pubkey_to_hexstr(tmpctx, &destination), msatoshi);

	hops = get_route(tmpctx, daemon->rstate, &source, &destination,
			 msatoshi, 1, final_cltv,
			 fuzz, &seed);

	out = towire_gossip_getroute_reply(msg, hops);
	daemon_conn_send(&daemon->master, out);
	return daemon_conn_read_next(conn, &daemon->master);
}

static void append_half_channel(struct gossip_getchannels_entry **entries,
				const struct chan *chan,
				int idx)
{
	const struct half_chan *c = &chan->half[idx];
	struct gossip_getchannels_entry *e;
	size_t n;

	if (!is_halfchan_defined(c))
		return;

	n = tal_count(*entries);
	tal_resize(entries, n+1);
	e = &(*entries)[n];

	e->source = chan->nodes[idx]->id;
	e->destination = chan->nodes[!idx]->id;
	e->satoshis = chan->satoshis;
	e->flags = c->flags;
	e->local_disabled = chan->local_disabled;
	e->public = is_chan_public(chan);
	e->short_channel_id = chan->scid;
	e->last_update_timestamp = c->last_timestamp;
	e->base_fee_msat = c->base_fee;
	e->fee_per_millionth = c->proportional_fee;
	e->delay = c->delay;
}

static void append_channel(struct gossip_getchannels_entry **entries,
			   const struct chan *chan)
{
	append_half_channel(entries, chan, 0);
	append_half_channel(entries, chan, 1);
}

static struct io_plan *getchannels_req(struct io_conn *conn, struct daemon *daemon,
				    u8 *msg)
{
	u8 *out;
	struct gossip_getchannels_entry *entries;
	struct chan *chan;
	struct short_channel_id *scid;

	fromwire_gossip_getchannels_request(msg, msg, &scid);

	entries = tal_arr(tmpctx, struct gossip_getchannels_entry, 0);
	if (scid) {
		chan = get_channel(daemon->rstate, scid);
		if (chan)
			append_channel(&entries, chan);
	} else {
		u64 idx;

		for (chan = uintmap_first(&daemon->rstate->chanmap, &idx);
		     chan;
		     chan = uintmap_after(&daemon->rstate->chanmap, &idx)) {
			append_channel(&entries, chan);
		}
	}

	out = towire_gossip_getchannels_reply(NULL, entries);
	daemon_conn_send(&daemon->master, take(out));
	return daemon_conn_read_next(conn, &daemon->master);
}

static void append_node(const struct gossip_getnodes_entry ***nodes,
			const struct pubkey *nodeid,
			const u8 *gfeatures,
			/* If non-NULL, contains more information */
			const struct node *n)
{
	struct gossip_getnodes_entry *new;
	size_t num_nodes = tal_count(*nodes);

	new = tal(*nodes, struct gossip_getnodes_entry);
	new->nodeid = *nodeid;
	new->global_features = tal_dup_arr(*nodes, u8, gfeatures,
					   tal_count(gfeatures), 0);
	if (!n || n->last_timestamp < 0) {
		new->last_timestamp = -1;
		new->addresses = NULL;
	} else {
		new->last_timestamp = n->last_timestamp;
		new->addresses = n->addresses;
		new->alias = n->alias;
		memcpy(new->color, n->rgb_color, 3);
	}
	tal_resize(nodes, num_nodes + 1);
	(*nodes)[num_nodes] = new;
}

static struct io_plan *getnodes(struct io_conn *conn, struct daemon *daemon,
				const u8 *msg)
{
	u8 *out;
	struct node *n;
	const struct gossip_getnodes_entry **nodes;
	struct pubkey *id;

	fromwire_gossip_getnodes_request(tmpctx, msg, &id);

	nodes = tal_arr(tmpctx, const struct gossip_getnodes_entry *, 0);
	if (id) {
		n = get_node(daemon->rstate, id);
		if (n)
			append_node(&nodes, id, n->gfeatures, n);
	} else {
		struct node_map_iter i;
		n = node_map_first(daemon->rstate->nodes, &i);
		while (n != NULL) {
			append_node(&nodes, &n->id, n->gfeatures, n);
			n = node_map_next(daemon->rstate->nodes, &i);
		}
	}
	out = towire_gossip_getnodes_reply(NULL, nodes);
	daemon_conn_send(&daemon->master, take(out));
	return daemon_conn_read_next(conn, &daemon->master);
}

#if DEVELOPER
static struct io_plan *ping_req(struct io_conn *conn, struct daemon *daemon,
				const u8 *msg)
{
	struct pubkey id;
	u16 num_pong_bytes, len;
	struct peer *peer;
	u8 *ping;

	if (!fromwire_gossip_ping(msg, &id, &num_pong_bytes, &len))
		master_badmsg(WIRE_GOSSIP_PING, msg);

	peer = find_peer(daemon, &id);
	if (!peer) {
		daemon_conn_send(&daemon->master,
				 take(towire_gossip_ping_reply(NULL, false, 0)));
		goto out;
	}

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
		daemon_conn_send(&daemon->master,
				 take(towire_gossip_ping_reply(NULL, true, 0)));
	else
		peer->num_pings_outstanding++;

out:
	return daemon_conn_read_next(conn, &daemon->master);
}

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
	return daemon_conn_read_next(conn, &daemon->master);

fail:
	daemon_conn_send(&daemon->master,
			 take(towire_gossip_scids_reply(NULL, false, false)));
	goto out;
}

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
	return daemon_conn_read_next(conn, &daemon->master);
}

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
	peer->first_channel_range = first_blocknum;
	/* This uses 8 times as much as it needs to, but it's only for dev */
	peer->query_channel_blocks = tal_arrz(peer, u8, number_of_blocks);
	peer->query_channel_scids = tal_arr(peer, struct short_channel_id, 0);

out:
	return daemon_conn_read_next(conn, &daemon->master);

fail:
	daemon_conn_send(&daemon->master,
			 take(towire_gossip_query_channel_range_reply(NULL,
								      0, 0,
								      false,
								      NULL)));
	goto out;
}

static struct io_plan *dev_set_max_scids_encode_size(struct io_conn *conn,
						     struct daemon *daemon,
						     const u8 *msg)
{
	if (!fromwire_gossip_dev_set_max_scids_encode_size(msg,
							   &max_scids_encode_bytes))
		master_badmsg(WIRE_GOSSIP_DEV_SET_MAX_SCIDS_ENCODE_SIZE, msg);

	status_trace("Set max_scids_encode_bytes to %u", max_scids_encode_bytes);
	return daemon_conn_read_next(conn, &daemon->master);
}

static struct io_plan *dev_gossip_suppress(struct io_conn *conn,
					   struct daemon *daemon,
					   const u8 *msg)
{
	if (!fromwire_gossip_dev_suppress(msg))
		master_badmsg(WIRE_GOSSIP_DEV_SUPPRESS, msg);

	status_unusual("Suppressing all gossip");
	suppress_gossip = true;
	return daemon_conn_read_next(conn, &daemon->master);
}
#endif /* DEVELOPER */

static void gossip_send_keepalive_update(struct routing_state *rstate,
					 const struct chan *chan,
					 const struct half_chan *hc)
{
	u8 *update, *err;

	/* Generate a new update, with up to date timestamp */
	update = create_channel_update(tmpctx, rstate, chan,
				       hc->flags & ROUTING_FLAGS_DIRECTION,
				       false,
				       hc->delay,
				       hc->htlc_minimum_msat,
				       hc->base_fee,
				       hc->proportional_fee);

	status_trace("Sending keepalive channel_update for %s",
		     type_to_string(tmpctx, struct short_channel_id,
				    &chan->scid));

	err = handle_channel_update(rstate, update, "keepalive");
	if (err)
		status_failed(STATUS_FAIL_INTERNAL_ERROR,
			      "rejected keepalive channel_update: %s",
			      tal_hex(tmpctx, err));
}

static void gossip_refresh_network(struct daemon *daemon)
{
	u64 now = time_now().ts.tv_sec;
	/* Anything below this highwater mark could be pruned if not refreshed */
	s64 highwater = now - daemon->rstate->prune_timeout / 2;
	struct node *n;

	/* Schedule next run now */
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

			gossip_send_keepalive_update(daemon->rstate, n->chans[i],
						     hc);
		}
	}

	route_prune(daemon->rstate);
}

static void gossip_disable_outgoing_halfchan(struct daemon *daemon,
					     struct chan *chan)
{
	u8 direction;
	struct half_chan *hc;
	u16 flags;
	u32 timestamp;
	struct bitcoin_blkid chain_hash;
	secp256k1_ecdsa_signature sig;
	struct local_update *local_update;
	struct routing_state *rstate = daemon->rstate;

	direction = pubkey_eq(&chan->nodes[0]->id, &rstate->local_id)?0:1;
	assert(chan);
	hc = &chan->half[direction];

	if (!is_halfchan_defined(hc))
		return;

	status_trace("Disabling channel %s/%d, active %d -> %d",
		     type_to_string(tmpctx, struct short_channel_id, &chan->scid),
		     direction, is_halfchan_enabled(hc), 0);

	local_update = tal(daemon, struct local_update);
	local_update->daemon = daemon;
	local_update->direction = direction;

	if (!fromwire_channel_update(
		hc->channel_update, &sig, &chain_hash,
		&local_update->scid, &timestamp, &flags,
		&local_update->cltv_delta,
		&local_update->htlc_minimum_msat,
		&local_update->fee_base_msat,
		&local_update->fee_proportional_millionths)) {
		status_failed(
		    STATUS_FAIL_INTERNAL_ERROR,
		    "Unable to parse previously accepted channel_update");
	}

	local_update->disable = true;

	queue_local_update(daemon, local_update);
}

/**
 * Disable both directions of a local channel.
 *
 * Disables both directions of a local channel as a result of a close or lost
 * connection. A disabling `channel_update` will be queued for the outgoing
 * direction as well, but that will be a little delayed.  We can't do that for
 * the incoming direction, so we set local_disabled and the other endpoint
 * should take care of publicly disabling it with a `channel_update`.
 *
 * It is important to disable the incoming edge as well since we might otherwise
 * return that edge as a `contact_point` as part of an invoice.
 */
static void gossip_disable_local_channel(struct daemon *daemon,
					 struct chan *chan)
{
	struct routing_state *rstate = daemon->rstate;

	assert(pubkey_eq(&rstate->local_id, &chan->nodes[0]->id) ||
	       pubkey_eq(&rstate->local_id, &chan->nodes[1]->id));

	chan->local_disabled = true;
	gossip_disable_outgoing_halfchan(daemon, chan);
}

static void gossip_disable_local_channels(struct daemon *daemon)
{
	struct node *local_node =
	    get_node(daemon->rstate, &daemon->rstate->local_id);
	size_t i;

	/* We don't have a local_node, so we don't have any channels yet
	 * either */
	if (!local_node)
		return;

	for (i = 0; i < tal_count(local_node->chans); i++)
		gossip_disable_local_channel(daemon,
					     local_node->chans[i]);
}

/* Parse an incoming gossip init message and assign config variables
 * to the daemon.
 */
static struct io_plan *gossip_init(struct daemon_conn *master,
				   struct daemon *daemon,
				   const u8 *msg)
{
	struct bitcoin_blkid chain_hash;
	u32 update_channel_interval;

	if (!fromwire_gossipctl_init(
		daemon, msg, &daemon->broadcast_interval, &chain_hash,
		&daemon->id, &daemon->globalfeatures,
		daemon->rgb,
		daemon->alias, &update_channel_interval,
		&daemon->announcable)) {
		master_badmsg(WIRE_GOSSIPCTL_INIT, msg);
	}
	/* Prune time is twice update time */
	daemon->rstate = new_routing_state(daemon, &chain_hash, &daemon->id,
					   update_channel_interval * 2);

	/* Load stored gossip messages */
	gossip_store_load(daemon->rstate, daemon->rstate->store);

	/* Now disable all local channels, they can't be connected yet. */
	gossip_disable_local_channels(daemon);

	new_reltimer(&daemon->timers, daemon,
		     time_from_sec(daemon->rstate->prune_timeout/4),
		     gossip_refresh_network, daemon);

	return daemon_conn_read_next(master->conn, master);
}

static struct io_plan *resolve_channel_req(struct io_conn *conn,
					   struct daemon *daemon, const u8 *msg)
{
	struct short_channel_id scid;
	struct chan *chan;
	struct pubkey *keys;

	if (!fromwire_gossip_resolve_channel_request(msg, &scid))
		master_badmsg(WIRE_GOSSIP_RESOLVE_CHANNEL_REQUEST, msg);

	chan = get_channel(daemon->rstate, &scid);
	if (!chan) {
		status_trace("Failed to resolve channel %s",
			     type_to_string(tmpctx, struct short_channel_id, &scid));
		keys = NULL;
	} else {
		keys = tal_arr(msg, struct pubkey, 2);
		keys[0] = chan->nodes[0]->id;
		keys[1] = chan->nodes[1]->id;
		status_trace("Resolved channel %s %s<->%s",
			     type_to_string(tmpctx, struct short_channel_id, &scid),
			     type_to_string(tmpctx, struct pubkey, &keys[0]),
			     type_to_string(tmpctx, struct pubkey, &keys[1]));
	}
	daemon_conn_send(&daemon->master,
			 take(towire_gossip_resolve_channel_reply(NULL, keys)));
	return daemon_conn_read_next(conn, &daemon->master);
}

static void peer_disable_channels(struct daemon *daemon, struct node *node)
{
	struct chan *c;
	size_t i;
	for (i=0; i<tal_count(node->chans); i++) {
		c = node->chans[i];
		if (pubkey_eq(&other_node(node, c)->id,
			      &daemon->rstate->local_id))
			gossip_disable_local_channel(daemon, c);
	}
}

static struct io_plan *handle_txout_reply(struct io_conn *conn,
					  struct daemon *daemon, const u8 *msg)
{
	struct short_channel_id scid;
	u8 *outscript;
	u64 satoshis;

	if (!fromwire_gossip_get_txout_reply(msg, msg, &scid, &satoshis, &outscript))
		master_badmsg(WIRE_GOSSIP_GET_TXOUT_REPLY, msg);

	handle_pending_cannouncement(daemon->rstate, &scid, satoshis, outscript);
	maybe_send_own_node_announce(daemon);

	return daemon_conn_read_next(conn, &daemon->master);
}

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

	return daemon_conn_read_next(conn, &daemon->master);
}
static struct io_plan *
handle_mark_channel_unroutable(struct io_conn *conn,
			       struct daemon *daemon,
			       const u8 *msg)
{
	struct short_channel_id channel;

	if (!fromwire_gossip_mark_channel_unroutable(msg, &channel))
		master_badmsg(WIRE_GOSSIP_MARK_CHANNEL_UNROUTABLE, msg);

	mark_channel_unroutable(daemon->rstate, &channel);

	return daemon_conn_read_next(conn, &daemon->master);
}

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
		gossip_store_add_channel_delete(rstate->store, &scid);
	}

	return daemon_conn_read_next(conn, &daemon->master);
}

/**
 * Disable both directions of a channel due to an imminent close.
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
		gossip_disable_local_channel(daemon, chan);
	return daemon_conn_read_next(conn, &daemon->master);
}

static struct io_plan *recv_req(struct io_conn *conn, struct daemon_conn *master)
{
	struct daemon *daemon = container_of(master, struct daemon, master);
	enum gossip_wire_type t = fromwire_peektype(master->msg_in);

	switch (t) {
	case WIRE_GOSSIPCTL_INIT:
		return gossip_init(master, daemon, master->msg_in);

	case WIRE_GOSSIP_GETNODES_REQUEST:
		return getnodes(conn, daemon, daemon->master.msg_in);

	case WIRE_GOSSIP_GETROUTE_REQUEST:
		return getroute_req(conn, daemon, daemon->master.msg_in);

	case WIRE_GOSSIP_GETCHANNELS_REQUEST:
		return getchannels_req(conn, daemon, daemon->master.msg_in);

	case WIRE_GOSSIP_RESOLVE_CHANNEL_REQUEST:
		return resolve_channel_req(conn, daemon, daemon->master.msg_in);

	case WIRE_GOSSIP_GET_TXOUT_REPLY:
		return handle_txout_reply(conn, daemon, master->msg_in);

	case WIRE_GOSSIP_ROUTING_FAILURE:
		return handle_routing_failure(conn, daemon, master->msg_in);

	case WIRE_GOSSIP_MARK_CHANNEL_UNROUTABLE:
		return handle_mark_channel_unroutable(conn, daemon, master->msg_in);

	case WIRE_GOSSIP_OUTPOINT_SPENT:
		return handle_outpoint_spent(conn, daemon, master->msg_in);

	case WIRE_GOSSIP_LOCAL_CHANNEL_CLOSE:
		return handle_local_channel_close(conn, daemon, master->msg_in);

#if DEVELOPER
	case WIRE_GOSSIP_PING:
		return ping_req(conn, daemon, daemon->master.msg_in);

	case WIRE_GOSSIP_QUERY_SCIDS:
		return query_scids_req(conn, daemon, daemon->master.msg_in);

	case WIRE_GOSSIP_SEND_TIMESTAMP_FILTER:
		return send_timestamp_filter(conn, daemon, daemon->master.msg_in);

	case WIRE_GOSSIP_QUERY_CHANNEL_RANGE:
		return query_channel_range(conn, daemon, daemon->master.msg_in);

	case WIRE_GOSSIP_DEV_SET_MAX_SCIDS_ENCODE_SIZE:
		return dev_set_max_scids_encode_size(conn, daemon,
						     daemon->master.msg_in);
	case WIRE_GOSSIP_DEV_SUPPRESS:
		return dev_gossip_suppress(conn, daemon,
					   daemon->master.msg_in);
#else
	case WIRE_GOSSIP_PING:
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
	case WIRE_GOSSIP_RESOLVE_CHANNEL_REPLY:
	case WIRE_GOSSIP_GET_UPDATE:
	case WIRE_GOSSIP_GET_UPDATE_REPLY:
	case WIRE_GOSSIP_SEND_GOSSIP:
	case WIRE_GOSSIP_LOCAL_ADD_CHANNEL:
	case WIRE_GOSSIP_LOCAL_CHANNEL_UPDATE:
	case WIRE_GOSSIP_GET_TXOUT:
		break;
	}

	/* Master shouldn't give bad requests. */
	status_failed(STATUS_FAIL_MASTER_IO, "%i: %s",
		      t, tal_hex(tmpctx, master->msg_in));
}

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

	daemon_conn_send(&daemon->connectd,
			 take(towire_gossip_get_addrs_reply(NULL, addrs)));
	return daemon_conn_read_next(conn, &daemon->connectd);
}

static struct io_plan *connectd_req(struct io_conn *conn,
				    struct daemon_conn *connectd)
{
	struct daemon *daemon = container_of(connectd, struct daemon, connectd);
	enum connect_gossip_wire_type t = fromwire_peektype(connectd->msg_in);

	switch (t) {
	case WIRE_GOSSIP_NEW_PEER:
		return connectd_new_peer(conn, daemon, connectd->msg_in);

	case WIRE_GOSSIP_GET_ADDRS:
		return connectd_get_address(conn, daemon, connectd->msg_in);

	/* We send these, don't receive them. */
	case WIRE_GOSSIP_NEW_PEER_REPLY:
	case WIRE_GOSSIP_GET_ADDRS_REPLY:
		break;
	}

	status_broken("Bad msg from connectd: %s",
		      tal_hex(tmpctx, connectd->msg_in));
	return io_close(conn);
}

#ifndef TESTING
static void master_gone(struct io_conn *unused UNUSED, struct daemon_conn *dc UNUSED)
{
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
	list_head_init(&daemon->local_updates);
	timers_init(&daemon->timers, time_mono());
	daemon->broadcast_interval = 30000;
	daemon->last_announce_timestamp = 0;

	/* stdin == control */
	daemon_conn_init(daemon, &daemon->master, STDIN_FILENO, recv_req,
			 master_gone);
	status_setup_async(&daemon->master);
	hsm_setup(HSM_FD);
	daemon_conn_init(daemon, &daemon->connectd, CONNECTD_FD, connectd_req,
			 NULL);

	/* When conn closes, everything is freed. */
	tal_steal(daemon->master.conn, daemon);

	for (;;) {
		struct timer *expired = NULL;
		io_loop(&daemon->timers, &expired);

		if (!expired) {
			break;
		} else {
			timer_expired(daemon, expired);
		}
	}
	daemon_shutdown();
	return 0;
}
#endif
