#include <ccan/build_assert/build_assert.h>
#include <ccan/container_of/container_of.h>
#include <ccan/crypto/hkdf_sha256/hkdf_sha256.h>
#include <ccan/endian/endian.h>
#include <ccan/fdpass/fdpass.h>
#include <ccan/io/fdpass/fdpass.h>
#include <ccan/io/io.h>
#include <ccan/list/list.h>
#include <ccan/mem/mem.h>
#include <ccan/noerr/noerr.h>
#include <ccan/read_write_all/read_write_all.h>
#include <ccan/structeq/structeq.h>
#include <ccan/take/take.h>
#include <ccan/tal/str/str.h>
#include <ccan/timer/timer.h>
#include <common/cryptomsg.h>
#include <common/daemon_conn.h>
#include <common/io_debug.h>
#include <common/ping.h>
#include <common/status.h>
#include <common/subdaemon.h>
#include <common/timeout.h>
#include <common/type_to_string.h>
#include <common/utils.h>
#include <common/version.h>
#include <common/wire_error.h>
#include <common/wireaddr.h>
#include <errno.h>
#include <fcntl.h>
#include <gossipd/broadcast.h>
#include <gossipd/gen_gossip_wire.h>
#include <gossipd/handshake.h>
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
#include <unistd.h>
#include <wire/gen_peer_wire.h>
#include <wire/wire_io.h>
#include <wire/wire_sync.h>

#define HSM_FD 3

struct daemon {
	/* Who am I? */
	struct pubkey id;

	/* Peers we have directly or indirectly */
	struct list_head peers;

	/* Peers we are trying to reach */
	struct list_head reaching;

	/* Connection to main daemon. */
	struct daemon_conn master;

	/* Routing information */
	struct routing_state *rstate;

	/* Hacky list of known address hints. */
	struct list_head addrhints;

	struct timers timers;

	u32 broadcast_interval;

	/* Local and global features to offer to peers. */
	u8 *localfeatures, *globalfeatures;

	u8 alias[33];
	u8 rgb[3];
	struct wireaddr *wireaddrs;

	/* To make sure our node_announcement timestamps increase */
	u32 last_announce_timestamp;
};

/* Peers we're trying to reach. */
struct reaching {
	struct daemon *daemon;

	/* daemon->reaching */
	struct list_node list;

	/* The ID of the peer (not necessarily unique, in transit!) */
	struct pubkey id;

	/* Where I'm reaching to. */
	struct wireaddr addr;

	/* Did we succeed? */
	bool succeeded;
};

/* Things we need when we're talking direct to the peer. */
struct local_peer_state {
	/* Cryptostate */
	struct peer_crypto_state pcs;

	/* File descriptor corresponding to conn. */
	int fd;

	/* Our connection (and owner) */
	struct io_conn *conn;

	/* Waiting to send_peer_with_fds to master? */
	bool return_to_master;

	/* If we're exiting due to non-gossip msg, otherwise release */
	u8 *nongossip_msg;

	/* How many pongs are we expecting? */
	size_t num_pings_outstanding;

	/* Message queue for outgoing. */
	struct msg_queue peer_out;
};

struct peer {
	struct daemon *daemon;

	/* daemon->peers */
	struct list_node list;

	/* The ID of the peer (not necessarily unique, in transit!) */
	struct pubkey id;

	/* Where it's connected to. */
	struct wireaddr addr;

	/* Feature bitmaps. */
	u8 *gfeatures, *lfeatures;

	/* High water mark for the staggered broadcast */
	u64 broadcast_index;

	/* Is it time to continue the staggered broadcast? */
	bool gossip_sync;

	/* If we die, should we reach again? */
	bool reach_again;

	/* Only one of these is set: */
	struct local_peer_state *local;
	struct daemon_conn *remote;
};

struct addrhint {
	/* Off ld->addrhints */
	struct list_node list;

	struct pubkey id;
	/* FIXME: use array... */
	struct wireaddr addr;
};

/* FIXME: Reorder */
static struct io_plan *peer_start_gossip(struct io_conn *conn,
					 struct peer *peer);
static bool send_peer_with_fds(struct peer *peer, const u8 *msg);
static void wake_pkt_out(struct peer *peer);
static bool try_reach_peer(struct daemon *daemon, const struct pubkey *id);

static void destroy_peer(struct peer *peer)
{
	list_del_from(&peer->daemon->peers, &peer->list);
	if (peer->reach_again)
		try_reach_peer(peer->daemon, &peer->id);
}

static struct peer *find_peer(struct daemon *daemon, const struct pubkey *id)
{
	struct peer *peer;

	list_for_each(&daemon->peers, peer, list)
		if (pubkey_eq(&peer->id, id))
			return peer;
	return NULL;
}

static void destroy_addrhint(struct addrhint *a)
{
	list_del(&a->list);
}

static struct addrhint *find_addrhint(struct daemon *daemon,
				      const struct pubkey *id)
{
	struct addrhint *a;

	list_for_each(&daemon->addrhints, a, list) {
		if (pubkey_eq(&a->id, id))
			return a;
	}
	return NULL;
}

static struct local_peer_state *
new_local_peer_state(struct peer *peer, const struct crypto_state *cs)
{
	struct local_peer_state *lps = tal(peer, struct local_peer_state);

	init_peer_crypto_state(peer, &lps->pcs);
	lps->pcs.cs = *cs;
	lps->return_to_master = false;
	lps->num_pings_outstanding = 0;
	msg_queue_init(&lps->peer_out, peer);

	return lps;
}

static struct peer *new_peer(const tal_t *ctx,
			     struct daemon *daemon,
			     const struct pubkey *their_id,
			     const struct wireaddr *addr,
			     const struct crypto_state *cs)
{
	struct peer *peer = tal(ctx, struct peer);

	peer->id = *their_id;
	peer->addr = *addr;
	peer->daemon = daemon;
	peer->local = new_local_peer_state(peer, cs);
	peer->remote = NULL;
	peer->reach_again = false;
	peer->broadcast_index = 0;

	return peer;
}

static void peer_finalized(struct peer *peer)
{
	/* No longer tied to peer->conn's lifetime. */
	tal_steal(peer->daemon, peer);

	/* Now we can put this in the list of peers */
	list_add_tail(&peer->daemon->peers, &peer->list);
	tal_add_destructor(peer, destroy_peer);
}

static void destroy_reaching(struct reaching *reach)
{
	list_del_from(&reach->daemon->reaching, &reach->list);
}

static struct reaching *find_reaching(struct daemon *daemon,
				      const struct pubkey *id)
{
	struct reaching *r;

	list_for_each(&daemon->reaching, r, list)
		if (pubkey_eq(id, &r->id))
			return r;
	return NULL;
}

static void reached_peer(struct daemon *daemon, const struct pubkey *id,
			 struct io_conn *conn)
{
	struct reaching *r = find_reaching(daemon, id);

	if (!r)
		return;

	/* OK, we've reached the peer successfully, stop retrying. */

	/* Don't free conn with reach. */
	tal_steal(daemon, conn);
	/* Don't call connect_failed */
	io_set_finish(conn, NULL, NULL);

	tal_free(r);
}

static void peer_error(struct peer *peer, const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	status_trace("peer %s: %s",
		     type_to_string(trc, struct pubkey, &peer->id),
		     tal_vfmt(trc, fmt, ap));
	va_end(ap);

	/* Send error: we'll close after writing this. */
	va_start(ap, fmt);
	msg_enqueue(&peer->local->peer_out,
		    take(towire_errorfmtv(peer, NULL, fmt, ap)));
	va_end(ap);
}

static bool is_all_channel_error(const u8 *msg)
{
	struct channel_id channel_id;
	u8 *data;

	if (!fromwire_error(msg, msg, NULL, &channel_id, &data))
		return false;
	tal_free(data);
	return channel_id_is_all(&channel_id);
}

static struct io_plan *peer_close_after_error(struct io_conn *conn,
					      struct peer *peer)
{
	status_trace("%s: we sent them a fatal error, closing",
		     type_to_string(trc, struct pubkey, &peer->id));
	return io_close(conn);
}

static struct io_plan *peer_init_received(struct io_conn *conn,
					  struct peer *peer,
					  u8 *msg)
{
	if (!fromwire_init(peer, msg, NULL, &peer->gfeatures, &peer->lfeatures)){
		status_trace("peer %s bad fromwire_init '%s', closing",
			     type_to_string(trc, struct pubkey, &peer->id),
			     tal_hex(trc, msg));
		return io_close(conn);
	}

	reached_peer(peer->daemon, &peer->id, conn);

	/* This is a full peer now; we keep it around until its
	 * gossipfd closed (forget_peer) or reconnect. */
	peer_finalized(peer);

	/* We will not have anything queued, since we're not duplex. */
	msg = towire_gossip_peer_connected(peer, &peer->id, &peer->addr,
					   &peer->local->pcs.cs,
					   peer->broadcast_index,
					   peer->gfeatures, peer->lfeatures);
	if (!send_peer_with_fds(peer, msg))
		return io_close(conn);

	/* Start the gossip flowing. */
	/* FIXME: This is a bit wasteful in the common case where master
	 * simply hands it straight back to us and we restart the peer and
	 * restart gossip broadcast... */
	wake_pkt_out(peer);

	return io_close_taken_fd(conn);
}

static struct io_plan *read_init(struct io_conn *conn, struct peer *peer)
{
	/* BOLT #1:
	 *
	 * Each node MUST wait to receive `init` before sending any other
	 * messages.
	 */
	return peer_read_message(conn, &peer->local->pcs, peer_init_received);
}

/* This creates a temporary peer which is not in the list and is owner
 * by the connection; it's placed in the list and owned by daemon once
 * we have the features. */
static struct io_plan *init_new_peer(struct io_conn *conn,
				     const struct pubkey *their_id,
				     const struct wireaddr *addr,
				     const struct crypto_state *cs,
				     struct daemon *daemon)
{
	struct peer *peer = new_peer(conn, daemon, their_id, addr, cs);
	u8 *initmsg;

	peer->local->fd = io_conn_fd(conn);

	/* BOLT #1:
	 *
	 * Each node MUST send `init` as the first lightning message for any
	 * connection.
	 */
	initmsg = towire_init(peer,
			      daemon->globalfeatures, daemon->localfeatures);
	return peer_write_message(conn, &peer->local->pcs,
				  take(initmsg), read_init);
}

static struct io_plan *owner_msg_in(struct io_conn *conn,
				    struct daemon_conn *dc);
static struct io_plan *nonlocal_dump_gossip(struct io_conn *conn,
					    struct daemon_conn *dc);

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
	u8 *features = NULL;
	u8 *addresses = tal_arr(ctx, u8, 0);
	u8 *announcement;
	size_t i;
	if (!sig) {
		sig = tal(ctx, secp256k1_ecdsa_signature);
		memset(sig, 0, sizeof(*sig));
	}
	for (i = 0; i < tal_count(daemon->wireaddrs); i++)
		towire_wireaddr(&addresses, daemon->wireaddrs+i);

	announcement =
	    towire_node_announcement(ctx, sig, features, timestamp,
				     &daemon->id, daemon->rgb, daemon->alias,
				     addresses);
	return announcement;
}

static void send_node_announcement(struct daemon *daemon)
{
	tal_t *tmpctx = tal_tmpctx(daemon);
	u32 timestamp = time_now().ts.tv_sec;
	secp256k1_ecdsa_signature sig;
	u8 *msg, *nannounce;

	/* Timestamps must move forward, or announce will be ignored! */
	if (timestamp <= daemon->last_announce_timestamp)
		timestamp = daemon->last_announce_timestamp + 1;
	daemon->last_announce_timestamp = timestamp;

	nannounce = create_node_announcement(tmpctx, daemon, NULL, timestamp);

	if (!wire_sync_write(HSM_FD, take(towire_hsm_node_announcement_sig_req(tmpctx, nannounce))))
		status_failed(STATUS_FAIL_MASTER_IO, "Could not write to HSM: %s", strerror(errno));

	msg = wire_sync_read(tmpctx, HSM_FD);
	if (!fromwire_hsm_node_announcement_sig_reply(msg, NULL, &sig))
		status_failed(STATUS_FAIL_MASTER_IO, "HSM returned an invalid node_announcement sig");

	/* We got the signature for out provisional node_announcement back
	 * from the HSM, create the real announcement and forward it to
	 * gossipd so it can take care of forwarding it. */
	nannounce = create_node_announcement(tmpctx, daemon, &sig, timestamp);
	handle_node_announcement(daemon->rstate, take(nannounce));
	tal_free(tmpctx);
}

static void handle_gossip_msg(struct daemon *daemon, u8 *msg)
{
	struct routing_state *rstate = daemon->rstate;
	int t = fromwire_peektype(msg);

	switch(t) {
	case WIRE_CHANNEL_ANNOUNCEMENT: {
		const struct short_channel_id *scid;
		/* If it's OK, tells us the short_channel_id to lookup */
		scid = handle_channel_announcement(rstate, msg);
		if (scid)
			daemon_conn_send(&daemon->master,
					 take(towire_gossip_get_txout(daemon,
								      scid)));
		break;
	}

	case WIRE_NODE_ANNOUNCEMENT:
		handle_node_announcement(rstate, msg);
		break;

	case WIRE_CHANNEL_UPDATE:
		handle_channel_update(rstate, msg);
		break;
	}
}

static void handle_ping(struct peer *peer, u8 *ping)
{
	u8 *pong;

	if (!check_ping_make_pong(peer, ping, &pong)) {
		peer_error(peer, "Bad ping");
		return;
	}

	if (pong)
		msg_enqueue(&peer->local->peer_out, take(pong));
}

static void handle_pong(struct peer *peer, const u8 *pong)
{
	u8 *ignored;

	status_trace("Got pong!");
	if (!fromwire_pong(pong, pong, NULL, &ignored)) {
		peer_error(peer, "Bad pong");
		return;
	}

	if (!peer->local->num_pings_outstanding) {
		peer_error(peer, "Unexpected pong");
		return;
	}

	peer->local->num_pings_outstanding--;
	daemon_conn_send(&peer->daemon->master,
			 take(towire_gossip_ping_reply(pong, true,
						       tal_len(pong))));
}

/* If master asks us to release peer, we attach this destructor in case it
 * dies while we're waiting for it to finish IO */
static void fail_release(struct peer *peer)
{
	u8 *msg = towire_gossipctl_release_peer_replyfail(peer);
	daemon_conn_send(&peer->daemon->master, take(msg));
}

static struct io_plan *ready_for_master(struct io_conn *conn, struct peer *peer)
{
	u8 *msg;
	if (peer->local->nongossip_msg)
		msg = towire_gossip_peer_nongossip(peer, &peer->id,
						   &peer->addr,
						   &peer->local->pcs.cs,
						   peer->broadcast_index,
						   peer->gfeatures,
						   peer->lfeatures,
						   peer->local->nongossip_msg);
	else
		msg = towire_gossipctl_release_peer_reply(peer,
							  &peer->addr,
							  &peer->local->pcs.cs,
							  peer->broadcast_index,
							  peer->gfeatures,
							  peer->lfeatures);

	if (send_peer_with_fds(peer, take(msg))) {
		/* In case we set this earlier. */
		tal_del_destructor(peer, fail_release);
		return io_close_taken_fd(conn);
	} else
		return io_close(conn);
}

static struct io_plan *peer_msgin(struct io_conn *conn,
				  struct peer *peer, u8 *msg);

/* Wrapper around peer_read_message: don't read another if we want to
 * pass up to master */
static struct io_plan *peer_next_in(struct io_conn *conn, struct peer *peer)
{
	if (peer->local->return_to_master) {
		assert(!peer_in_started(conn, &peer->local->pcs));
		if (!peer_out_started(conn, &peer->local->pcs))
			return ready_for_master(conn, peer);
		return io_wait(conn, peer, peer_next_in, peer);
	}

	return peer_read_message(conn, &peer->local->pcs, peer_msgin);
}

static struct io_plan *peer_msgin(struct io_conn *conn,
				  struct peer *peer, u8 *msg)
{
	enum wire_type t = fromwire_peektype(msg);

	switch (t) {
	case WIRE_ERROR:
		status_trace("%s sent ERROR %s",
			     type_to_string(trc, struct pubkey, &peer->id),
			     sanitize_error(trc, msg, NULL));
		return io_close(conn);

	case WIRE_CHANNEL_ANNOUNCEMENT:
	case WIRE_NODE_ANNOUNCEMENT:
	case WIRE_CHANNEL_UPDATE:
		handle_gossip_msg(peer->daemon, msg);
		return peer_next_in(conn, peer);

	case WIRE_PING:
		handle_ping(peer, msg);
		return peer_next_in(conn, peer);

	case WIRE_PONG:
		handle_pong(peer, msg);
		return peer_next_in(conn, peer);

	case WIRE_OPEN_CHANNEL:
	case WIRE_CHANNEL_REESTABLISH:
	case WIRE_ACCEPT_CHANNEL:
	case WIRE_FUNDING_CREATED:
	case WIRE_FUNDING_SIGNED:
	case WIRE_FUNDING_LOCKED:
	case WIRE_ANNOUNCEMENT_SIGNATURES:
	case WIRE_UPDATE_FEE:
	case WIRE_SHUTDOWN:
	case WIRE_CLOSING_SIGNED:
	case WIRE_UPDATE_ADD_HTLC:
	case WIRE_UPDATE_FULFILL_HTLC:
	case WIRE_UPDATE_FAIL_HTLC:
	case WIRE_UPDATE_FAIL_MALFORMED_HTLC:
	case WIRE_COMMITMENT_SIGNED:
	case WIRE_REVOKE_AND_ACK:
	case WIRE_INIT:
		/* Not our place to handle this, so we punt */
		peer->local->return_to_master = true;
		peer->local->nongossip_msg = tal_steal(peer, msg);

		/* This will wait. */
		return peer_next_in(conn, peer);
	}

	/* BOLT #1:
	 *
	 * The type follows the _it's ok to be odd_ rule, so nodes MAY send
	 * odd-numbered types without ascertaining that the recipient
	 * understands it. */
	if (t & 1) {
		status_trace("Peer %s sent unknown packet %u, ignoring",
			     type_to_string(trc, struct pubkey, &peer->id), t);
	} else
		peer_error(peer, "Unknown packet %u", t);

	return peer_next_in(conn, peer);
}

/* Wake up the outgoing direction of the connection and write any
 * queued messages. Needed since the `io_wake` method signature does
 * not allow us to specify it as the callback for `new_reltimer`, but
 * it allows us to set an additional flag for the routing dump..
 */
static void wake_pkt_out(struct peer *peer)
{
	peer->gossip_sync = true;
	new_reltimer(&peer->daemon->timers, peer,
		     time_from_msec(peer->daemon->broadcast_interval),
		     wake_pkt_out, peer);

	if (peer->local)
		/* Notify the peer-write loop */
		msg_wake(&peer->local->peer_out);
	else
		/* Notify the daemon_conn-write loop */
		msg_wake(&peer->remote->out);
}

/* Mutual recursion. */
static struct io_plan *peer_pkt_out(struct io_conn *conn, struct peer *peer);

static struct io_plan *local_gossip_broadcast_done(struct io_conn *conn,
						   struct peer *peer)
{
	peer->broadcast_index++;
	return peer_pkt_out(conn, peer);
}

static struct io_plan *peer_pkt_out(struct io_conn *conn, struct peer *peer)
{
	/* First priority is queued packets, if any */
	const u8 *out = msg_dequeue(&peer->local->peer_out);
	if (out) {
		if (is_all_channel_error(out))
			return peer_write_message(conn, &peer->local->pcs,
						  take(out),
						  peer_close_after_error);
		return peer_write_message(conn, &peer->local->pcs, take(out),
					  peer_pkt_out);
	}

	/* Do we want to send this peer to the master daemon? */
	if (peer->local->return_to_master) {
		assert(!peer_out_started(conn, &peer->local->pcs));
		if (!peer_in_started(conn, &peer->local->pcs))
			return ready_for_master(conn, peer);
		return io_out_wait(conn, peer, peer_pkt_out, peer);
	}

	/* If we're supposed to be sending gossip, do so now. */
	if (peer->gossip_sync) {
		struct queued_message *next;

		next = next_broadcast_message(peer->daemon->rstate->broadcasts,
					      peer->broadcast_index);

		if (next)
			return peer_write_message(conn, &peer->local->pcs,
						  next->payload,
						  local_gossip_broadcast_done);

		/* Gossip is drained.  Wait for next timer. */
		peer->gossip_sync = false;
	}

	return msg_queue_wait(conn, &peer->local->peer_out, peer_pkt_out, peer);
}

/* Now we're a fully-fledged peer. */
static struct io_plan *peer_start_gossip(struct io_conn *conn, struct peer *peer)
{
	wake_pkt_out(peer);
	return io_duplex(conn,
			 peer_next_in(conn, peer),
			 peer_pkt_out(conn, peer));
}

static void handle_get_update(struct peer *peer, const u8 *msg)
{
	struct short_channel_id schanid;
	struct node *us;
	size_t i;
	const u8 *update;

	if (!fromwire_gossip_get_update(msg, NULL, &schanid)) {
		status_trace("peer %s sent bad gossip_get_update %s",
			     type_to_string(trc, struct pubkey, &peer->id),
			     tal_hex(trc, msg));
		return;
	}

	/* We want update than comes from our end. */
	us = node_map_get(peer->daemon->rstate->nodes, &peer->daemon->id.pubkey);
	if (!us) {
		status_trace("peer %s schanid %s but can't find ourselves",
			     type_to_string(trc, struct pubkey, &peer->id),
			     type_to_string(trc, struct short_channel_id,
					    &schanid));
		update = NULL;
		goto reply;
	}

	for (i = 0; i < tal_count(us->out); i++) {
		if (!short_channel_id_eq(&us->out[i]->short_channel_id,
					 &schanid))
			continue;

		update = us->out[i]->channel_update;
		status_trace("peer %s schanid %s: %s update",
			     type_to_string(trc, struct pubkey, &peer->id),
			     type_to_string(trc, struct short_channel_id,
					    &schanid),
			     update ? "got" : "no");
		goto reply;
	}
	update = NULL;

reply:
	msg = towire_gossip_get_update_reply(msg, update);
	daemon_conn_send(peer->remote, take(msg));
}

static void handle_local_add_channel(struct peer *peer, u8 *msg)
{
	struct routing_state *rstate = peer->daemon->rstate;
	struct short_channel_id scid;
	struct bitcoin_blkid chain_hash;
	struct pubkey remote_node_id;
	u16 flags, cltv_expiry_delta, direction;
	u32 fee_base_msat, fee_proportional_millionths;
	u64 htlc_minimum_msat;
	struct node_connection *c;

	if (!fromwire_gossip_local_add_channel(
		msg, NULL, &scid, &chain_hash, &remote_node_id, &flags,
		&cltv_expiry_delta, &htlc_minimum_msat, &fee_base_msat,
		&fee_proportional_millionths)) {
		status_trace("Unable to parse local_add_channel message: %s", tal_hex(msg, msg));
		return;
	}

	if (!structeq(&chain_hash, &rstate->chain_hash)) {
		status_trace("Received channel_announcement for unknown chain %s",
			     type_to_string(msg, struct bitcoin_blkid,
					    &chain_hash));
		return;
	}

	if (get_connection_by_scid(rstate, &scid, 0) || get_connection_by_scid(rstate, &scid, 1)) {
		status_trace("Attempted to local_add_channel a know channel");
		return;
	}

	direction = get_channel_direction(&rstate->local_id, &remote_node_id);
	c = half_add_connection(rstate, &rstate->local_id, &remote_node_id, &scid, direction);

	c->active = true;
	c->last_timestamp = 0;
	c->delay = cltv_expiry_delta;
	c->htlc_minimum_msat = htlc_minimum_msat;
	c->base_fee = fee_base_msat;
	c->proportional_fee = fee_proportional_millionths;
	status_trace("Added and updated local channel %s/%d", type_to_string(msg, struct short_channel_id, &scid), direction);
}

/**
 * owner_msg_in - Called by the `peer->owner_conn` upon receiving a
 * message
 */
static struct io_plan *owner_msg_in(struct io_conn *conn,
				    struct daemon_conn *dc)
{
	struct peer *peer = dc->ctx;
	u8 *msg = dc->msg_in;

	int type = fromwire_peektype(msg);
	if (type == WIRE_CHANNEL_ANNOUNCEMENT || type == WIRE_CHANNEL_UPDATE ||
	    type == WIRE_NODE_ANNOUNCEMENT) {
		handle_gossip_msg(peer->daemon, dc->msg_in);
	} else if (type == WIRE_GOSSIP_GET_UPDATE) {
		handle_get_update(peer, dc->msg_in);
	} else if (type == WIRE_GOSSIP_LOCAL_ADD_CHANNEL) {
		handle_local_add_channel(peer, dc->msg_in);
	} else {
		status_failed(
		    STATUS_FAIL_INTERNAL_ERROR,
		    "Gossip received unknown message of type %s from owner",
		    gossip_wire_type_name(type));
	}

	return daemon_conn_read_next(conn, dc);
}

static void forget_peer(struct io_conn *conn, struct daemon_conn *dc)
{
	struct peer *peer = dc->ctx;

	status_trace("Forgetting %s peer %s",
		     peer->local ? "local" : "remote",
		     type_to_string(trc, struct pubkey, &peer->id));

	/* Free peer. */
	tal_free(dc->ctx);
}

/* When a peer is to be owned by another daemon, we create a socket
 * pair to send/receive gossip from it */
static bool send_peer_with_fds(struct peer *peer, const u8 *msg)
{
	int fds[2];
	int peer_fd = peer->local->fd;

	if (socketpair(AF_LOCAL, SOCK_STREAM, 0, fds) != 0) {
		status_trace("Failed to create socketpair: %s",
			     strerror(errno));

		/* FIXME: Send error to peer? */
		/* Peer will be freed when caller closes conn. */
		return false;
	}

	/* Now we talk to socket to get to peer's owner daemon. */
	peer->local = tal_free(peer->local);
	peer->remote = tal(peer, struct daemon_conn);
	daemon_conn_init(peer, peer->remote, fds[0],
			 owner_msg_in, forget_peer);
	peer->remote->msg_queue_cleared_cb = nonlocal_dump_gossip;

	/* Peer stays around, even though caller will close conn. */
	tal_steal(peer->daemon, peer);

	daemon_conn_send(&peer->daemon->master, msg);
	daemon_conn_send_fd(&peer->daemon->master, peer_fd);
	daemon_conn_send_fd(&peer->daemon->master, fds[1]);

	return true;
}

static struct io_plan *nonlocal_gossip_broadcast_done(struct io_conn *conn,
						      struct daemon_conn *dc)
{
	struct peer *peer = dc->ctx;

	status_trace("%s", __func__);
	peer->broadcast_index++;
	return nonlocal_dump_gossip(conn, dc);
}

/**
 * nonlocal_dump_gossip - catch the nonlocal peer up with the latest gossip.
 *
 * Registered as `msg_queue_cleared_cb` by the `peer->owner_conn`.
 */
static struct io_plan *nonlocal_dump_gossip(struct io_conn *conn, struct daemon_conn *dc)
{
	struct queued_message *next;
	struct peer *peer = dc->ctx;


	/* Make sure we are not connected directly */
	assert(!peer->local);

	next = next_broadcast_message(peer->daemon->rstate->broadcasts,
				      peer->broadcast_index);

	if (!next) {
		return msg_queue_wait(conn, &peer->remote->out,
				      daemon_conn_write_next, dc);
	} else {
		u8 *msg = towire_gossip_send_gossip(conn,
						    peer->broadcast_index,
						    next->payload);
		return io_write_wire(conn, take(msg),
				     nonlocal_gossip_broadcast_done, dc);
	}
}

static struct io_plan *new_peer_got_fd(struct io_conn *conn, struct peer *peer)
{
	peer->local->conn = io_new_conn(conn, peer->local->fd,
					peer_start_gossip, peer);
	if (!peer->local->conn) {
		status_trace("Could not create connection for peer: %s",
			     strerror(errno));
		tal_free(peer);
	} else {
		/* If conn dies, we forget peer. */
		tal_steal(peer->local->conn, peer);
	}
	return daemon_conn_read_next(conn, &peer->daemon->master);
}

/* This lets us read the fds in before handling anything. */
struct returning_peer {
	struct daemon *daemon;
	struct pubkey id;
	struct crypto_state cs;
	u64 gossip_index;
	u8 *inner_msg;
	int peer_fd, gossip_fd;
};

static struct io_plan *handle_returning_peer(struct io_conn *conn,
					     struct returning_peer *rpeer)
{
	struct daemon *daemon = rpeer->daemon;
	struct peer *peer;

	peer = find_peer(daemon, &rpeer->id);
	if (!peer)
		status_failed(STATUS_FAIL_INTERNAL_ERROR,
			      "hand_back_peer unknown peer: %s",
			      type_to_string(trc, struct pubkey, &rpeer->id));

	/* We don't need the gossip_fd; we know what gossip it got
	 * from gossip_index */
	close(rpeer->gossip_fd);

	/* Possible if there's a reconnect: ignore handed back. */
	if (peer->local) {
		status_trace("hand_back_peer %s: reconnected, dropping handback",
			     type_to_string(trc, struct pubkey, &rpeer->id));

		close(rpeer->peer_fd);
		tal_free(rpeer);
		return daemon_conn_read_next(conn, &daemon->master);
	}

	status_trace("hand_back_peer %s: now local again",
		     type_to_string(trc, struct pubkey, &rpeer->id));

	/* Now we talk to peer directly again. */
	daemon_conn_clear(peer->remote);
	peer->remote = tal_free(peer->remote);

	peer->local = new_local_peer_state(peer, &rpeer->cs);
	peer->local->fd = rpeer->peer_fd;
	peer->broadcast_index = rpeer->gossip_index;

	/* If they told us to send a message, queue it now */
	if (tal_len(rpeer->inner_msg))
		msg_enqueue(&peer->local->peer_out, take(rpeer->inner_msg));
	tal_free(rpeer);

	return new_peer_got_fd(conn, peer);
}

static struct io_plan *read_returning_gossipfd(struct io_conn *conn,
					       struct returning_peer *rpeer)
{
	return io_recv_fd(conn, &rpeer->gossip_fd,
			  handle_returning_peer, rpeer);
}

static struct io_plan *hand_back_peer(struct io_conn *conn,
				      struct daemon *daemon,
				      const u8 *msg)
{
	struct returning_peer *rpeer = tal(daemon, struct returning_peer);

	rpeer->daemon = daemon;
	if (!fromwire_gossipctl_hand_back_peer(msg, msg, NULL,
					       &rpeer->id, &rpeer->cs,
					       &rpeer->gossip_index,
					       &rpeer->inner_msg))
		master_badmsg(WIRE_GOSSIPCTL_HAND_BACK_PEER, msg);

	return io_recv_fd(conn, &rpeer->peer_fd,
			  read_returning_gossipfd, rpeer);
}

static struct io_plan *release_peer(struct io_conn *conn, struct daemon *daemon,
				    const u8 *msg)
{
	struct pubkey id;
 	struct peer *peer;

	if (!fromwire_gossipctl_release_peer(msg, NULL, &id))
		master_badmsg(WIRE_GOSSIPCTL_RELEASE_PEER, msg);

	peer = find_peer(daemon, &id);
	if (!peer || !peer->local || peer->local->return_to_master) {
		/* This can happen with dying peers, or reconnect */
		status_trace("release_peer: peer %s %s",
			     type_to_string(trc, struct pubkey, &id),
			     !peer ? "not found"
			     : peer->local ? "already releasing"
			     : "not local");
		msg = towire_gossipctl_release_peer_replyfail(msg);
		daemon_conn_send(&daemon->master, take(msg));
	} else {
		peer->local->return_to_master = true;
		peer->local->nongossip_msg = NULL;

		/* Wake output, in case it's idle. */
		msg_wake(&peer->local->peer_out);
	}
	return daemon_conn_read_next(conn, &daemon->master);
}

static struct io_plan *getroute_req(struct io_conn *conn, struct daemon *daemon,
				    u8 *msg)
{
	tal_t *tmpctx = tal_tmpctx(msg);
	struct pubkey source, destination;
	u32 msatoshi, final_cltv;
	u16 riskfactor;
	u8 *out;
	struct route_hop *hops;

	fromwire_gossip_getroute_request(msg, NULL, &source, &destination,
					 &msatoshi, &riskfactor, &final_cltv);
	status_trace("Trying to find a route from %s to %s for %d msatoshi",
		     pubkey_to_hexstr(tmpctx, &source),
		     pubkey_to_hexstr(tmpctx, &destination), msatoshi);

	hops = get_route(tmpctx, daemon->rstate, &source, &destination,
			 msatoshi, 1, final_cltv);

	out = towire_gossip_getroute_reply(msg, hops);
	tal_free(tmpctx);
	daemon_conn_send(&daemon->master, out);
	return daemon_conn_read_next(conn, &daemon->master);
}

static struct io_plan *getchannels_req(struct io_conn *conn, struct daemon *daemon,
				    u8 *msg)
{
	tal_t *tmpctx = tal_tmpctx(daemon);
	u8 *out;
	size_t j, num_chans = 0;
	struct gossip_getchannels_entry *entries;
	struct node *n;
	struct node_map_iter i;

	entries = tal_arr(tmpctx, struct gossip_getchannels_entry, num_chans);
	n = node_map_first(daemon->rstate->nodes, &i);
	while (n != NULL) {
		for (j=0; j<tal_count(n->out); j++){
			tal_resize(&entries, num_chans + 1);
			entries[num_chans].source = n->out[j]->src->id;
			entries[num_chans].destination = n->out[j]->dst->id;
			entries[num_chans].active = n->out[j]->active;
			entries[num_chans].flags = n->out[j]->flags;
			entries[num_chans].public = (n->out[j]->channel_update != NULL);
			entries[num_chans].short_channel_id = n->out[j]->short_channel_id;
			entries[num_chans].last_update_timestamp = n->out[j]->last_timestamp;
			if (entries[num_chans].last_update_timestamp >= 0) {
				entries[num_chans].base_fee_msat = n->out[j]->base_fee;
				entries[num_chans].fee_per_millionth = n->out[j]->proportional_fee;
				entries[num_chans].delay = n->out[j]->delay;
			}
			num_chans++;
		}
		n = node_map_next(daemon->rstate->nodes, &i);
	}

	out = towire_gossip_getchannels_reply(daemon, entries);
	daemon_conn_send(&daemon->master, take(out));
	tal_free(tmpctx);
	return daemon_conn_read_next(conn, &daemon->master);
}

static struct io_plan *getnodes(struct io_conn *conn, struct daemon *daemon)
{
	tal_t *tmpctx = tal_tmpctx(daemon);
	u8 *out;
	struct node *n;
	struct node_map_iter i;
	struct gossip_getnodes_entry *nodes;
	size_t node_count = 0;

	nodes = tal_arr(tmpctx, struct gossip_getnodes_entry, node_count);
	n = node_map_first(daemon->rstate->nodes, &i);
	while (n != NULL) {
		tal_resize(&nodes, node_count + 1);
		nodes[node_count].nodeid = n->id;
		nodes[node_count].addresses = n->addresses;
		node_count++;
		n = node_map_next(daemon->rstate->nodes, &i);
	}
	out = towire_gossip_getnodes_reply(daemon, nodes);
	daemon_conn_send(&daemon->master, take(out));
	tal_free(tmpctx);
	return daemon_conn_read_next(conn, &daemon->master);
}

static struct io_plan *ping_req(struct io_conn *conn, struct daemon *daemon,
				const u8 *msg)
{
	struct pubkey id;
	u16 num_pong_bytes, len;
	struct peer *peer;
	u8 *ping;

	if (!fromwire_gossip_ping(msg, NULL, &id, &num_pong_bytes, &len))
		master_badmsg(WIRE_GOSSIP_PING, msg);

	peer = find_peer(daemon, &id);
	if (!peer) {
		daemon_conn_send(&daemon->master,
				 take(towire_gossip_ping_reply(peer, false, 0)));
		goto out;
	}

	ping = make_ping(peer, num_pong_bytes, len);
	if (tal_len(ping) > 65535)
		status_failed(STATUS_FAIL_MASTER_IO, "Oversize ping");

	msg_enqueue(&peer->local->peer_out, take(ping));
	status_trace("sending ping expecting %sresponse",
		     num_pong_bytes >= 65532 ? "no " : "");

	/* BOLT #1:
	 *
	 * if `num_pong_bytes` is less than 65532 it MUST respond by sending a
	 * `pong` message with `byteslen` equal to `num_pong_bytes`, otherwise
	 * it MUST ignore the `ping`.
	 */
	if (num_pong_bytes >= 65532)
		daemon_conn_send(&daemon->master,
				 take(towire_gossip_ping_reply(peer, true, 0)));
	else
		peer->local->num_pings_outstanding++;

out:
	return daemon_conn_read_next(conn, &daemon->master);
}

static int make_listen_fd(int domain, void *addr, socklen_t len)
{
	int fd = socket(domain, SOCK_STREAM, 0);
	if (fd < 0) {
		status_trace("Failed to create %u socket: %s",
			     domain, strerror(errno));
		return -1;
	}

	if (addr) {
		int on = 1;

		/* Re-use, please.. */
		if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on)))
			status_trace("Failed setting socket reuse: %s",
				     strerror(errno));

		if (bind(fd, addr, len) != 0) {
			status_trace("Failed to bind on %u socket: %s",
				    domain, strerror(errno));
			goto fail;
		}
	}

	if (listen(fd, 5) != 0) {
		status_trace("Failed to listen on %u socket: %s",
			     domain, strerror(errno));
		goto fail;
	}
	return fd;

fail:
	close_noerr(fd);
	return -1;
}

static struct io_plan *connection_in(struct io_conn *conn, struct daemon *daemon)
{
	struct wireaddr addr;
	struct sockaddr_storage s;
	socklen_t len = sizeof(s);

	if (getpeername(io_conn_fd(conn), (struct sockaddr *)&s, &len) != 0) {
		status_trace("Failed to get peername for incoming conn");
		return io_close(conn);
	}

	if (s.ss_family == AF_INET6) {
		struct sockaddr_in6 *s6 = (void *)&s;
		addr.type = ADDR_TYPE_IPV6;
		addr.addrlen = sizeof(s6->sin6_addr);
		BUILD_ASSERT(sizeof(s6->sin6_addr) <= sizeof(addr.addr));
		memcpy(addr.addr, &s6->sin6_addr, addr.addrlen);
		addr.port = ntohs(s6->sin6_port);
	} else if (s.ss_family == AF_INET) {
		struct sockaddr_in *s4 = (void *)&s;
		addr.type = ADDR_TYPE_IPV4;
		addr.addrlen = sizeof(s4->sin_addr);
		BUILD_ASSERT(sizeof(s4->sin_addr) <= sizeof(addr.addr));
		memcpy(addr.addr, &s4->sin_addr, addr.addrlen);
		addr.port = ntohs(s4->sin_port);
	} else  {
		status_trace("Unknown socket type %i for incoming conn",
			     s.ss_family);
		return io_close(conn);
	}

	/* FIXME: Timeout */
	return responder_handshake(conn, &daemon->id, &addr,
				   init_new_peer, daemon);
}

static void setup_listeners(struct daemon *daemon, u16 portnum)
{
	struct sockaddr_in addr;
	struct sockaddr_in6 addr6;
	socklen_t len;
	int fd1, fd2;

	if (!portnum) {
		status_trace("Zero portnum, not listening for incoming");
		return;
	}

	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = INADDR_ANY;
	addr.sin_port = htons(portnum);

	memset(&addr6, 0, sizeof(addr6));
	addr6.sin6_family = AF_INET6;
	addr6.sin6_addr = in6addr_any;
	addr6.sin6_port = htons(portnum);

	/* IPv6, since on Linux that (usually) binds to IPv4 too. */
	fd1 = make_listen_fd(AF_INET6, &addr6, sizeof(addr6));
	if (fd1 >= 0) {
		struct sockaddr_in6 in6;

		len = sizeof(in6);
		if (getsockname(fd1, (void *)&in6, &len) != 0) {
			status_trace("Failed get IPv6 sockname: %s",
				     strerror(errno));
			close_noerr(fd1);
			fd1 = -1;
		} else {
			addr.sin_port = in6.sin6_port;
			assert(portnum == ntohs(addr.sin_port));
			status_trace("Creating IPv6 listener on port %u",
				     portnum);
			io_new_listener(daemon, fd1, connection_in, daemon);
		}
	}

	/* Just in case, aim for the same port... */
	fd2 = make_listen_fd(AF_INET, &addr, sizeof(addr));
	if (fd2 >= 0) {
		len = sizeof(addr);
		if (getsockname(fd2, (void *)&addr, &len) != 0) {
			status_trace("Failed get IPv4 sockname: %s",
				     strerror(errno));
			close_noerr(fd2);
			fd2 = -1;
		} else {
			assert(portnum == ntohs(addr.sin_port));
			status_trace("Creating IPv4 listener on port %u",
				     portnum);
			io_new_listener(daemon, fd2, connection_in, daemon);
		}
	}

	if (fd1 < 0 && fd2 < 0)
		status_failed(STATUS_FAIL_INTERNAL_ERROR,
			      "Could not bind to a network address on port %u",
			      portnum);
}


/* Parse an incoming gossip init message and assign config variables
 * to the daemon.
 */
static struct io_plan *gossip_init(struct daemon_conn *master,
				   struct daemon *daemon,
				   const u8 *msg)
{
	struct bitcoin_blkid chain_hash;
	u16 port;

	if (!fromwire_gossipctl_init(daemon, msg, NULL,
				     &daemon->broadcast_interval,
				     &chain_hash, &daemon->id, &port,
				     &daemon->globalfeatures,
				     &daemon->localfeatures,
				     &daemon->wireaddrs,
				     daemon->rgb, daemon->alias)) {
		master_badmsg(WIRE_GOSSIPCTL_INIT, msg);
	}
	daemon->rstate = new_routing_state(daemon, &chain_hash, &daemon->id);

	setup_listeners(daemon, port);
	return daemon_conn_read_next(master->conn, master);
}

static struct io_plan *resolve_channel_req(struct io_conn *conn,
					   struct daemon *daemon, const u8 *msg)
{
	struct short_channel_id scid;
	struct node_connection *nc;
	struct pubkey *keys;

	if (!fromwire_gossip_resolve_channel_request(msg, NULL, &scid))
		master_badmsg(WIRE_GOSSIP_RESOLVE_CHANNEL_REQUEST, msg);

	nc = get_connection_by_scid(daemon->rstate, &scid, 0);
	if (!nc) {
		status_trace("Failed to resolve channel %s",
			     type_to_string(trc, struct short_channel_id, &scid));
		keys = NULL;
	} else {
		keys = tal_arr(msg, struct pubkey, 2);
		keys[0] = nc->src->id;
		keys[1] = nc->dst->id;
		status_trace("Resolved channel %s %s<->%s",
			     type_to_string(trc, struct short_channel_id, &scid),
			     type_to_string(trc, struct pubkey, &keys[0]),
			     type_to_string(trc, struct pubkey, &keys[1]));
	}
	daemon_conn_send(&daemon->master,
			 take(towire_gossip_resolve_channel_reply(msg, keys)));
	return daemon_conn_read_next(conn, &daemon->master);
}

static struct io_plan *handshake_out_success(struct io_conn *conn,
					     const struct pubkey *id,
					     const struct wireaddr *addr,
					     const struct crypto_state *cs,
					     struct reaching *reach)
{
	return init_new_peer(conn, id, addr, cs, reach->daemon);
}


static struct io_plan *connection_out(struct io_conn *conn,
				      struct reaching *reach)
{
	/* FIXME: Timeout */
	status_trace("Connected out for %s",
		     type_to_string(trc, struct pubkey, &reach->id));

	return initiator_handshake(conn, &reach->daemon->id, &reach->id,
				   &reach->addr,
				   handshake_out_success, reach);
}

static void try_connect(struct reaching *reach);

static void connect_failed(struct io_conn *conn, struct reaching *reach)
{
	status_trace("Failed connected out for %s, will try again",
		     type_to_string(trc, struct pubkey, &reach->id));

	/* FIXME: Configurable timer! */
	new_reltimer(&reach->daemon->timers, reach,
		     time_from_sec(5),
		     try_connect, reach);
}

static struct io_plan *conn_init(struct io_conn *conn, struct reaching *reach)
{
	struct addrinfo ai;
	struct sockaddr_in sin;
	struct sockaddr_in6 sin6;

	/* FIXME: make generic */
	ai.ai_flags = 0;
	ai.ai_socktype = SOCK_STREAM;
	ai.ai_protocol = 0;
	ai.ai_canonname = NULL;
	ai.ai_next = NULL;

	switch (reach->addr.type) {
	case ADDR_TYPE_IPV4:
		ai.ai_family = AF_INET;
		sin.sin_family = AF_INET;
		sin.sin_port = htons(reach->addr.port);
		memcpy(&sin.sin_addr, reach->addr.addr, sizeof(sin.sin_addr));
		ai.ai_addrlen = sizeof(sin);
		ai.ai_addr = (struct sockaddr *)&sin;
		break;
	case ADDR_TYPE_IPV6:
		ai.ai_family = AF_INET6;
		memset(&sin6, 0, sizeof(sin6));
		sin6.sin6_family = AF_INET6;
		sin6.sin6_port = htons(reach->addr.port);
		memcpy(&sin6.sin6_addr, reach->addr.addr, sizeof(sin6.sin6_addr));
		ai.ai_addrlen = sizeof(sin6);
		ai.ai_addr = (struct sockaddr *)&sin6;
		break;
	case ADDR_TYPE_PADDING:
		/* Shouldn't happen. */
		return io_close(conn);
	}

	io_set_finish(conn, connect_failed, reach);
	return io_connect(conn, &ai, connection_out, reach);
}

static void try_connect(struct reaching *reach)
{
	struct addrhint *a;
	int fd;

	/* Already succeeded somehow? */
	if (find_peer(reach->daemon, &reach->id)) {
		status_trace("Already reached %s, not retrying",
			     type_to_string(trc, struct pubkey, &reach->id));
		tal_free(reach);
		return;
	}

	a = find_addrhint(reach->daemon, &reach->id);
	if (!a) {
		/* FIXME: now try node table, dns lookups... */
		/* FIXME: add reach_failed message */
		status_trace("No address known for %s, giving up",
			     type_to_string(trc, struct pubkey, &reach->id));
		tal_free(reach);
		return;
	}

	/* Might not even be able to create eg. IPv6 sockets */
	switch (a->addr.type) {
	case ADDR_TYPE_IPV4:
		fd = socket(AF_INET, SOCK_STREAM, 0);
		break;
	case ADDR_TYPE_IPV6:
		fd = socket(AF_INET6, SOCK_STREAM, 0);
		break;
	default:
		fd = -1;
		errno = EPROTONOSUPPORT;
		break;
	}

	if (fd < 0) {
		status_trace("Can't open %i socket for %s (%s), giving up",
			     a->addr.type,
			     type_to_string(trc, struct pubkey, &reach->id),
			     strerror(errno));
		tal_free(reach);
		return;
	}

	reach->addr = a->addr;
	io_new_conn(reach, fd, conn_init, reach);
}

/* Returns true if we're already connected. */
static bool try_reach_peer(struct daemon *daemon, const struct pubkey *id)
{
	struct reaching *reach;
	struct peer *peer;

	if (find_reaching(daemon, id)) {
		/* FIXME: Perhaps kick timer in this case? */
		status_trace("try_reach_peer: already trying to reach %s",
			     type_to_string(trc, struct pubkey, id));
		return false;
	}

	/* Master might find out before we do that a peer is dead; if we
	 * seem to be connected just mark it for reconnect. */
	peer = find_peer(daemon, id);
	if (peer) {
		status_trace("reach_peer: have %s, will retry if it dies",
			     type_to_string(trc, struct pubkey, id));
		peer->reach_again = true;
		return true;
	}

	reach = tal(daemon, struct reaching);
	reach->succeeded = false;
	reach->daemon = daemon;
	reach->id = *id;
	list_add_tail(&daemon->reaching, &reach->list);
	tal_add_destructor(reach, destroy_reaching);

	try_connect(reach);
	return false;
}

/* This catches all kinds of failures, like network errors. */
static struct io_plan *reach_peer(struct io_conn *conn,
				  struct daemon *daemon, const u8 *msg)
{
	struct pubkey id;

	if (!fromwire_gossipctl_reach_peer(msg, NULL, &id))
		master_badmsg(WIRE_GOSSIPCTL_REACH_PEER, msg);

	/* Master can't check this itself, because that's racy. */
	if (try_reach_peer(daemon, &id)) {
		daemon_conn_send(&daemon->master,
				 take(towire_gossip_peer_already_connected(conn,
									  &id)));
	}

	return daemon_conn_read_next(conn, &daemon->master);
}

static struct io_plan *addr_hint(struct io_conn *conn,
				 struct daemon *daemon, const u8 *msg)
{
	struct addrhint *a = tal(daemon, struct addrhint);

	if (!fromwire_gossipctl_peer_addrhint(msg, NULL, &a->id, &a->addr))
		master_badmsg(WIRE_GOSSIPCTL_PEER_ADDRHINT, msg);

	/* Replace any old one. */
	tal_free(find_addrhint(daemon, &a->id));

	list_add_tail(&daemon->addrhints, &a->list);
	tal_add_destructor(a, destroy_addrhint);

	return daemon_conn_read_next(conn, &daemon->master);
}

static struct io_plan *get_peers(struct io_conn *conn,
				 struct daemon *daemon, const u8 *msg)
{
	struct peer *peer;
	size_t n = 0;
	struct pubkey *id = tal_arr(conn, struct pubkey, n);
	struct wireaddr *wireaddr = tal_arr(conn, struct wireaddr, n);

	if (!fromwire_gossip_getpeers_request(msg, NULL))
		master_badmsg(WIRE_GOSSIPCTL_PEER_ADDRHINT, msg);

	list_for_each(&daemon->peers, peer, list) {
		tal_resize(&id, n+1);
		tal_resize(&wireaddr, n+1);

		id[n] = peer->id;
		wireaddr[n] = peer->addr;
		n++;
	}

	daemon_conn_send(&daemon->master,
			 take(towire_gossip_getpeers_reply(conn, id, wireaddr)));
	return daemon_conn_read_next(conn, &daemon->master);
}

static struct io_plan *handle_txout_reply(struct io_conn *conn,
					  struct daemon *daemon, const u8 *msg)
{
	struct short_channel_id scid;
	u8 *outscript;

	if (!fromwire_gossip_get_txout_reply(msg, msg, NULL, &scid, &outscript))
		master_badmsg(WIRE_GOSSIP_GET_TXOUT_REPLY, msg);

	if (handle_pending_cannouncement(daemon->rstate, &scid, outscript))
		send_node_announcement(daemon);

	return daemon_conn_read_next(conn, &daemon->master);
}

static struct io_plan *recv_req(struct io_conn *conn, struct daemon_conn *master)
{
	struct daemon *daemon = container_of(master, struct daemon, master);
	enum gossip_wire_type t = fromwire_peektype(master->msg_in);

	status_trace("req: type %s len %zu",
		     gossip_wire_type_name(t), tal_count(master->msg_in));

	switch (t) {
	case WIRE_GOSSIPCTL_INIT:
		return gossip_init(master, daemon, master->msg_in);

	case WIRE_GOSSIPCTL_RELEASE_PEER:
		return release_peer(conn, daemon, master->msg_in);

	case WIRE_GOSSIP_GETNODES_REQUEST:
		return getnodes(conn, daemon);

	case WIRE_GOSSIP_GETROUTE_REQUEST:
		return getroute_req(conn, daemon, daemon->master.msg_in);

	case WIRE_GOSSIP_GETCHANNELS_REQUEST:
		return getchannels_req(conn, daemon, daemon->master.msg_in);

	case WIRE_GOSSIP_PING:
		return ping_req(conn, daemon, daemon->master.msg_in);

	case WIRE_GOSSIP_RESOLVE_CHANNEL_REQUEST:
		return resolve_channel_req(conn, daemon, daemon->master.msg_in);

	case WIRE_GOSSIPCTL_HAND_BACK_PEER:
		return hand_back_peer(conn, daemon, master->msg_in);

	case WIRE_GOSSIPCTL_REACH_PEER:
		return reach_peer(conn, daemon, master->msg_in);

	case WIRE_GOSSIPCTL_PEER_ADDRHINT:
		return addr_hint(conn, daemon, master->msg_in);

	case WIRE_GOSSIP_GETPEERS_REQUEST:
		return get_peers(conn, daemon, master->msg_in);

	case WIRE_GOSSIP_GET_TXOUT_REPLY:
		return handle_txout_reply(conn, daemon, master->msg_in);

	/* We send these, we don't receive them */
	case WIRE_GOSSIPCTL_RELEASE_PEER_REPLY:
	case WIRE_GOSSIPCTL_RELEASE_PEER_REPLYFAIL:
	case WIRE_GOSSIP_GETNODES_REPLY:
	case WIRE_GOSSIP_GETROUTE_REPLY:
	case WIRE_GOSSIP_GETCHANNELS_REPLY:
	case WIRE_GOSSIP_GETPEERS_REPLY:
	case WIRE_GOSSIP_PING_REPLY:
	case WIRE_GOSSIP_RESOLVE_CHANNEL_REPLY:
	case WIRE_GOSSIP_PEER_CONNECTED:
	case WIRE_GOSSIP_PEER_ALREADY_CONNECTED:
	case WIRE_GOSSIP_PEER_NONGOSSIP:
	case WIRE_GOSSIP_GET_UPDATE:
	case WIRE_GOSSIP_GET_UPDATE_REPLY:
	case WIRE_GOSSIP_SEND_GOSSIP:
	case WIRE_GOSSIP_LOCAL_ADD_CHANNEL:
	case WIRE_GOSSIP_GET_TXOUT:
		break;
	}

	/* Master shouldn't give bad requests. */
	status_failed(STATUS_FAIL_MASTER_IO, "%i: %s",
		      t, tal_hex(trc, master->msg_in));
}

#ifndef TESTING
static void master_gone(struct io_conn *unused, struct daemon_conn *dc)
{
	/* Can't tell master, it's gone. */
	exit(2);
}

int main(int argc, char *argv[])
{
	struct daemon *daemon;

	subdaemon_setup(argc, argv);
	io_poll_override(debug_poll);

	daemon = tal(NULL, struct daemon);
	list_head_init(&daemon->peers);
	list_head_init(&daemon->reaching);
	list_head_init(&daemon->addrhints);
	timers_init(&daemon->timers, time_mono());
	daemon->broadcast_interval = 30000;
	daemon->last_announce_timestamp = 0;

	/* stdin == control */
	daemon_conn_init(daemon, &daemon->master, STDIN_FILENO, recv_req,
			 master_gone);
	status_setup_async(&daemon->master);
	hsm_setup(HSM_FD);

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
	return 0;
}
#endif
