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
#include <ccan/structeq/structeq.h>
#include <ccan/take/take.h>
#include <ccan/tal/str/str.h>
#include <ccan/timer/timer.h>
#include <common/bech32.h>
#include <common/bech32_util.h>
#include <common/cryptomsg.h>
#include <common/daemon_conn.h>
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
#include <errno.h>
#include <fcntl.h>
#include <gossipd/broadcast.h>
#include <gossipd/gen_gossip_wire.h>
#include <gossipd/gossip.h>
#include <gossipd/handshake.h>
#include <gossipd/netaddress.h>
#include <gossipd/routing.h>
#include <gossipd/tor.h>
#include <gossipd/tor_autoservice.h>
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

#define GOSSIP_MAX_REACH_ATTEMPTS 10

#define HSM_FD 3

#define INITIAL_WAIT_SECONDS	1
#define MAX_WAIT_SECONDS	300

/* We put everything in this struct (redundantly) to pass it to timer cb */
struct important_peerid {
	struct daemon *daemon;

	struct pubkey id;

	/* How long to wait after failed connect */
	unsigned int wait_seconds;

	/* The timer we're using to reconnect */
	struct oneshot *reconnect_timer;
};

/* We keep a set of peer ids we're always trying to reach. */
static const struct pubkey *
important_peerid_keyof(const struct important_peerid *imp)
{
	return &imp->id;
}

static bool important_peerid_eq(const struct important_peerid *imp,
				const struct pubkey *key)
{
	return pubkey_eq(&imp->id, key);
}

static size_t important_peerid_hash(const struct pubkey *id)
{
	return siphash24(siphash_seed(), id, sizeof(*id));
}

HTABLE_DEFINE_TYPE(struct important_peerid,
		   important_peerid_keyof,
		   important_peerid_hash,
		   important_peerid_eq,
		   important_peerid_map);

struct daemon {
	/* Who am I? */
	struct pubkey id;

	/* Peers we have directly or indirectly: id is unique */
	struct list_head peers;

	/* Peers reconnecting now (waiting for current peer to die). */
	struct list_head reconnecting;

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

	/* Important peers */
	struct important_peerid_map important_peerids;

	/* Local and global features to offer to peers. */
	u8 *localfeatures, *globalfeatures;

	u8 alias[33];
	u8 rgb[3];

	/* Addresses master told us to use */
	struct wireaddr_internal *proposed_wireaddr;
	enum addr_listen_announce *proposed_listen_announce;

	/* What we actually announce. */
	struct wireaddr *announcable;

	/* To make sure our node_announcement timestamps increase */
	u32 last_announce_timestamp;

	/* Automatically reconnect. */
	bool reconnect;

	struct addrinfo *proxyaddr;
	bool use_proxy_always;

	bool tor_autoservice;
	struct wireaddr *tor_serviceaddr;
	char *tor_password;

};

/* Peers we're trying to reach. */
struct reaching {
	struct daemon *daemon;

	/* daemon->reaching */
	struct list_node list;

	/* The ID of the peer (not necessarily unique, in transit!) */
	struct pubkey id;

	/* FIXME: Support multiple address. */
	struct wireaddr_internal addr;

	/* Whether connect command is waiting for the result. */
	bool master_needs_response;

	/* How far did we get? */
	const char *connstate;
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
	struct wireaddr_internal addr;

	/* Feature bitmaps. */
	u8 *gfeatures, *lfeatures;

	/* High water mark for the staggered broadcast */
	u64 broadcast_index;

	/* Is it time to continue the staggered broadcast? */
	bool gossip_sync;

	/* Only one of these is set: */
	struct local_peer_state *local;
	struct daemon_conn *remote;
};

struct addrhint {
	/* Off ld->addrhints */
	struct list_node list;

	struct pubkey id;
	/* FIXME: use array... */
	struct wireaddr_internal addr;
};

/* FIXME: Reorder */
static struct io_plan *peer_start_gossip(struct io_conn *conn,
					 struct peer *peer);
static bool send_peer_with_fds(struct peer *peer, const u8 *msg);
static void wake_pkt_out(struct peer *peer);
static void retry_important(struct important_peerid *imp);

static void destroy_peer(struct peer *peer)
{
	struct important_peerid *imp;

	list_del_from(&peer->daemon->peers, &peer->list);
	imp = important_peerid_map_get(&peer->daemon->important_peerids,
				       &peer->id);
	if (imp) {
		imp->wait_seconds = INITIAL_WAIT_SECONDS;
		retry_important(imp);
	}
}

static struct peer *find_peer(struct daemon *daemon, const struct pubkey *id)
{
	struct peer *peer;

	list_for_each(&daemon->peers, peer, list)
		if (pubkey_eq(&peer->id, id))
			return peer;
	return NULL;
}

static struct peer *find_reconnecting_peer(struct daemon *daemon,
					   const struct pubkey *id)
{
	struct peer *peer;

	list_for_each(&daemon->reconnecting, peer, list)
		if (pubkey_eq(&peer->id, id))
			return peer;
	return NULL;
}

static void destroy_reconnecting_peer(struct peer *peer)
{
	list_del_from(&peer->daemon->reconnecting, &peer->list);
	/* This is safe even if we're being destroyed because of peer->conn,
	 * since tal_free protects against loops. */
	io_close(peer->local->conn);
}

static void add_reconnecting_peer(struct daemon *daemon, struct peer *peer)
{
	/* Drop any previous connecting peer */
	tal_free(find_reconnecting_peer(peer->daemon, &peer->id));

	list_add_tail(&daemon->reconnecting, &peer->list);
	tal_add_destructor(peer, destroy_reconnecting_peer);
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
			     const struct wireaddr_internal *addr,
			     const struct crypto_state *cs)
{
	struct peer *peer = tal(ctx, struct peer);

	peer->id = *their_id;
	peer->addr = *addr;
	peer->daemon = daemon;
	peer->local = new_local_peer_state(peer, cs);
	peer->remote = NULL;

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

static void reached_peer(struct peer *peer, struct io_conn *conn)
{
	/* OK, we've reached the peer successfully, tell everyone. */
	struct reaching *r = find_reaching(peer->daemon, &peer->id);
	u8 *msg;

	if (!r)
		return;

	/* Don't call connect_failed */
	io_set_finish(conn, NULL, NULL);

	/* Don't free conn with reach */
	tal_steal(peer->daemon, conn);

	/* Tell any connect command what happened. */
	if (r->master_needs_response) {
		msg = towire_gossipctl_connect_to_peer_result(NULL, &r->id,
							      true, "");
		daemon_conn_send(&peer->daemon->master, take(msg));
	}

	tal_free(r);
}

static void queue_peer_msg(struct peer *peer, const u8 *msg TAKES)
{
	if (peer->local) {
		msg_enqueue(&peer->local->peer_out, msg);
	} else if (peer->remote) {
		const u8 *send = towire_gossip_send_gossip(NULL, msg);
		if (taken(msg))
			tal_free(msg);
		daemon_conn_send(peer->remote, take(send));
	}
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

static bool is_all_channel_error(const u8 *msg)
{
	struct channel_id channel_id;
	u8 *data;

	if (!fromwire_error(msg, msg, &channel_id, &data))
		return false;
	tal_free(data);
	return channel_id_is_all(&channel_id);
}

static struct io_plan *peer_close_after_error(struct io_conn *conn,
					      struct peer *peer)
{
	status_trace("%s: we sent them a fatal error, closing",
		     type_to_string(tmpctx, struct pubkey, &peer->id));
	return io_close(conn);
}

/* Mutual recursion */
static struct io_plan *peer_connected(struct io_conn *conn, struct peer *peer);
static struct io_plan *retry_peer_connected(struct io_conn *conn,
					    struct peer *peer)
{
	status_trace("peer %s: processing now old peer gone",
		     type_to_string(tmpctx, struct pubkey, &peer->id));

	/* Clean up reconnecting state, try again */
	list_del_from(&peer->daemon->reconnecting, &peer->list);
	tal_del_destructor(peer, destroy_reconnecting_peer);

	return peer_connected(conn, peer);
}

static struct io_plan *peer_connected(struct io_conn *conn, struct peer *peer)
{
	struct peer *old_peer;
	u8 *msg;

	/* Now, is this a reconnect? */
	old_peer = find_peer(peer->daemon, &peer->id);
	if (old_peer) {
		status_trace("peer %s: reconnect for %s",
			     type_to_string(tmpctx, struct pubkey, &peer->id),
			     old_peer->local ? "local peer" : "active peer");
		if (!old_peer->local) {
			/* If not already closed, close it: it will
			 * fail, and master will peer_died to us */
			if (old_peer->remote) {
				daemon_conn_clear(old_peer->remote);
				old_peer->remote = tal_free(old_peer->remote);
			}
			add_reconnecting_peer(peer->daemon, peer);
			return io_wait(conn, peer, retry_peer_connected, peer);
		}
		/* Local peers can just be discarded when they reconnect */
		tal_free(old_peer);
	}

	reached_peer(peer, conn);

	/* BOLT #7:
	 *
	 * Upon receiving an `init` message with the `initial_routing_sync`
	 * flag set the node sends `channel_announcement`s, `channel_update`s
	 * and `node_announcement`s for all known channels and nodes as if
	 * they were just received.
	 */
	if (feature_offered(peer->lfeatures, LOCAL_INITIAL_ROUTING_SYNC))
		peer->broadcast_index = 0;
	else
		peer->broadcast_index
			= peer->daemon->rstate->broadcasts->next_index;

	/* This is a full peer now; we keep it around until master says
	 * it's dead. */
	peer_finalized(peer);

	/* We will not have anything queued, since we're not duplex. */
	msg = towire_gossip_peer_connected(peer, &peer->id, &peer->addr,
					   &peer->local->pcs.cs,
					   peer->gfeatures, peer->lfeatures);
	if (!send_peer_with_fds(peer, msg))
		return io_close(conn);

	/* Start the gossip flowing. */
	wake_pkt_out(peer);

	return io_close_taken_fd(conn);
}

static struct io_plan *peer_init_received(struct io_conn *conn,
					  struct peer *peer,
					  u8 *msg)
{
	if (!fromwire_init(peer, msg, &peer->gfeatures, &peer->lfeatures)) {
		status_trace("peer %s bad fromwire_init '%s', closing",
			     type_to_string(tmpctx, struct pubkey, &peer->id),
			     tal_hex(tmpctx, msg));
		return io_close(conn);
	}

	return peer_connected(conn, peer);
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
				     const struct wireaddr_internal *addr,
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
	initmsg = towire_init(NULL,
			      daemon->globalfeatures, daemon->localfeatures);
	return peer_write_message(conn, &peer->local->pcs,
				  take(initmsg), read_init);
}

static struct io_plan *owner_msg_in(struct io_conn *conn,
				    struct daemon_conn *dc);
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
	u8 *features = NULL;
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
	    towire_node_announcement(ctx, sig, features, timestamp,
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

/**
 * Handle an incoming gossip message
 *
 * Returns wire formatted error if handling failed. The error contains the
 * details of the failures. The caller is expected to return the error to the
 * peer, or drop the error if the message did not come from a peer.
 */
static u8 *handle_gossip_msg(struct daemon *daemon, const u8 *msg)
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
		err = handle_channel_update(rstate, msg);
		if (err)
			return err;
		break;
	}

	/* All good, no error to report */
	return NULL;
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
	const char *err = got_pong(pong, &peer->local->num_pings_outstanding);

	if (err) {
		peer_error(peer, "%s", err);
		return;
	}

	daemon_conn_send(&peer->daemon->master,
			 take(towire_gossip_ping_reply(NULL, true,
						       tal_len(pong))));
}

/* If master asks us to release peer, we attach this destructor in case it
 * dies while we're waiting for it to finish IO */
static void fail_release(struct peer *peer)
{
	u8 *msg = towire_gossipctl_release_peer_replyfail(NULL);
	daemon_conn_send(&peer->daemon->master, take(msg));
}

static struct io_plan *ready_for_master(struct io_conn *conn, struct peer *peer)
{
	u8 *msg;
	if (peer->local->nongossip_msg)
		msg = towire_gossip_peer_nongossip(peer, &peer->id,
						   &peer->addr,
						   &peer->local->pcs.cs,
						   peer->gfeatures,
						   peer->lfeatures,
						   peer->local->nongossip_msg);
	else
		msg = towire_gossipctl_release_peer_reply(peer,
							  &peer->addr,
							  &peer->local->pcs.cs,
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
		/* Wake writer. */
		msg_wake(&peer->local->peer_out);
		return io_wait(conn, peer, peer_next_in, peer);
	}

	return peer_read_message(conn, &peer->local->pcs, peer_msgin);
}

static struct io_plan *peer_msgin(struct io_conn *conn,
				  struct peer *peer, u8 *msg)
{
	enum wire_type t = fromwire_peektype(msg);
	u8 *err;

	switch (t) {
	case WIRE_ERROR:
		status_trace("%s sent ERROR %s",
			     type_to_string(tmpctx, struct pubkey, &peer->id),
			     sanitize_error(tmpctx, msg, NULL));
		return io_close(conn);

	case WIRE_CHANNEL_ANNOUNCEMENT:
	case WIRE_NODE_ANNOUNCEMENT:
	case WIRE_CHANNEL_UPDATE:
		err = handle_gossip_msg(peer->daemon, msg);
		if (err)
			queue_peer_msg(peer, take(err));
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
		status_trace("Peer %s sent packet with unknown message type %u, ignoring",
			     type_to_string(tmpctx, struct pubkey, &peer->id), t);
	} else
		peer_error(peer, "Packet with unknown message type %u", t);

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
	else if (peer->remote)
		/* Notify the daemon_conn-write loop */
		msg_wake(&peer->remote->out);
}

/* Mutual recursion. */
static struct io_plan *peer_pkt_out(struct io_conn *conn, struct peer *peer);

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
		if (!peer_in_started(conn, &peer->local->pcs))
			return ready_for_master(conn, peer);
	} else if (peer->gossip_sync) {
		/* If we're supposed to be sending gossip, do so now. */
		const u8 *next;

		next = next_broadcast(peer->daemon->rstate->broadcasts,
				      &peer->broadcast_index);

		if (next)
			return peer_write_message(conn, &peer->local->pcs,
						  next,
						  peer_pkt_out);

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
		/* We want update that comes from our end. */
		if (pubkey_eq(&chan->nodes[0]->id, &peer->daemon->id))
			update = get_broadcast(rstate->broadcasts,
					       chan->half[0]
					       .channel_update_msgidx);
		else if (pubkey_eq(&chan->nodes[1]->id, &peer->daemon->id))
			update = get_broadcast(rstate->broadcasts,
					       chan->half[1]
					       .channel_update_msgidx);
		else {
			status_unusual("peer %s scid %s: not our channel?",
				       type_to_string(tmpctx, struct pubkey,
						      &peer->id),
				       type_to_string(tmpctx,
						      struct short_channel_id,
						      &scid));
			update = NULL;
		}
	}
	status_trace("peer %s schanid %s: %s update",
		     type_to_string(tmpctx, struct pubkey, &peer->id),
		     type_to_string(tmpctx, struct short_channel_id, &scid),
		     update ? "got" : "no");

	msg = towire_gossip_get_update_reply(NULL, update);
	daemon_conn_send(peer->remote, take(msg));
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
		err = handle_gossip_msg(peer->daemon, dc->msg_in);
		if (err)
			queue_peer_msg(peer, take(err));

	} else if (type == WIRE_GOSSIP_GET_UPDATE) {
		handle_get_update(peer, dc->msg_in);
	} else if (type == WIRE_GOSSIP_LOCAL_ADD_CHANNEL) {
		gossip_store_local_add_channel(peer->daemon->rstate->store,
					       dc->msg_in);
		handle_local_add_channel(peer->daemon->rstate, dc->msg_in);
	} else {
		status_broken("peer %s: send us unknown msg of type %s",
			      type_to_string(tmpctx, struct pubkey, &peer->id),
			      gossip_wire_type_name(type));
		return io_close(conn);
	}

	return daemon_conn_read_next(conn, dc);
}

static void free_peer_remote(struct io_conn *conn, struct daemon_conn *dc)
{
	struct peer *peer = dc->ctx;

	peer->remote = tal_free(peer->remote);
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
			 owner_msg_in, free_peer_remote);
	peer->remote->msg_queue_cleared_cb = nonlocal_dump_gossip;

	/* Peer stays around, even though caller will close conn. */
	tal_steal(peer->daemon, peer);

	status_debug("peer %s now remote",
		     type_to_string(tmpctx, struct pubkey, &peer->id));

	daemon_conn_send(&peer->daemon->master, msg);
	daemon_conn_send_fd(&peer->daemon->master, peer_fd);
	daemon_conn_send_fd(&peer->daemon->master, fds[1]);

	return true;
}

/**
 * nonlocal_dump_gossip - catch the nonlocal peer up with the latest gossip.
 *
 * Registered as `msg_queue_cleared_cb` by the `peer->remote`.
 */
static bool nonlocal_dump_gossip(struct io_conn *conn, struct daemon_conn *dc)
{
	const u8 *next;
	struct peer *peer = dc->ctx;

	/* Make sure we are not connected directly */
	assert(!peer->local);

	/* Nothing to do if we're not gossiping */
	if (!peer->gossip_sync)
		return false;

	next = next_broadcast(peer->daemon->rstate->broadcasts,
			      &peer->broadcast_index);

	if (!next) {
		peer->gossip_sync = false;
		return false;
	} else {
		u8 *msg = towire_gossip_send_gossip(NULL, next);
		daemon_conn_send(peer->remote, take(msg));
		return true;
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
	u8 *inner_msg;
	int peer_fd, gossip_fd;
};

static void drain_and_forward_gossip(struct peer *peer, int gossip_fd)
{
	u8 *msg;

	/* Be careful: what if they handed wrong fd?  Make it non-blocking. */
	if (!io_fd_block(gossip_fd, false)) {
		status_unusual("NONBLOCK failed for gossip_fd from peer %s: %s",
			       type_to_string(tmpctx, struct pubkey, &peer->id),
			       strerror(errno));
		return;
	}

	/* It's sync, but not blocking. */
	while ((msg = wire_sync_read(tmpctx, gossip_fd)) != NULL) {
		u8 *gossip;
		if (!fromwire_gossip_send_gossip(NULL, msg, &gossip))
			break;
		msg_enqueue(&peer->local->peer_out, take(gossip));
	}

	close(gossip_fd);
}

static struct io_plan *handle_returning_peer(struct io_conn *conn,
					     struct returning_peer *rpeer)
{
	struct daemon *daemon = rpeer->daemon;
	struct peer *peer, *connecting;

	peer = find_peer(daemon, &rpeer->id);
	if (!peer)
		status_failed(STATUS_FAIL_INTERNAL_ERROR,
			      "hand_back_peer unknown peer: %s",
			      type_to_string(tmpctx, struct pubkey, &rpeer->id));

	assert(!peer->local);

	/* Corner case: we got a reconnection while master was handing this
	 * back.  We would have killed it immediately if it was local previously
	 * so do that now */
	connecting = find_reconnecting_peer(daemon, &rpeer->id);
	if (connecting) {
		status_trace("Forgetting handed back peer %s",
			     type_to_string(tmpctx, struct pubkey, &peer->id));

		tal_free(peer);
		/* Now connecting peer can go ahead. */
		io_wake(connecting);

		return daemon_conn_read_next(conn, &daemon->master);
	}

	status_trace("hand_back_peer %s: now local again",
		     type_to_string(tmpctx, struct pubkey, &rpeer->id));

	/* Now we talk to peer directly again. */
	daemon_conn_clear(peer->remote);
	peer->remote = tal_free(peer->remote);

	peer->local = new_local_peer_state(peer, &rpeer->cs);
	peer->local->fd = rpeer->peer_fd;

	/* Forward any gossip we sent while fd wasn't being read */
	drain_and_forward_gossip(peer, rpeer->gossip_fd);

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
	if (!fromwire_gossipctl_hand_back_peer(msg, msg,
					       &rpeer->id, &rpeer->cs,
					       &rpeer->inner_msg))
		master_badmsg(WIRE_GOSSIPCTL_HAND_BACK_PEER, msg);

	status_debug("Handing back peer %s to master",
		     type_to_string(msg, struct pubkey, &rpeer->id));

	return io_recv_fd(conn, &rpeer->peer_fd,
			  read_returning_gossipfd, rpeer);
}

static struct io_plan *disconnect_peer(struct io_conn *conn, struct daemon *daemon,
				       const u8 *msg)
{
	struct pubkey id;
 	struct peer *peer;

	if (!fromwire_gossipctl_peer_disconnect(msg, &id))
		master_badmsg(WIRE_GOSSIPCTL_PEER_DISCONNECT, msg);

	peer = find_peer(daemon, &id);
	if (peer && peer->local) {
		/* This peer is local to this (gossipd) daemon */
		io_close(peer->local->conn);
		msg = towire_gossipctl_peer_disconnect_reply(NULL);
		daemon_conn_send(&daemon->master, take(msg));
	} else {
		status_trace("disconnect_peer: peer %s %s",
			     type_to_string(tmpctx, struct pubkey, &id),
			     !peer ? "not connected" : "not gossiping");
		msg = towire_gossipctl_peer_disconnect_replyfail(NULL, peer ? true : false);
		daemon_conn_send(&daemon->master, take(msg));
	}
	return daemon_conn_read_next(conn, &daemon->master);
}

static struct io_plan *release_peer(struct io_conn *conn, struct daemon *daemon,
				    const u8 *msg)
{
	struct pubkey id;
 	struct peer *peer;

	if (!fromwire_gossipctl_release_peer(msg, &id))
		master_badmsg(WIRE_GOSSIPCTL_RELEASE_PEER, msg);

	peer = find_peer(daemon, &id);
	if (!peer || !peer->local || peer->local->return_to_master) {
		/* This can happen with dying peers, or reconnect */
		status_trace("release_peer: peer %s %s",
			     type_to_string(tmpctx, struct pubkey, &id),
			     !peer ? "not found"
			     : peer->local ? "already releasing"
			     : "not local");
		msg = towire_gossipctl_release_peer_replyfail(NULL);
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

	if (!c)
		return;

	/* Don't mention non-public inactive channels. */
	if (!c->active && !c->channel_update_msgidx)
		return;

	n = tal_count(*entries);
	tal_resize(entries, n+1);
	e = &(*entries)[n];

	e->source = chan->nodes[idx]->id;
	e->destination = chan->nodes[!idx]->id;
	e->satoshis = chan->satoshis;
	e->active = c->active;
	e->flags = c->flags;
	e->public = chan->public && (c->channel_update_msgidx != 0);
	e->short_channel_id = chan->scid;
	e->last_update_timestamp = c->channel_update_msgidx ? c->last_timestamp : -1;
	if (e->last_update_timestamp >= 0) {
		e->base_fee_msat = c->base_fee;
		e->fee_per_millionth = c->proportional_fee;
		e->delay = c->delay;
	}
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
			const struct node *n)
{
	struct gossip_getnodes_entry *new;
	size_t num_nodes = tal_count(*nodes);

	new = tal(*nodes, struct gossip_getnodes_entry);
	new->nodeid = n->id;
	new->last_timestamp = n->last_timestamp;
	if (n->last_timestamp < 0) {
		new->addresses = NULL;
	} else {
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
	struct pubkey *ids;

	fromwire_gossip_getnodes_request(tmpctx, msg, &ids);

	nodes = tal_arr(tmpctx, const struct gossip_getnodes_entry *, 0);
	if (ids) {
		for (size_t i = 0; i < tal_count(ids); i++) {
			n = get_node(daemon->rstate, &ids[i]);
			if (n)
				append_node(&nodes, n);
		}
	} else {
		struct node_map_iter i;
		n = node_map_first(daemon->rstate->nodes, &i);
		while (n != NULL) {
			append_node(&nodes, n);
			n = node_map_next(daemon->rstate->nodes, &i);
		}
	}
	out = towire_gossip_getnodes_reply(NULL, nodes);
	daemon_conn_send(&daemon->master, take(out));
	return daemon_conn_read_next(conn, &daemon->master);
}

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
				 take(towire_gossip_ping_reply(NULL, true, 0)));
	else
		peer->local->num_pings_outstanding++;

out:
	return daemon_conn_read_next(conn, &daemon->master);
}

static int make_listen_fd(int domain, void *addr, socklen_t len, bool mayfail)
{
	int fd = socket(domain, SOCK_STREAM, 0);
	if (fd < 0) {
		if (!mayfail)
			status_failed(STATUS_FAIL_INTERNAL_ERROR,
				      "Failed to create %u socket: %s",
				      domain, strerror(errno));
		status_trace("Failed to create %u socket: %s",
			     domain, strerror(errno));
		return -1;
	}

	if (addr) {
		int on = 1;

		/* Re-use, please.. */
		if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on)))
			status_unusual("Failed setting socket reuse: %s",
				       strerror(errno));

		if (bind(fd, addr, len) != 0) {
			if (!mayfail)
				status_failed(STATUS_FAIL_INTERNAL_ERROR,
					      "Failed to bind on %u socket: %s",
					      domain, strerror(errno));
			status_trace("Failed to create %u socket: %s",
				     domain, strerror(errno));
			goto fail;
		}
	}

	if (listen(fd, 5) != 0) {
		status_failed(STATUS_FAIL_INTERNAL_ERROR,
			      "Failed to listen on %u socket: %s",
			      domain, strerror(errno));
	}
	return fd;

fail:
	close_noerr(fd);
	return -1;
}

static void gossip_send_keepalive_update(struct routing_state *rstate,
					 struct half_chan *hc)
{
	secp256k1_ecdsa_signature sig;
	struct bitcoin_blkid chain_hash;
	struct short_channel_id scid;
	u32 timestamp, fee_base_msat, fee_proportional_millionths;
	u64 htlc_minimum_msat;
	u16 flags, cltv_expiry_delta;
	u8 *update, *msg, *err;
	const u8 *old_update;

	/* Parse old update */
	old_update = get_broadcast(rstate->broadcasts,
				   hc->channel_update_msgidx);

	if (!fromwire_channel_update(
		old_update, &sig, &chain_hash, &scid, &timestamp,
		&flags, &cltv_expiry_delta, &htlc_minimum_msat, &fee_base_msat,
		&fee_proportional_millionths)) {
		status_failed(
		    STATUS_FAIL_INTERNAL_ERROR,
		    "Unable to parse previously accepted channel_update");
	}

	/* Now generate a new update, with up to date timestamp */
	timestamp = time_now().ts.tv_sec;
	update =
	    towire_channel_update(tmpctx, &sig, &chain_hash, &scid, timestamp,
				  flags, cltv_expiry_delta, htlc_minimum_msat,
				  fee_base_msat, fee_proportional_millionths);

	if (!wire_sync_write(HSM_FD,
			     towire_hsm_cupdate_sig_req(tmpctx, update))) {
		status_failed(STATUS_FAIL_HSM_IO, "Writing cupdate_sig_req: %s",
			      strerror(errno));
	}

	msg = wire_sync_read(tmpctx, HSM_FD);
	if (!msg || !fromwire_hsm_cupdate_sig_reply(tmpctx, msg, &update)) {
		status_failed(STATUS_FAIL_HSM_IO,
			      "Reading cupdate_sig_req: %s",
			      strerror(errno));
	}

	status_trace("Sending keepalive channel_update for %s",
		     type_to_string(tmpctx, struct short_channel_id, &scid));

	err = handle_channel_update(rstate, update);
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

			if (!hc->channel_update_msgidx) {
				/* Connection is not public yet, so don't even
				 * try to re-announce it */
				continue;
			}

			if (hc->last_timestamp > highwater) {
				/* No need to send a keepalive update message */
				continue;
			}

			if (!hc->active) {
				/* Only send keepalives for active connections */
				continue;
			}

			gossip_send_keepalive_update(daemon->rstate, hc);
		}
	}

	route_prune(daemon->rstate);
}

static struct io_plan *connection_in(struct io_conn *conn, struct daemon *daemon)
{
	struct wireaddr_internal addr;
	struct sockaddr_storage s = {};
	socklen_t len = sizeof(s);

	if (getpeername(io_conn_fd(conn), (struct sockaddr *)&s, &len) != 0) {
		status_trace("Failed to get peername for incoming conn: %s",
			     strerror(errno));
		return io_close(conn);
	}

	if (s.ss_family == AF_INET6) {
		struct sockaddr_in6 *s6 = (void *)&s;
		addr.itype = ADDR_INTERNAL_WIREADDR;
		wireaddr_from_ipv6(&addr.u.wireaddr,
				   &s6->sin6_addr, ntohs(s6->sin6_port));
	} else if (s.ss_family == AF_INET) {
		struct sockaddr_in *s4 = (void *)&s;
		addr.itype = ADDR_INTERNAL_WIREADDR;
		wireaddr_from_ipv4(&addr.u.wireaddr,
				   &s4->sin_addr, ntohs(s4->sin_port));
	} else if (s.ss_family == AF_UNIX) {
		struct sockaddr_un *sun = (void *)&s;
		addr.itype = ADDR_INTERNAL_SOCKNAME;
		memcpy(addr.u.sockname, sun->sun_path, sizeof(sun->sun_path));
	} else {
		status_broken("Unknown socket type %i for incoming conn",
			      s.ss_family);
		return io_close(conn);
	}

	/* FIXME: Timeout */
	return responder_handshake(conn, &daemon->id, &addr,
				   init_new_peer, daemon);
}

/* Return true if it created socket successfully. */
static bool handle_wireaddr_listen(struct daemon *daemon,
				   const struct wireaddr *wireaddr,
				   bool mayfail)
{
	int fd;
	struct sockaddr_in addr;
	struct sockaddr_in6 addr6;

	switch (wireaddr->type) {
	case ADDR_TYPE_IPV4:
		wireaddr_to_ipv4(wireaddr, &addr);
		/* We might fail if IPv6 bound to port first */
		fd = make_listen_fd(AF_INET, &addr, sizeof(addr), mayfail);
		if (fd >= 0) {
			status_trace("Created IPv4 listener on port %u",
				     wireaddr->port);
			io_new_listener(daemon, fd, connection_in, daemon);
			return true;
		}
		return false;
	case ADDR_TYPE_IPV6:
		wireaddr_to_ipv6(wireaddr, &addr6);
		fd = make_listen_fd(AF_INET6, &addr6, sizeof(addr6), mayfail);
		if (fd >= 0) {
			status_trace("Created IPv6 listener on port %u",
				     wireaddr->port);
			io_new_listener(daemon, fd, connection_in, daemon);
			return true;
		}
		return false;
	case ADDR_TYPE_PADDING:
	case ADDR_TYPE_TOR_V2:
	case ADDR_TYPE_TOR_V3:
		break;
	}
	status_failed(STATUS_FAIL_INTERNAL_ERROR,
		      "Invalid listener wireaddress type %u", wireaddr->type);
}

/* If it's a wildcard, turns it into a real address pointing to internet */
static bool public_address(struct daemon *daemon, struct wireaddr *wireaddr)
{
	if (wireaddr_is_wildcard(wireaddr)) {
		if (!guess_address(wireaddr))
			return false;
	}

	return address_routable(wireaddr, daemon->rstate->dev_allow_localhost);
}

static void add_announcable(struct daemon *daemon, const struct wireaddr *addr)
{
	size_t n = tal_count(daemon->announcable);
	tal_resize(&daemon->announcable, n+1);
	daemon->announcable[n] = *addr;
}

static void add_binding(struct wireaddr_internal **binding,
			const struct wireaddr_internal *addr)
{
	size_t n = tal_count(*binding);
	tal_resize(binding, n+1);
	(*binding)[n] = *addr;
}

/* Initializes daemon->announcable array, returns addresses we bound to. */
static struct wireaddr_internal *setup_listeners(const tal_t *ctx,
						 struct daemon *daemon)
{
	struct sockaddr_un addrun;
	int fd;
	struct wireaddr_internal *binding;

	binding = tal_arr(ctx, struct wireaddr_internal, 0);
	daemon->announcable = tal_arr(daemon, struct wireaddr, 0);

	for (size_t i = 0; i < tal_count(daemon->proposed_wireaddr); i++) {
		struct wireaddr_internal wa = daemon->proposed_wireaddr[i];

		if (!(daemon->proposed_listen_announce[i] & ADDR_LISTEN)) {
			assert(daemon->proposed_listen_announce[i]
			       & ADDR_ANNOUNCE);
			/* You can only announce wiretypes! */
			assert(daemon->proposed_wireaddr[i].itype
			       == ADDR_INTERNAL_WIREADDR);
			add_announcable(daemon, &wa.u.wireaddr);
			continue;
		}

		switch (wa.itype) {
		case ADDR_INTERNAL_SOCKNAME:
			addrun.sun_family = AF_UNIX;
			memcpy(addrun.sun_path, wa.u.sockname,
			       sizeof(addrun.sun_path));
			fd = make_listen_fd(AF_INET, &addrun, sizeof(addrun),
					    false);
			status_trace("Created socket listener on file %s",
				     addrun.sun_path);
			io_new_listener(daemon, fd, connection_in, daemon);
			/* We don't announce socket names */
			add_binding(&binding, &wa);
			continue;
		case ADDR_INTERNAL_ALLPROTO: {
			bool ipv6_ok;

			wa.itype = ADDR_INTERNAL_WIREADDR;
			wa.u.wireaddr.port = wa.u.port;
			memset(wa.u.wireaddr.addr, 0,
			       sizeof(wa.u.wireaddr.addr));

			/* Try both IPv6 and IPv4. */
			wa.u.wireaddr.type = ADDR_TYPE_IPV6;
			wa.u.wireaddr.addrlen = 16;

			ipv6_ok = handle_wireaddr_listen(daemon, &wa.u.wireaddr,
							 true);
			if (ipv6_ok) {
				add_binding(&binding, &wa);
				if (public_address(daemon, &wa.u.wireaddr))
					add_announcable(daemon, &wa.u.wireaddr);
			}
			wa.u.wireaddr.type = ADDR_TYPE_IPV4;
			wa.u.wireaddr.addrlen = 4;
			/* OK if this fails, as long as one succeeds! */
			if (handle_wireaddr_listen(daemon, &wa.u.wireaddr,
						   ipv6_ok)) {
				add_binding(&binding, &wa);
				if (public_address(daemon, &wa.u.wireaddr))
					add_announcable(daemon, &wa.u.wireaddr);
			}
			continue;
		}
		case ADDR_INTERNAL_WIREADDR:
			handle_wireaddr_listen(daemon, &wa.u.wireaddr, false);
			add_binding(&binding, &wa);
			if (public_address(daemon, &wa.u.wireaddr))
				add_announcable(daemon, &wa.u.wireaddr);
			continue;
		}
		/* Shouldn't happen. */
		status_failed(STATUS_FAIL_INTERNAL_ERROR,
			      "Invalid listener address type %u",
			      daemon->proposed_wireaddr[i].itype);
	}

	return binding;
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
	bool dev_allow_localhost;
	struct wireaddr *proxyaddr;

	if (!fromwire_gossipctl_init(
		daemon, msg, &daemon->broadcast_interval, &chain_hash,
		&daemon->id, &daemon->globalfeatures,
		&daemon->localfeatures, &daemon->proposed_wireaddr,
		&daemon->proposed_listen_announce, daemon->rgb,
		daemon->alias, &update_channel_interval, &daemon->reconnect,
		&proxyaddr, &daemon->use_proxy_always,
		&dev_allow_localhost, &daemon->tor_autoservice,
		&daemon->tor_serviceaddr, &daemon->tor_password)) {
		master_badmsg(WIRE_GOSSIPCTL_INIT, msg);
	}
	/* Prune time is twice update time */
	daemon->rstate = new_routing_state(daemon, &chain_hash, &daemon->id,
					   update_channel_interval * 2,
					   dev_allow_localhost);

	/* Resolve Tor proxy address if any */
	if (proxyaddr) {
		status_trace("Proxy address: %s",
			     fmt_wireaddr(tmpctx, proxyaddr));
		daemon->proxyaddr = wireaddr_to_addrinfo(daemon, proxyaddr);
	} else
		daemon->proxyaddr = NULL;

	/* Load stored gossip messages */
	gossip_store_load(daemon->rstate, daemon->rstate->store);

	new_reltimer(&daemon->timers, daemon,
		     time_from_sec(daemon->rstate->prune_timeout/4),
		     gossip_refresh_network, daemon);

	return daemon_conn_read_next(master->conn, master);
}

static struct io_plan *gossip_activate(struct daemon_conn *master,
				       struct daemon *daemon,
				       const u8 *msg)
{
	bool listen;
	struct wireaddr_internal *binding;

	if (!fromwire_gossipctl_activate(msg, &listen))
		master_badmsg(WIRE_GOSSIPCTL_ACTIVATE, msg);

	if (listen) {
		binding = setup_listeners(tmpctx, daemon);
		if (daemon->tor_autoservice) {
			struct wireaddr *tor;
			tor = tor_autoservice(tmpctx,
					      daemon->tor_serviceaddr,
					      daemon->tor_password,
					      binding);
			add_announcable(daemon, tor);
		}
	} else
		binding = NULL;

	/* If we only advertize Tor addresses, force everything through proxy
	 * to avoid other leakage */
	if (!daemon->use_proxy_always
	    && tal_count(daemon->announcable) != 0
	    && all_tor_addresses(daemon->announcable)) {
		status_trace("Only announcing Tor addresses: forcing proxy use");
		daemon->use_proxy_always = true;
	}

	/* OK, we're ready! */
	daemon_conn_send(&daemon->master,
			 take(towire_gossipctl_activate_reply(NULL,
							      binding,
							      daemon->announcable)));

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

static struct io_plan *handshake_out_success(struct io_conn *conn,
					     const struct pubkey *id,
					     const struct wireaddr_internal *addr,
					     const struct crypto_state *cs,
					     struct reaching *reach)
{
	reach->connstate = "Exchanging init messages";
	return init_new_peer(conn, id, addr, cs, reach->daemon);
}


struct io_plan *connection_out(struct io_conn *conn, struct reaching *reach)
{
	/* FIXME: Timeout */
	status_trace("Connected out for %s",
		     type_to_string(tmpctx, struct pubkey, &reach->id));

	reach->connstate = "Cryptographic handshake";
	return initiator_handshake(conn, &reach->daemon->id, &reach->id,
				   &reach->addr,
				   handshake_out_success, reach);
}

static void connect_failed(struct io_conn *conn, struct reaching *reach)
{
	u8 *msg;
	struct important_peerid *imp;
	const char *err = tal_fmt(tmpctx, "%s: %s",
				  reach->connstate,
				  strerror(errno));

	/* Tell any connect command what happened. */
	if (reach->master_needs_response) {
		msg = towire_gossipctl_connect_to_peer_result(NULL, &reach->id,
							      false, err);
		daemon_conn_send(&reach->daemon->master, take(msg));
	}

	status_trace("Failed connected out for %s",
		     type_to_string(tmpctx, struct pubkey, &reach->id));

	/* If we want to keep trying, do so. */
	imp = important_peerid_map_get(&reach->daemon->important_peerids,
				       &reach->id);
	if (imp) {
		imp->wait_seconds *= 2;
		if (imp->wait_seconds > MAX_WAIT_SECONDS)
			imp->wait_seconds = MAX_WAIT_SECONDS;

		status_trace("...will try again in %u seconds",
			     imp->wait_seconds);
		/* If important_id freed, this will be removed too */
		imp->reconnect_timer
			= new_reltimer(&reach->daemon->timers, imp,
				       time_from_sec(imp->wait_seconds),
				       retry_important, imp);
	}
	tal_free(reach);
	return;
}

static struct io_plan *conn_init(struct io_conn *conn, struct reaching *reach)
{
	struct addrinfo *ai;

	switch (reach->addr.itype) {
	case ADDR_INTERNAL_SOCKNAME:
		ai = wireaddr_internal_to_addrinfo(tmpctx, &reach->addr);
		break;
	case ADDR_INTERNAL_ALLPROTO:
		status_failed(STATUS_FAIL_INTERNAL_ERROR,
			      "Can't reach to all protocols");
		break;
	case ADDR_INTERNAL_WIREADDR:
		/* If it was a Tor address, we wouldn't be here. */
		ai = wireaddr_to_addrinfo(tmpctx, &reach->addr.u.wireaddr);
		break;
	}
	assert(ai);

	io_set_finish(conn, connect_failed, reach);
	return io_connect(conn, ai, connection_out, reach);
}

static struct io_plan *conn_tor_init(struct io_conn *conn,
				     struct reaching *reach)
{
	assert(reach->addr.itype == ADDR_INTERNAL_WIREADDR);
	io_set_finish(conn, connect_failed, reach);
	return io_tor_connect(conn, reach->daemon->proxyaddr,
			      &reach->addr.u.wireaddr, reach);
}

static struct addrhint *
seed_resolve_addr(const tal_t *ctx, const struct pubkey *id, const u16 port,
		  bool dns_ok)
{
	struct addrhint *a;
	char bech32[100], *addr;
	u8 der[PUBKEY_DER_LEN];
	u5 *data = tal_arr(ctx, u5, 0);

	pubkey_to_der(der, id);
	bech32_push_bits(&data, der, PUBKEY_DER_LEN*8);
	bech32_encode(bech32, "ln", data, tal_count(data), sizeof(bech32));
	addr = tal_fmt(ctx, "%s.lseed.bitcoinstats.com", bech32);

	status_trace("Resolving %s", addr);

	a = tal(ctx, struct addrhint);
	a->addr.itype = ADDR_INTERNAL_WIREADDR;
	if (!wireaddr_from_hostname(&a->addr.u.wireaddr, addr, port, dns_ok,
				    NULL)) {
		status_trace("Could not resolve %s", addr);
		return tal_free(a);
	} else {
		status_trace("Resolved %s to %s", addr,
			     type_to_string(ctx, struct wireaddr,
					    &a->addr.u.wireaddr));
		return a;
	}
}

/* Resolve using gossiped wireaddr stored in routemap. */
static struct addrhint *
gossip_resolve_addr(const tal_t *ctx,
		    struct routing_state *rstate,
		    const struct pubkey *id)
{
	struct node *node;

	/* Get from routing state. */
	node = get_node(rstate, id);

	/* No matching node? */
	if (!node)
		return NULL;

	/* FIXME: When struct addrhint can contain more than one address,
	 * we should copy all routable addresses. */
	for (size_t i = 0; i < tal_count(node->addresses); i++) {
		struct addrhint *a;

		if (!address_routable(&node->addresses[i],
				      rstate->dev_allow_localhost))
			continue;

		a = tal(ctx, struct addrhint);
		a->addr.itype = ADDR_INTERNAL_WIREADDR;
		a->addr.u.wireaddr = node->addresses[i];
		return a;
	}

	return NULL;
}

static void try_reach_peer(struct daemon *daemon, const struct pubkey *id,
			   bool master_needs_response)
{
	struct addrhint *a;
	int fd, af;
	struct reaching *reach;
	u8 *msg;
	bool use_tor;
	struct peer *peer = find_peer(daemon, id);

	if (peer) {
		status_debug("try_reach_peer: have peer %s",
			     type_to_string(tmpctx, struct pubkey, id));
		if (master_needs_response) {
			msg = towire_gossipctl_connect_to_peer_result(NULL, id,
								      true,
								      "");
			daemon_conn_send(&daemon->master, take(msg));
		}
		return;
	}

	/* If we're trying to reach it right now, that's OK. */
	reach = find_reaching(daemon, id);
	if (reach) {
		/* Please tell us too.  Master should not ask twice (we'll
		 * only respond once, and so one request will get stuck) */
		if (reach->master_needs_response)
			status_failed(STATUS_FAIL_MASTER_IO,
				      "Already reaching %s",
				      type_to_string(tmpctx, struct pubkey, id));
		reach->master_needs_response = true;
		return;
	}

	a = find_addrhint(daemon, id);

	if (!a)
		a = gossip_resolve_addr(tmpctx,
					daemon->rstate,
					id);

	if (!a)
		a = seed_resolve_addr(tmpctx, id, 9735,
				      !daemon->use_proxy_always);

	if (!a) {
		status_debug("No address known for %s, giving up",
			     type_to_string(tmpctx, struct pubkey, id));
		if (master_needs_response) {
			msg = towire_gossipctl_connect_to_peer_result(NULL, id,
					      false,
					      "No address known, giving up");
			daemon_conn_send(&daemon->master, take(msg));
		}
		return;
	}

	/* Might not even be able to create eg. IPv6 sockets */
	af = -1;
	use_tor = daemon->use_proxy_always;

	switch (a->addr.itype) {
	case ADDR_INTERNAL_SOCKNAME:
		af = AF_LOCAL;
		/* Local sockets don't use tor proxy */
		use_tor = false;
		break;
	case ADDR_INTERNAL_ALLPROTO:
		status_failed(STATUS_FAIL_INTERNAL_ERROR,
			      "Can't reach ALLPROTO");
	case ADDR_INTERNAL_WIREADDR:
		switch (a->addr.u.wireaddr.type) {
		case ADDR_TYPE_TOR_V2:
		case ADDR_TYPE_TOR_V3:
			use_tor = true;
			break;
		case ADDR_TYPE_IPV4:
			af = AF_INET;
			break;
		case ADDR_TYPE_IPV6:
			af = AF_INET6;
			break;
		case ADDR_TYPE_PADDING:
			break;
		}
	}

	/* If we have to use Tor but we don't have a proxy, we fail. */
	if (use_tor) {
		/* Can't reach tor addresses without proxy. */
		if (!daemon->proxyaddr) {
			status_debug("Need to use tor for %i, but no proxy",
				     a->addr.u.wireaddr.type);
			af = -1;
		} else
			af = daemon->proxyaddr->ai_family;
	}

	if (af == -1) {
		fd = -1;
		errno = EPROTONOSUPPORT;
	} else
		fd = socket(af, SOCK_STREAM, 0);

	if (fd < 0) {
		char *err = tal_fmt(tmpctx,
				    "Can't open %i socket for %s (%s), giving up",
				    af,
				    type_to_string(tmpctx, struct pubkey, id),
				    strerror(errno));
		status_debug("%s", err);
		if (master_needs_response) {
			msg = towire_gossipctl_connect_to_peer_result(NULL, id,
							      false, err);
			daemon_conn_send(&daemon->master, take(msg));
		}
		return;
	}

	/* Start connecting to it */
	reach = tal(daemon, struct reaching);
	reach->daemon = daemon;
	reach->id = *id;
	reach->addr = a->addr;
	reach->master_needs_response = master_needs_response;
	reach->connstate = "Connection establishment";
	list_add_tail(&daemon->reaching, &reach->list);
	tal_add_destructor(reach, destroy_reaching);

	if (use_tor)
		io_new_conn(reach, fd, conn_tor_init, reach);
	else
		io_new_conn(reach, fd, conn_init, reach);
}

/* Called from timer, so needs single-arg declaration */
static void retry_important(struct important_peerid *imp)
{
	/* In case we've come off a timer, don't leave dangling pointer */
	imp->reconnect_timer = NULL;

	/* With --dev-no-reconnect or --offline, we only want explicit
	 * connects */
	if (!imp->daemon->reconnect)
		return;

	try_reach_peer(imp->daemon, &imp->id, false);
}

static struct io_plan *connect_to_peer(struct io_conn *conn,
				       struct daemon *daemon, const u8 *msg)
{
	struct pubkey id;
	struct important_peerid *imp;

	if (!fromwire_gossipctl_connect_to_peer(msg, &id))
		master_badmsg(WIRE_GOSSIPCTL_CONNECT_TO_PEER, msg);

	/* If this is an important peer, free any outstanding timer */
	imp = important_peerid_map_get(&daemon->important_peerids, &id);
	if (imp)
		imp->reconnect_timer = tal_free(imp->reconnect_timer);
	try_reach_peer(daemon, &id, true);
	return daemon_conn_read_next(conn, &daemon->master);
}

static struct io_plan *addr_hint(struct io_conn *conn,
				 struct daemon *daemon, const u8 *msg)
{
	struct addrhint *a = tal(daemon, struct addrhint);

	if (!fromwire_gossipctl_peer_addrhint(msg, &a->id, &a->addr))
		master_badmsg(WIRE_GOSSIPCTL_PEER_ADDRHINT, msg);

	/* Replace any old one. */
	tal_free(find_addrhint(daemon, &a->id));

	list_add_tail(&daemon->addrhints, &a->list);
	tal_add_destructor(a, destroy_addrhint);

	return daemon_conn_read_next(conn, &daemon->master);
}

static struct io_plan *peer_important(struct io_conn *conn,
				      struct daemon *daemon, const u8 *msg)
{
	struct pubkey id;
	bool important;
	struct important_peerid *imp;

	if (!fromwire_gossipctl_peer_important(msg, &id, &important))
		master_badmsg(WIRE_GOSSIPCTL_PEER_IMPORTANT, msg);

	imp = important_peerid_map_get(&daemon->important_peerids, &id);
	if (important) {
		if (!imp) {
			imp = tal(daemon, struct important_peerid);
			imp->id = id;
			imp->daemon = daemon;
			imp->wait_seconds = INITIAL_WAIT_SECONDS;
			important_peerid_map_add(&daemon->important_peerids,
						 imp);
			/* Start trying to reaching it now. */
			retry_important(imp);
		}
	} else {
		if (imp) {
			important_peerid_map_del(&daemon->important_peerids,
						 imp);
			/* Stop trying to reach it (if we are) */
			tal_free(find_reaching(daemon, &imp->id));
		}
	}

	return daemon_conn_read_next(conn, &daemon->master);
}

static struct io_plan *peer_disconnected(struct io_conn *conn,
					 struct daemon *daemon, const u8 *msg)
{
	struct pubkey id;
	struct peer *peer;

	if (!fromwire_gossipctl_peer_disconnected(msg, &id))
		master_badmsg(WIRE_GOSSIPCTL_PEER_DISCONNECTED, msg);

	peer = find_peer(daemon, &id);
	if (!peer)
		status_failed(STATUS_FAIL_INTERNAL_ERROR,
			      "peer_disconnected unknown peer: %s",
			      type_to_string(tmpctx, struct pubkey, &id));

	assert(!peer->local);

	status_trace("Forgetting remote peer %s",
		     type_to_string(tmpctx, struct pubkey, &peer->id));

	tal_free(peer);

	/* If there was a connecting peer waiting, wake it now */
	peer = find_reconnecting_peer(daemon, &id);
	if (peer)
		io_wake(peer);

	return daemon_conn_read_next(conn, &daemon->master);
}

static struct io_plan *get_peers(struct io_conn *conn,
				 struct daemon *daemon, const u8 *msg)
{
	struct peer *peer;
	size_t n = 0;
	struct pubkey *id = tal_arr(conn, struct pubkey, n);
	struct wireaddr_internal *wireaddr = tal_arr(conn, struct wireaddr_internal, n);
	const struct gossip_getnodes_entry **nodes;
	struct pubkey *specific_id = NULL;
	struct node_map_iter it;

	if (!fromwire_gossip_getpeers_request(msg, msg, &specific_id))
		master_badmsg(WIRE_GOSSIPCTL_PEER_ADDRHINT, msg);

	nodes = tal_arr(conn, const struct gossip_getnodes_entry*, 0);
	list_for_each(&daemon->peers, peer, list) {
		if (specific_id && !pubkey_eq(specific_id, &peer->id))
			continue;
		tal_resize(&id, n+1);
		tal_resize(&wireaddr, n+1);

		id[n] = peer->id;
		wireaddr[n] = peer->addr;

		struct node* nd = NULL;
		for (nd = node_map_first(daemon->rstate->nodes, &it); nd; nd = node_map_next(daemon->rstate->nodes, &it)) {
			if (pubkey_eq(&nd->id, &peer->id)) {
				append_node(&nodes, nd);
				break;
			}
		}
		n++;
	}

	daemon_conn_send(&daemon->master,
			 take(towire_gossip_getpeers_reply(NULL, id, wireaddr, nodes)));
	return daemon_conn_read_next(conn, &daemon->master);
}

static struct io_plan *handle_txout_reply(struct io_conn *conn,
					  struct daemon *daemon, const u8 *msg)
{
	struct short_channel_id scid;
	u8 *outscript;
	u64 satoshis;

	if (!fromwire_gossip_get_txout_reply(msg, msg, &scid, &satoshis, &outscript))
		master_badmsg(WIRE_GOSSIP_GET_TXOUT_REPLY, msg);

	if (handle_pending_cannouncement(daemon->rstate, &scid, satoshis, outscript))
		send_node_announcement(daemon);

	return daemon_conn_read_next(conn, &daemon->master);
}

static struct io_plan *handle_disable_channel(struct io_conn *conn,
					      struct daemon *daemon, u8 *msg)
{
	struct short_channel_id scid;
	u8 direction;
	struct chan *chan;
	struct half_chan *hc;
	bool active;
	u16 flags, cltv_expiry_delta;
	u32 timestamp, fee_base_msat, fee_proportional_millionths;
	struct bitcoin_blkid chain_hash;
	secp256k1_ecdsa_signature sig;
	u64 htlc_minimum_msat;
	u8 *err;
	const u8 *old_update;

	if (!fromwire_gossip_disable_channel(msg, &scid, &direction, &active) ) {
		status_unusual("Unable to parse %s",
			      gossip_wire_type_name(fromwire_peektype(msg)));
		goto fail;
	}

	chan = get_channel(daemon->rstate, &scid);
	if (!chan) {
		status_trace(
		    "Unable to find channel %s",
		    type_to_string(msg, struct short_channel_id, &scid));
		goto fail;
	}
	hc = &chan->half[direction];

	status_trace("Disabling channel %s/%d, active %d -> %d",
		     type_to_string(msg, struct short_channel_id, &scid),
		     direction, hc->active, active);

	hc->active = active;

	if (!hc->channel_update_msgidx) {
		status_trace(
		    "Channel %s/%d doesn't have a channel_update yet, can't "
		    "disable",
		    type_to_string(msg, struct short_channel_id, &scid),
		    direction);
		goto fail;
	}

	old_update = get_broadcast(daemon->rstate->broadcasts,
				   hc->channel_update_msgidx);

	if (!fromwire_channel_update(
		old_update, &sig, &chain_hash, &scid, &timestamp,
		&flags, &cltv_expiry_delta, &htlc_minimum_msat, &fee_base_msat,
		&fee_proportional_millionths)) {
		status_failed(
		    STATUS_FAIL_INTERNAL_ERROR,
		    "Unable to parse previously accepted channel_update");
	}

	timestamp = time_now().ts.tv_sec;
	if (timestamp <= hc->last_timestamp)
		timestamp = hc->last_timestamp + 1;

	/* Active is bit 1 << 1, mask and apply */
	flags = (0xFFFD & flags) | (!active << 1);

	msg = towire_channel_update(tmpctx, &sig, &chain_hash, &scid, timestamp,
				    flags, cltv_expiry_delta, htlc_minimum_msat,
				    fee_base_msat, fee_proportional_millionths);

	if (!wire_sync_write(HSM_FD,
			     towire_hsm_cupdate_sig_req(tmpctx, msg))) {
		status_failed(STATUS_FAIL_HSM_IO, "Writing cupdate_sig_req: %s",
			      strerror(errno));
	}

	msg = wire_sync_read(tmpctx, HSM_FD);
	if (!msg || !fromwire_hsm_cupdate_sig_reply(tmpctx, msg, &msg)) {
		status_failed(STATUS_FAIL_HSM_IO,
			      "Reading cupdate_sig_req: %s",
			      strerror(errno));
	}

	err = handle_channel_update(daemon->rstate, msg);
	if (err)
		status_failed(STATUS_FAIL_INTERNAL_ERROR,
			      "rejected disabling channel_update: %s",
			      tal_hex(tmpctx, err));

fail:
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

static struct io_plan *recv_req(struct io_conn *conn, struct daemon_conn *master)
{
	struct daemon *daemon = container_of(master, struct daemon, master);
	enum gossip_wire_type t = fromwire_peektype(master->msg_in);

	switch (t) {
	case WIRE_GOSSIPCTL_INIT:
		return gossip_init(master, daemon, master->msg_in);

	case WIRE_GOSSIPCTL_ACTIVATE:
		return gossip_activate(master, daemon, master->msg_in);

	case WIRE_GOSSIPCTL_RELEASE_PEER:
		return release_peer(conn, daemon, master->msg_in);

	case WIRE_GOSSIP_GETNODES_REQUEST:
		return getnodes(conn, daemon, daemon->master.msg_in);

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

	case WIRE_GOSSIPCTL_CONNECT_TO_PEER:
		return connect_to_peer(conn, daemon, master->msg_in);

	case WIRE_GOSSIPCTL_PEER_ADDRHINT:
		return addr_hint(conn, daemon, master->msg_in);

	case WIRE_GOSSIPCTL_PEER_IMPORTANT:
		return peer_important(conn, daemon, master->msg_in);

	case WIRE_GOSSIPCTL_PEER_DISCONNECTED:
		return peer_disconnected(conn, daemon, master->msg_in);

	case WIRE_GOSSIP_GETPEERS_REQUEST:
		return get_peers(conn, daemon, master->msg_in);

	case WIRE_GOSSIP_GET_TXOUT_REPLY:
		return handle_txout_reply(conn, daemon, master->msg_in);

	case WIRE_GOSSIP_DISABLE_CHANNEL:
		return handle_disable_channel(conn, daemon, master->msg_in);

	case WIRE_GOSSIP_ROUTING_FAILURE:
		return handle_routing_failure(conn, daemon, master->msg_in);

	case WIRE_GOSSIP_MARK_CHANNEL_UNROUTABLE:
		return handle_mark_channel_unroutable(conn, daemon, master->msg_in);

	case WIRE_GOSSIPCTL_PEER_DISCONNECT:
		return disconnect_peer(conn, daemon, master->msg_in);

	case WIRE_GOSSIP_OUTPOINT_SPENT:
		return handle_outpoint_spent(conn, daemon, master->msg_in);

	/* We send these, we don't receive them */
	case WIRE_GOSSIPCTL_ACTIVATE_REPLY:
	case WIRE_GOSSIPCTL_RELEASE_PEER_REPLY:
	case WIRE_GOSSIPCTL_RELEASE_PEER_REPLYFAIL:
	case WIRE_GOSSIP_GETNODES_REPLY:
	case WIRE_GOSSIP_GETROUTE_REPLY:
	case WIRE_GOSSIP_GETCHANNELS_REPLY:
	case WIRE_GOSSIP_GETPEERS_REPLY:
	case WIRE_GOSSIP_PING_REPLY:
	case WIRE_GOSSIP_RESOLVE_CHANNEL_REPLY:
	case WIRE_GOSSIP_PEER_CONNECTED:
	case WIRE_GOSSIPCTL_CONNECT_TO_PEER_RESULT:
	case WIRE_GOSSIP_PEER_NONGOSSIP:
	case WIRE_GOSSIP_GET_UPDATE:
	case WIRE_GOSSIP_GET_UPDATE_REPLY:
	case WIRE_GOSSIP_SEND_GOSSIP:
	case WIRE_GOSSIP_LOCAL_ADD_CHANNEL:
	case WIRE_GOSSIP_GET_TXOUT:
	case WIRE_GOSSIPCTL_PEER_DISCONNECT_REPLY:
	case WIRE_GOSSIPCTL_PEER_DISCONNECT_REPLYFAIL:
		break;
	}

	/* Master shouldn't give bad requests. */
	status_failed(STATUS_FAIL_MASTER_IO, "%i: %s",
		      t, tal_hex(tmpctx, master->msg_in));
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
	list_head_init(&daemon->reconnecting);
	list_head_init(&daemon->reaching);
	list_head_init(&daemon->addrhints);
	important_peerid_map_init(&daemon->important_peerids);
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
	daemon_shutdown();
	return 0;
}
#endif
