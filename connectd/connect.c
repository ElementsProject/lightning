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
#include <connectd/connect.h>
#include <connectd/gen_connect_gossip_wire.h>
#include <connectd/gen_connect_wire.h>
#include <connectd/handshake.h>
#include <connectd/netaddress.h>
#include <connectd/tor.h>
#include <connectd/tor_autoservice.h>
#include <errno.h>
#include <gossipd/gen_gossip_wire.h>
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
#include <wire/peer_wire.h>
#include <wire/wire_io.h>
#include <wire/wire_sync.h>
#include <zlib.h>

#define CONNECT_MAX_REACH_ATTEMPTS 10

#define HSM_FD 3
#define GOSSIPCTL_FD 4

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

	/* Hacky list of known address hints. */
	struct list_head addrhints;

	struct timers timers;

	/* Important peers */
	struct important_peerid_map important_peerids;

	/* Local and global features to offer to peers. */
	u8 *localfeatures, *globalfeatures;

	/* Addresses master told us to use */
	struct wireaddr_internal *proposed_wireaddr;
	enum addr_listen_announce *proposed_listen_announce;

	/* What we actually announce. */
	struct wireaddr *announcable;

	/* Automatically reconnect. */
	bool reconnect;

	/* Allow localhost to be considered "public" */
	bool dev_allow_localhost;

	struct addrinfo *proxyaddr;
	bool use_proxy_always;
	char *tor_password;

	/* @see lightningd.config.use_dns */
	bool use_dns;

	/* The address that the broken response returns instead of
	 * NXDOMAIN. NULL if we have not detected a broken resolver. */
	struct sockaddr *broken_resolver_response;

	/* File descriptors to listen on once we're activated. */
	int *listen_fds;
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

	/* File descriptor for talking to gossipd. */
	int gossip_fd;

	/* Our connection (and owner) */
	struct io_conn *conn;

	/* Gossipd connection */
	struct daemon_conn gossip_conn;

	/* Waiting to send_peer_with_fds to master? */
	bool return_to_master;

	/* If we're exiting due to non-gossip msg, otherwise release */
	u8 *nongossip_msg;

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

	/* Non-NULL if we're talking to peer */
	struct local_peer_state *local;
};

struct addrhint {
	/* Off ld->addrhints */
	struct list_node list;

	struct pubkey id;
	/* FIXME: use array... */
	struct wireaddr_internal addr;
};

/* FIXME: Reorder */
static void send_peer_with_fds(struct peer *peer, const u8 *msg);
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
	msg_queue_init(&lps->peer_out, lps);

	return lps;
}

/**
 * Some ISP resolvers will reply with a dummy IP to queries that would otherwise
 * result in an NXDOMAIN reply. This just checks whether we have one such
 * resolver upstream and remembers its reply so we can try to filter future
 * dummies out.
 */
static bool broken_resolver(struct daemon *daemon)
{
	struct addrinfo *addrinfo;
	struct addrinfo hints;
	char *hostname = "nxdomain-test.doesntexist";
	int err;
	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_protocol = 0;
	hints.ai_flags = AI_ADDRCONFIG;
	err = getaddrinfo(hostname, tal_fmt(tmpctx, "%d", 42),
			      &hints, &addrinfo);

	daemon->broken_resolver_response =
	    tal_free(daemon->broken_resolver_response);

	if (err == 0) {
		daemon->broken_resolver_response = tal_dup(daemon, struct sockaddr, addrinfo->ai_addr);
		freeaddrinfo(addrinfo);
	}

	return 	daemon->broken_resolver_response != NULL;
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
		msg = towire_connectctl_connect_to_peer_result(NULL, &r->id,
							      true, "");
		daemon_conn_send(&peer->daemon->master, take(msg));
	}

	tal_free(r);
}

static void queue_peer_msg(struct peer *peer, const u8 *msg TAKES)
{
	if (peer->local) {
		msg_enqueue(&peer->local->peer_out, msg);
	} else { /* Waiting to die. */
		if (taken(msg))
			tal_free(msg);
	}
}

static int get_gossipfd(struct peer *peer)
{
	bool gossip_queries_feature, initial_routing_sync, success;
	u8 *msg;

	gossip_queries_feature
		= feature_offered(peer->lfeatures, LOCAL_GOSSIP_QUERIES)
		&& feature_offered(peer->daemon->localfeatures,
				   LOCAL_GOSSIP_QUERIES);
	initial_routing_sync
		= feature_offered(peer->lfeatures, LOCAL_INITIAL_ROUTING_SYNC);

	/* We do this communication sync. */
	msg = towire_gossip_new_peer(NULL, &peer->id, gossip_queries_feature,
				     initial_routing_sync);
	if (!wire_sync_write(GOSSIPCTL_FD, take(msg)))
		status_failed(STATUS_FAIL_INTERNAL_ERROR,
			      "Failed writing to gossipctl: %s",
			      strerror(errno));

	msg = wire_sync_read(peer, GOSSIPCTL_FD);
	if (!fromwire_gossip_new_peer_reply(msg, &success))
		status_failed(STATUS_FAIL_INTERNAL_ERROR,
			      "Failed parsing msg gossipctl: %s",
			      tal_hex(tmpctx, msg));
	if (!success) {
		status_broken("Gossipd did not give us an fd: losing peer %s",
			      type_to_string(tmpctx, struct pubkey, &peer->id));
		return -1;
	}
	return fdpass_recv(GOSSIPCTL_FD);
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
			/* Tell master to kill it: will send peer_disconnect */
			msg = towire_connect_reconnected(NULL, &peer->id);
			daemon_conn_send(&peer->daemon->master, take(msg));
			add_reconnecting_peer(peer->daemon, peer);
			return io_wait(conn, peer, retry_peer_connected, peer);
		}
		/* Local peers can just be discarded when they reconnect:
		 * closing conn will free peer. */
		io_close(old_peer->local->conn);
	}

	reached_peer(peer, conn);

	peer->local->gossip_fd = get_gossipfd(peer);
	if (peer->local->gossip_fd < 0)
		return io_close(conn);

	/* We will not have anything queued, since we're not duplex. */
	msg = towire_connect_peer_connected(peer, &peer->id, &peer->addr,
					   &peer->local->pcs.cs,
					   peer->gfeatures, peer->lfeatures);
	send_peer_with_fds(peer, msg);

	/* This is a full peer now; we keep it around until master says
	 * it's dead. */
	peer_finalized(peer);

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

	if (!features_supported(peer->gfeatures, peer->lfeatures)) {
		const u8 *global_features = get_offered_global_features(msg);
		const u8 *local_features = get_offered_local_features(msg);
		msg = towire_errorfmt(NULL, NULL, "Unsupported features %s/%s:"
				      " we only offer globalfeatures %s"
				      " and localfeatures %s",
				      tal_hex(msg, peer->gfeatures),
				      tal_hex(msg, peer->lfeatures),
				      tal_hexstr(msg,
						 global_features,
						 tal_count(global_features)),
				      tal_hexstr(msg,
						 local_features,
						 tal_count(local_features)));
		queue_peer_msg(peer, take(msg));

		/* Don't read any more */
		return io_wait(conn, peer, io_never, peer);
	}

	return peer_connected(conn, peer);
}

static struct io_plan *read_init(struct io_conn *conn, struct peer *peer)
{
	/* BOLT #1:
	 *
	 * The receiving node:
	 *  - MUST wait to receive `init` before sending any other messages.
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
	 * The sending node:
	 *   - MUST send `init` as the first Lightning message for any
	 *     connection.
	 */
	initmsg = towire_init(NULL,
			      daemon->globalfeatures, daemon->localfeatures);
	return peer_write_message(conn, &peer->local->pcs,
				  take(initmsg), read_init);
}

/* If master asks us to release peer, we attach this destructor in case it
 * dies while we're waiting for it to finish IO */
static void fail_release(struct peer *peer)
{
	u8 *msg = towire_connectctl_release_peer_replyfail(NULL);
	daemon_conn_send(&peer->daemon->master, take(msg));
}

static struct io_plan *ready_for_master(struct io_conn *conn, struct peer *peer)
{
	u8 *msg;
	if (peer->local->nongossip_msg)
		msg = towire_connect_peer_nongossip(peer, &peer->id,
						   &peer->addr,
						   &peer->local->pcs.cs,
						   peer->gfeatures,
						   peer->lfeatures,
						   peer->local->nongossip_msg);
	else
		msg = towire_connectctl_release_peer_reply(peer,
							  &peer->addr,
							  &peer->local->pcs.cs,
							  peer->gfeatures,
							  peer->lfeatures);

	/* FIXME: This can block (bad!) and anyway we can still have
	 * half-*read* gossip messages! */
	daemon_conn_sync_flush(&peer->local->gossip_conn);

	io_close_taken_fd(peer->local->gossip_conn.conn);
	send_peer_with_fds(peer, take(msg));
	/* In case we set this earlier. */
	tal_del_destructor(peer, fail_release);
	return io_close_taken_fd(conn);
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

	assert(peer->local);

	switch (t) {
	case WIRE_ERROR:
		status_trace("%s sent ERROR %s",
			     type_to_string(tmpctx, struct pubkey, &peer->id),
			     sanitize_error(tmpctx, msg, NULL));
		return io_close(conn);

	case WIRE_PING:
	case WIRE_PONG:
 	case WIRE_CHANNEL_ANNOUNCEMENT:
	case WIRE_NODE_ANNOUNCEMENT:
	case WIRE_CHANNEL_UPDATE:
	case WIRE_QUERY_SHORT_CHANNEL_IDS:
	case WIRE_REPLY_SHORT_CHANNEL_IDS_END:
	case WIRE_QUERY_CHANNEL_RANGE:
	case WIRE_REPLY_CHANNEL_RANGE:
	case WIRE_GOSSIP_TIMESTAMP_FILTER:
		daemon_conn_send(&peer->local->gossip_conn, msg);
		return peer_next_in(conn, peer);

	case WIRE_INIT:
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
		/* Not our place to handle this, so we punt */
		peer->local->return_to_master = true;
		peer->local->nongossip_msg = tal_steal(peer, msg);
		/* This will wait. */
		return peer_next_in(conn, peer);
	}

	/* BOLT #1:
	 *
	 * The type follows the _it's ok to be odd_ rule, so nodes MAY send
	 * _odd_-numbered types without ascertaining that the recipient
	 * understands it. */
	if (t & 1) {
		status_trace("Peer %s sent packet with unknown message type %u, ignoring",
			     type_to_string(tmpctx, struct pubkey, &peer->id), t);
	} else
		peer_error(peer, "Packet with unknown message type %u", t);

	return peer_next_in(conn, peer);
}

static struct io_plan *peer_pkt_out(struct io_conn *conn, struct peer *peer)
{
	/* First priority is queued packets, if any */
	const u8 *out;

	assert(peer->local);

	out = msg_dequeue(&peer->local->peer_out);
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
	}

	return msg_queue_wait(conn, &peer->local->peer_out, peer_pkt_out, peer);
}

/* Now we're a fully-fledged peer. */
static struct io_plan *peer_start_duplex(struct io_conn *conn, struct peer *peer)
{
	return io_duplex(conn,
			 peer_next_in(conn, peer),
			 peer_pkt_out(conn, peer));
}

static struct io_plan *recv_gossip(struct io_conn *conn,
				   struct daemon_conn *dc)
{
	struct peer *peer = dc->ctx;
	u8 *gossip;

	if (!fromwire_gossip_send_gossip(tmpctx, dc->msg_in, &gossip)) {
		status_broken("Got bad message for %s from gossipd: %s",
			      type_to_string(tmpctx, struct pubkey, &peer->id),
			      tal_hex(tmpctx, dc->msg_in));
		return io_close(conn);
	}

	/* Gossipd can send us gossip messages, OR errors */
	if (is_msg_for_gossipd(gossip)
	    || fromwire_peektype(gossip) == WIRE_ERROR) {
		queue_peer_msg(peer, take(gossip));
	} else {
		status_broken("Gossipd gave %s bad gossip message %s",
			      type_to_string(tmpctx, struct pubkey, &peer->id),
			      tal_hex(tmpctx, dc->msg_in));
		return io_close(conn);
	}

	return daemon_conn_read_next(conn, dc);
}

/* When a peer is to be owned by another daemon */
static void send_peer_with_fds(struct peer *peer, const u8 *msg)
{
	int peer_fd = peer->local->fd;
	int gossip_fd = peer->local->gossip_fd;

	/* Now we talk to socket to get to peer's owner daemon. */
	peer->local = tal_free(peer->local);

	/* Peer stays around, even though caller will close conn. */
	tal_steal(peer->daemon, peer);

	status_debug("peer %s now remote",
		     type_to_string(tmpctx, struct pubkey, &peer->id));

	daemon_conn_send(&peer->daemon->master, msg);
	daemon_conn_send_fd(&peer->daemon->master, peer_fd);
	daemon_conn_send_fd(&peer->daemon->master, gossip_fd);
}

static struct io_plan *new_peer_got_fd(struct io_conn *conn, struct peer *peer)
{
	struct daemon *daemon = peer->daemon;

	peer->local->conn = io_new_conn(conn, peer->local->fd,
					peer_start_duplex, peer);
	if (!peer->local->conn) {
		status_trace("Could not create connection for peer: %s",
			     strerror(errno));
		tal_free(peer);
	} else {
		/* If conn dies, we forget peer. */
		tal_steal(peer->local->conn, peer);
	}
	return daemon_conn_read_next(conn, &daemon->master);
}

/* This lets us read the fds in before handling anything. */
struct returning_peer {
	struct daemon *daemon;
	struct pubkey id;
	struct crypto_state cs;
	u8 *inner_msg;
	int peer_fd, gossip_fd;
};

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

	peer->local = new_local_peer_state(peer, &rpeer->cs);
	peer->local->fd = rpeer->peer_fd;
	peer->local->gossip_fd = rpeer->gossip_fd;
	daemon_conn_init(peer, &peer->local->gossip_conn, peer->local->gossip_fd,
			 recv_gossip, NULL);

	/* If they told us to send a message, queue it now */
	if (tal_count(rpeer->inner_msg))
		msg_enqueue(&peer->local->peer_out, take(rpeer->inner_msg));

	/* FIXME: rpeer destructor should close peer_fd, gossip_fd */
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
	if (!fromwire_connectctl_hand_back_peer(msg, msg,
					       &rpeer->id, &rpeer->cs,
					       &rpeer->inner_msg))
		master_badmsg(WIRE_CONNECTCTL_HAND_BACK_PEER, msg);

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

	if (!fromwire_connectctl_peer_disconnect(msg, &id))
		master_badmsg(WIRE_CONNECTCTL_PEER_DISCONNECT, msg);

	peer = find_peer(daemon, &id);
	if (peer && peer->local) {
		/* This peer is local to this (connectd) daemon */
		io_close(peer->local->conn);
		msg = towire_connectctl_peer_disconnect_reply(NULL);
		daemon_conn_send(&daemon->master, take(msg));
	} else {
		status_trace("disconnect_peer: peer %s %s",
			     type_to_string(tmpctx, struct pubkey, &id),
			     !peer ? "not connected" : "not gossiping");
		msg = towire_connectctl_peer_disconnect_replyfail(NULL, peer ? true : false);
		daemon_conn_send(&daemon->master, take(msg));
	}
	return daemon_conn_read_next(conn, &daemon->master);
}

static struct io_plan *release_peer(struct io_conn *conn, struct daemon *daemon,
				    const u8 *msg)
{
	struct pubkey id;
 	struct peer *peer;

	if (!fromwire_connectctl_release_peer(msg, &id))
		master_badmsg(WIRE_CONNECTCTL_RELEASE_PEER, msg);

	peer = find_peer(daemon, &id);
	if (!peer || !peer->local || peer->local->return_to_master) {
		/* This can happen with dying peers, or reconnect */
		status_trace("release_peer: peer %s %s",
			     type_to_string(tmpctx, struct pubkey, &id),
			     !peer ? "not found"
			     : peer->local ? "already releasing"
			     : "not local");
		msg = towire_connectctl_release_peer_replyfail(NULL);
		daemon_conn_send(&daemon->master, take(msg));
	} else {
		peer->local->return_to_master = true;
		peer->local->nongossip_msg = NULL;

		/* Wake output, in case it's idle. */
		msg_wake(&peer->local->peer_out);
	}
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

	return fd;

fail:
	close_noerr(fd);
	return -1;
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

static void add_listen_fd(struct daemon *daemon, int fd)
{
	size_t n = tal_count(daemon->listen_fds);
	tal_resize(&daemon->listen_fds, n+1);
	daemon->listen_fds[n] = fd;
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
			add_listen_fd(daemon, fd);
			return true;
		}
		return false;
	case ADDR_TYPE_IPV6:
		wireaddr_to_ipv6(wireaddr, &addr6);
		fd = make_listen_fd(AF_INET6, &addr6, sizeof(addr6), mayfail);
		if (fd >= 0) {
			status_trace("Created IPv6 listener on port %u",
				     wireaddr->port);
			add_listen_fd(daemon, fd);
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

	return address_routable(wireaddr, daemon->dev_allow_localhost);
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

static int wireaddr_cmp_type(const struct wireaddr *a,
			     const struct wireaddr *b, void *unused)
{
	return (int)a->type - (int)b->type;
}

static void finalize_announcable(struct daemon *daemon)
{
	size_t n = tal_count(daemon->announcable);

	/* BOLT #7:
	 *
	 * The origin node:
	 *...
	 *   - MUST place non-zero typed address descriptors in ascending order.
	 *...
	 *   - MUST NOT include more than one `address descriptor` of the same
	 *     type.
	 */
	asort(daemon->announcable, n, wireaddr_cmp_type, NULL);
	for (size_t i = 1; i < n; i++) {
		/* Note we use > instead of !=: catches asort bugs too. */
		if (daemon->announcable[i].type > daemon->announcable[i-1].type)
			continue;

		status_unusual("WARNING: Cannot announce address %s,"
			       " already announcing %s",
			       type_to_string(tmpctx, struct wireaddr,
					      &daemon->announcable[i]),
			       type_to_string(tmpctx, struct wireaddr,
					      &daemon->announcable[i-1]));
		memmove(daemon->announcable + i,
			daemon->announcable + i + 1,
			(n - i - 1) * sizeof(daemon->announcable[0]));
		tal_resize(&daemon->announcable, --n);
		--i;
	}
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

	/* Add addresses we've explicitly been told to *first*: implicit
	 * addresses will be discarded then if we have multiple. */
	for (size_t i = 0; i < tal_count(daemon->proposed_wireaddr); i++) {
		struct wireaddr_internal wa = daemon->proposed_wireaddr[i];

		if (daemon->proposed_listen_announce[i] & ADDR_LISTEN)
			continue;

		assert(daemon->proposed_listen_announce[i] & ADDR_ANNOUNCE);
		/* You can only announce wiretypes! */
		assert(daemon->proposed_wireaddr[i].itype
		       == ADDR_INTERNAL_WIREADDR);
		add_announcable(daemon, &wa.u.wireaddr);
	}

	/* Now look for listening addresses. */
	for (size_t i = 0; i < tal_count(daemon->proposed_wireaddr); i++) {
		struct wireaddr_internal wa = daemon->proposed_wireaddr[i];
		bool announce = (daemon->proposed_listen_announce[i]
				 & ADDR_ANNOUNCE);

		if (!(daemon->proposed_listen_announce[i] & ADDR_LISTEN))
			continue;

		switch (wa.itype) {
		case ADDR_INTERNAL_SOCKNAME:
			addrun.sun_family = AF_UNIX;
			memcpy(addrun.sun_path, wa.u.sockname,
			       sizeof(addrun.sun_path));
			fd = make_listen_fd(AF_INET, &addrun, sizeof(addrun),
					    false);
			status_trace("Created socket listener on file %s",
				     addrun.sun_path);
			add_listen_fd(daemon, fd);
			/* We don't announce socket names */
			assert(!announce);
			add_binding(&binding, &wa);
			continue;
		case ADDR_INTERNAL_AUTOTOR:
			/* We handle these after we have all bindings. */
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
				if (announce
				    && public_address(daemon, &wa.u.wireaddr))
					add_announcable(daemon, &wa.u.wireaddr);
			}
			wa.u.wireaddr.type = ADDR_TYPE_IPV4;
			wa.u.wireaddr.addrlen = 4;
			/* OK if this fails, as long as one succeeds! */
			if (handle_wireaddr_listen(daemon, &wa.u.wireaddr,
						   ipv6_ok)) {
				add_binding(&binding, &wa);
				if (announce
				    && public_address(daemon, &wa.u.wireaddr))
					add_announcable(daemon, &wa.u.wireaddr);
			}
			continue;
		}
		case ADDR_INTERNAL_WIREADDR:
			handle_wireaddr_listen(daemon, &wa.u.wireaddr, false);
			add_binding(&binding, &wa);
			if (announce && public_address(daemon, &wa.u.wireaddr))
				add_announcable(daemon, &wa.u.wireaddr);
			continue;
		case ADDR_INTERNAL_FORPROXY:
			break;
		}
		/* Shouldn't happen. */
		status_failed(STATUS_FAIL_INTERNAL_ERROR,
			      "Invalid listener address type %u",
			      daemon->proposed_wireaddr[i].itype);
	}

	/* Now we have bindings, set up any Tor auto addresses */
	for (size_t i = 0; i < tal_count(daemon->proposed_wireaddr); i++) {
		if (!(daemon->proposed_listen_announce[i] & ADDR_LISTEN))
			continue;

		if (!(daemon->proposed_listen_announce[i] & ADDR_ANNOUNCE))
			continue;

		if (daemon->proposed_wireaddr[i].itype != ADDR_INTERNAL_AUTOTOR)
			continue;

		add_announcable(daemon,
				tor_autoservice(tmpctx,
						&daemon->proposed_wireaddr[i].u.torservice,
						daemon->tor_password,
						binding));
	}

	finalize_announcable(daemon);

	return binding;
}


/* Parse an incoming connect init message and assign config variables
 * to the daemon.
 */
static struct io_plan *connect_init(struct daemon_conn *master,
				   struct daemon *daemon,
				   const u8 *msg)
{
	struct wireaddr *proxyaddr;
	struct wireaddr_internal *binding;

	if (!fromwire_connectctl_init(
		daemon, msg,
		&daemon->id, &daemon->globalfeatures,
		&daemon->localfeatures, &daemon->proposed_wireaddr,
		&daemon->proposed_listen_announce, &daemon->reconnect,
		&proxyaddr, &daemon->use_proxy_always,
		&daemon->dev_allow_localhost, &daemon->use_dns,
		&daemon->tor_password)) {
		master_badmsg(WIRE_CONNECTCTL_INIT, msg);
	}

	/* Resolve Tor proxy address if any */
	if (proxyaddr) {
		status_trace("Proxy address: %s",
			     fmt_wireaddr(tmpctx, proxyaddr));
		daemon->proxyaddr = wireaddr_to_addrinfo(daemon, proxyaddr);
	} else
		daemon->proxyaddr = NULL;

	if (broken_resolver(daemon)) {
		status_trace("Broken DNS resolver detected, will check for "
			     "dummy replies");
	}

	binding = setup_listeners(tmpctx, daemon);

	daemon_conn_send(&daemon->master,
			 take(towire_connectctl_init_reply(NULL,
							   binding,
							   daemon->announcable)));

	return daemon_conn_read_next(master->conn, master);
}

static struct io_plan *connect_activate(struct daemon_conn *master,
				       struct daemon *daemon,
				       const u8 *msg)
{
	bool do_listen;

	if (!fromwire_connectctl_activate(msg, &do_listen))
		master_badmsg(WIRE_CONNECTCTL_ACTIVATE, msg);

	if (do_listen) {
		for (size_t i = 0; i < tal_count(daemon->listen_fds); i++) {
			if (listen(daemon->listen_fds[i], 5) != 0)
				status_failed(STATUS_FAIL_INTERNAL_ERROR,
					      "Failed to listen on socket: %s",
					      strerror(errno));
			io_new_listener(daemon, daemon->listen_fds[i],
					connection_in, daemon);
		}
	}
	daemon->listen_fds = tal_free(daemon->listen_fds);

	/* OK, we're ready! */
	daemon_conn_send(&daemon->master,
			 take(towire_connectctl_activate_reply(NULL)));
	return daemon_conn_read_next(master->conn, master);
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
		msg = towire_connectctl_connect_to_peer_result(NULL, &reach->id,
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
}

static struct io_plan *conn_init(struct io_conn *conn, struct reaching *reach)
{
	struct addrinfo *ai = NULL;

	switch (reach->addr.itype) {
	case ADDR_INTERNAL_SOCKNAME:
		ai = wireaddr_internal_to_addrinfo(tmpctx, &reach->addr);
		break;
	case ADDR_INTERNAL_ALLPROTO:
		status_failed(STATUS_FAIL_INTERNAL_ERROR,
			      "Can't reach to all protocols");
		break;
	case ADDR_INTERNAL_AUTOTOR:
		status_failed(STATUS_FAIL_INTERNAL_ERROR,
			      "Can't reach to autotor address");
		break;
	case ADDR_INTERNAL_FORPROXY:
		status_failed(STATUS_FAIL_INTERNAL_ERROR,
			      "Can't reach to forproxy address");
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

static struct io_plan *conn_proxy_init(struct io_conn *conn,
				       struct reaching *reach)
{
	char *host = NULL;
	u16 port;

	switch (reach->addr.itype) {
	case ADDR_INTERNAL_FORPROXY:
		host = reach->addr.u.unresolved.name;
		port = reach->addr.u.unresolved.port;
		break;
	case ADDR_INTERNAL_WIREADDR:
		host = fmt_wireaddr_without_port(tmpctx,
						 &reach->addr.u.wireaddr);
		port = reach->addr.u.wireaddr.port;
		break;
	case ADDR_INTERNAL_SOCKNAME:
	case ADDR_INTERNAL_ALLPROTO:
	case ADDR_INTERNAL_AUTOTOR:
		break;
	}

	if (!host)
		status_failed(STATUS_FAIL_INTERNAL_ERROR,
			      "Can't reach to %u address", reach->addr.itype);

	io_set_finish(conn, connect_failed, reach);
	return io_tor_connect(conn, reach->daemon->proxyaddr, host, port, reach);
}

static const char *seedname(const tal_t *ctx, const struct pubkey *id)
{
	char bech32[100];
	u8 der[PUBKEY_DER_LEN];
	u5 *data = tal_arr(ctx, u5, 0);

	pubkey_to_der(der, id);
	bech32_push_bits(&data, der, PUBKEY_DER_LEN*8);
	bech32_encode(bech32, "ln", data, tal_count(data), sizeof(bech32));
	return tal_fmt(ctx, "%s.lseed.bitcoinstats.com", bech32);
}

static struct wireaddr_internal *
seed_resolve_addr(const tal_t *ctx, const struct pubkey *id,
		  struct sockaddr *broken_reply)
{
	struct wireaddr_internal *a;
	const char *addr;

	addr = seedname(tmpctx, id);
	status_trace("Resolving %s", addr);

	a = tal(ctx, struct wireaddr_internal);
	a->itype = ADDR_INTERNAL_WIREADDR;
	if (!wireaddr_from_hostname(&a->u.wireaddr, addr, DEFAULT_PORT, NULL,
				    broken_reply, NULL)) {
		status_trace("Could not resolve %s", addr);
		return tal_free(a);
	} else {
		status_trace("Resolved %s to %s", addr,
			     type_to_string(ctx, struct wireaddr,
					    &a->u.wireaddr));
		return a;
	}
}

static struct wireaddr_internal *
gossip_resolve_addr(const tal_t *ctx, const struct pubkey *id)
{
	u8 *msg;
	struct wireaddr *addrs;
	struct wireaddr_internal *addr;

	msg = towire_gossip_get_addrs(NULL, id);
	if (!wire_sync_write(GOSSIPCTL_FD, take(msg)))
		status_failed(STATUS_FAIL_INTERNAL_ERROR,
			      "Failed writing to gossipctl: %s",
			      strerror(errno));

	msg = wire_sync_read(tmpctx, GOSSIPCTL_FD);
	if (!fromwire_gossip_get_addrs_reply(tmpctx, msg, &addrs))
		status_failed(STATUS_FAIL_INTERNAL_ERROR,
			      "Failed parsing get_addrs_reply gossipctl: %s",
			      tal_hex(tmpctx, msg));

	if (!addrs)
		return NULL;

	/* FIXME: Don't just take first address! */
	addr = tal(ctx, struct wireaddr_internal);
	addr->itype = ADDR_INTERNAL_WIREADDR;
	addr->u.wireaddr = addrs[0];

	return addr;
}

static void try_reach_peer(struct daemon *daemon, const struct pubkey *id,
			   bool master_needs_response)
{
	struct wireaddr_internal *a;
	struct addrhint *hint;
	int fd, af;
	struct reaching *reach;
	u8 *msg;
	bool use_proxy = daemon->use_proxy_always;
	struct peer *peer = find_peer(daemon, id);

	if (peer) {
		status_debug("try_reach_peer: have peer %s",
			     type_to_string(tmpctx, struct pubkey, id));
		if (master_needs_response) {
			msg = towire_connectctl_connect_to_peer_result(NULL, id,
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
		reach->master_needs_response = master_needs_response;
		return;
	}

	hint = find_addrhint(daemon, id);
	if (hint)
		a = &hint->addr;
	else
		a = NULL;

	if (!a)
		a = gossip_resolve_addr(tmpctx, id);

	if (!a) {
		/* Don't resolve via DNS seed if we're supposed to use proxy. */
		if (use_proxy) {
			a = tal(tmpctx, struct wireaddr_internal);
			wireaddr_from_unresolved(a, seedname(tmpctx, id),
						 DEFAULT_PORT);
		} else if (daemon->use_dns) {
			a = seed_resolve_addr(tmpctx, id,
					      daemon->broken_resolver_response);
		}
	}

	if (!a) {
		status_debug("No address known for %s, giving up",
			     type_to_string(tmpctx, struct pubkey, id));
		if (master_needs_response) {
			msg = towire_connectctl_connect_to_peer_result(NULL, id,
					      false,
					      "No address known, giving up");
			daemon_conn_send(&daemon->master, take(msg));
		}
		return;
	}

	/* Might not even be able to create eg. IPv6 sockets */
	af = -1;

	switch (a->itype) {
	case ADDR_INTERNAL_SOCKNAME:
		af = AF_LOCAL;
		/* Local sockets don't use tor proxy */
		use_proxy = false;
		break;
	case ADDR_INTERNAL_ALLPROTO:
		status_failed(STATUS_FAIL_INTERNAL_ERROR,
			      "Can't reach ALLPROTO");
	case ADDR_INTERNAL_AUTOTOR:
		status_failed(STATUS_FAIL_INTERNAL_ERROR,
			      "Can't reach AUTOTOR");
	case ADDR_INTERNAL_FORPROXY:
		use_proxy = true;
		break;
	case ADDR_INTERNAL_WIREADDR:
		switch (a->u.wireaddr.type) {
		case ADDR_TYPE_TOR_V2:
		case ADDR_TYPE_TOR_V3:
			use_proxy = true;
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

	/* If we have to use proxy but we don't have one, we fail. */
	if (use_proxy) {
		if (!daemon->proxyaddr) {
			status_debug("Need proxy");
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
			msg = towire_connectctl_connect_to_peer_result(NULL, id,
							      false, err);
			daemon_conn_send(&daemon->master, take(msg));
		}
		return;
	}

	/* Start connecting to it */
	reach = tal(daemon, struct reaching);
	reach->daemon = daemon;
	reach->id = *id;
	reach->addr = *a;
	reach->master_needs_response = master_needs_response;
	reach->connstate = "Connection establishment";
	list_add_tail(&daemon->reaching, &reach->list);
	tal_add_destructor(reach, destroy_reaching);

	if (use_proxy)
		io_new_conn(reach, fd, conn_proxy_init, reach);
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

	if (!fromwire_connectctl_connect_to_peer(msg, &id))
		master_badmsg(WIRE_CONNECTCTL_CONNECT_TO_PEER, msg);

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

	if (!fromwire_connectctl_peer_addrhint(msg, &a->id, &a->addr))
		master_badmsg(WIRE_CONNECTCTL_PEER_ADDRHINT, msg);

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

	if (!fromwire_connectctl_peer_important(msg, &id, &important))
		master_badmsg(WIRE_CONNECTCTL_PEER_IMPORTANT, msg);

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

	if (!fromwire_connectctl_peer_disconnected(msg, &id))
		master_badmsg(WIRE_CONNECTCTL_PEER_DISCONNECTED, msg);

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

static void append_peer_features(const struct peer_features ***pf,
				 const u8 *gfeatures,
				 const u8 *lfeatures)
{
	struct peer_features *new;
	size_t num_nodes = tal_count(*pf);

	new = tal(*pf, struct peer_features);
	new->global_features = tal_dup_arr(new, u8, gfeatures,
					   tal_count(gfeatures), 0);
	new->local_features = tal_dup_arr(new, u8, lfeatures,
					  tal_count(lfeatures), 0);
	tal_resize(pf, num_nodes + 1);
	(*pf)[num_nodes] = new;
}

static struct io_plan *get_peers(struct io_conn *conn,
				 struct daemon *daemon, const u8 *msg)
{
	struct peer *peer;
	size_t n = 0;
	struct pubkey *id = tal_arr(conn, struct pubkey, n);
	struct wireaddr_internal *wireaddr = tal_arr(conn, struct wireaddr_internal, n);
	const struct peer_features **pf = tal_arr(conn, const struct peer_features *, n);
	struct pubkey *specific_id;

	if (!fromwire_connect_getpeers_request(msg, msg, &specific_id))
		master_badmsg(WIRE_CONNECTCTL_PEER_ADDRHINT, msg);

	list_for_each(&daemon->peers, peer, list) {
		if (specific_id && !pubkey_eq(specific_id, &peer->id))
			continue;
		tal_resize(&id, n+1);
		tal_resize(&wireaddr, n+1);

		id[n] = peer->id;
		wireaddr[n] = peer->addr;
		append_peer_features(&pf, peer->gfeatures, peer->lfeatures);
		n++;
	}

	daemon_conn_send(&daemon->master,
			 take(towire_connect_getpeers_reply(NULL, id, wireaddr, pf)));
	return daemon_conn_read_next(conn, &daemon->master);
}


static struct io_plan *recv_req(struct io_conn *conn, struct daemon_conn *master)
{
	struct daemon *daemon = container_of(master, struct daemon, master);
	enum connect_wire_type t = fromwire_peektype(master->msg_in);

	switch (t) {
	case WIRE_CONNECTCTL_INIT:
		return connect_init(master, daemon, master->msg_in);

	case WIRE_CONNECTCTL_ACTIVATE:
		return connect_activate(master, daemon, master->msg_in);

	case WIRE_CONNECTCTL_RELEASE_PEER:
		return release_peer(conn, daemon, master->msg_in);

	case WIRE_CONNECTCTL_HAND_BACK_PEER:
		return hand_back_peer(conn, daemon, master->msg_in);

	case WIRE_CONNECTCTL_CONNECT_TO_PEER:
		return connect_to_peer(conn, daemon, master->msg_in);

	case WIRE_CONNECTCTL_PEER_ADDRHINT:
		return addr_hint(conn, daemon, master->msg_in);

	case WIRE_CONNECTCTL_PEER_IMPORTANT:
		return peer_important(conn, daemon, master->msg_in);

	case WIRE_CONNECTCTL_PEER_DISCONNECTED:
		return peer_disconnected(conn, daemon, master->msg_in);

	case WIRE_CONNECT_GETPEERS_REQUEST:
		return get_peers(conn, daemon, master->msg_in);

	case WIRE_CONNECTCTL_PEER_DISCONNECT:
		return disconnect_peer(conn, daemon, master->msg_in);

	/* We send these, we don't receive them */
	case WIRE_CONNECTCTL_INIT_REPLY:
	case WIRE_CONNECTCTL_ACTIVATE_REPLY:
	case WIRE_CONNECTCTL_RELEASE_PEER_REPLY:
	case WIRE_CONNECTCTL_RELEASE_PEER_REPLYFAIL:
	case WIRE_CONNECT_GETPEERS_REPLY:
	case WIRE_CONNECT_PEER_CONNECTED:
	case WIRE_CONNECTCTL_CONNECT_TO_PEER_RESULT:
	case WIRE_CONNECT_PEER_NONGOSSIP:
	case WIRE_CONNECTCTL_PEER_DISCONNECT_REPLY:
	case WIRE_CONNECTCTL_PEER_DISCONNECT_REPLYFAIL:
	case WIRE_CONNECT_RECONNECTED:
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
	daemon->broken_resolver_response = NULL;
	daemon->listen_fds = tal_arr(daemon, int, 0);
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
