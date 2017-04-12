#include <ccan/container_of/container_of.h>
#include <ccan/crypto/hkdf_sha256/hkdf_sha256.h>
#include <ccan/endian/endian.h>
#include <ccan/fdpass/fdpass.h>
#include <ccan/io/fdpass/fdpass.h>
#include <ccan/io/io.h>
#include <ccan/list/list.h>
#include <ccan/noerr/noerr.h>
#include <ccan/read_write_all/read_write_all.h>
#include <ccan/take/take.h>
#include <ccan/tal/str/str.h>
#include <daemon/broadcast.h>
#include <daemon/log.h>
#include <daemon/routing.h>
#include <daemon/timeout.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <lightningd/cryptomsg.h>
#include <lightningd/daemon_conn.h>
#include <lightningd/debug.h>
#include <lightningd/gossip/gen_gossip_wire.h>
#include <lightningd/gossip_msg.h>
#include <lightningd/ping.h>
#include <lightningd/status.h>
#include <secp256k1_ecdh.h>
#include <sodium/randombytes.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <utils.h>
#include <version.h>
#include <wire/gen_peer_wire.h>
#include <wire/wire_io.h>

struct daemon {
	struct list_head peers;

	/* Connection to main daemon. */
	struct daemon_conn master;

	/* Routing information */
	struct routing_state *rstate;

	struct timers timers;
};

struct peer {
	struct daemon *daemon;
	/* daemon->peers */
	struct list_node list;

	u64 unique_id;
	struct peer_crypto_state pcs;

	/* File descriptor corresponding to conn. */
	int fd;

	/* Our connection (and owner) */
	struct io_conn *conn;

	/* If this is non-NULL, it means we failed. */
	const char *error;

	/* High water mark for the staggered broadcast */
	u64 broadcast_index;

	/* Message queue for outgoing. */
	struct msg_queue peer_out;

	/* Is it time to continue the staggered broadcast? */
	bool gossip_sync;

	/* The peer owner will use this to talk to gossipd */
	struct daemon_conn owner_conn;

	/* How many pongs are we expecting? */
	size_t num_pings_outstanding;

	/* Are we the owner of the peer? */
	bool local;
};

static void wake_pkt_out(struct peer *peer);

static void destroy_peer(struct peer *peer)
{
	list_del_from(&peer->daemon->peers, &peer->list);
	if (peer->error) {
		u8 *msg = towire_gossipstatus_peer_bad_msg(peer,
							   peer->unique_id,
							   (u8 *)peer->error);
		daemon_conn_send(&peer->daemon->master, take(msg));
	}
}

static struct peer *setup_new_peer(struct daemon *daemon, const u8 *msg)
{
	struct peer *peer = tal(daemon, struct peer);

	init_peer_crypto_state(peer, &peer->pcs);
	if (!fromwire_gossipctl_new_peer(msg, NULL, &peer->unique_id,
					 &peer->pcs.cs))
		return tal_free(peer);
	peer->daemon = daemon;
	peer->error = NULL;
	peer->local = true;
	peer->num_pings_outstanding = 0;
	msg_queue_init(&peer->peer_out, peer);
	list_add_tail(&daemon->peers, &peer->list);
	tal_add_destructor(peer, destroy_peer);
	wake_pkt_out(peer);
	return peer;
}

static struct io_plan *owner_msg_in(struct io_conn *conn,
				    struct daemon_conn *dc);
static struct io_plan *nonlocal_dump_gossip(struct io_conn *conn,
					    struct daemon_conn *dc);

/* When a peer is to be owned by another daemon, we create a socket
 * pair to send/receive gossip from it */
static void send_peer_with_fds(struct peer *peer, const u8 *msg)
{
	int fds[2];
	u8 *out;

	if (socketpair(AF_LOCAL, SOCK_STREAM, 0, fds) != 0) {
		out = towire_gossipstatus_peer_failed(msg,
				peer->unique_id,
				(u8 *)tal_fmt(msg,
					      "Failed to create socketpair: %s",
					      strerror(errno)));
		daemon_conn_send(&peer->daemon->master, take(out));

		/* FIXME: Send error to peer? */
		/* Peer will be freed when caller closes conn. */
		return;
	}

	/* Now we talk to socket to get to peer's owner daemon. */
	peer->local = false;
	daemon_conn_init(peer, &peer->owner_conn, fds[0], owner_msg_in);
	peer->owner_conn.msg_queue_cleared_cb = nonlocal_dump_gossip;

	/* Peer stays around, even though we're going to free conn. */
	tal_steal(peer->daemon, peer);

	daemon_conn_send(&peer->daemon->master, msg);
	daemon_conn_send_fd(&peer->daemon->master, peer->fd);
	daemon_conn_send_fd(&peer->daemon->master, fds[1]);

	/* Don't get confused: we can't use this any more. */
	peer->fd = -1;
}

static void handle_gossip_msg(struct routing_state *rstate, u8 *msg)
{
	int t = fromwire_peektype(msg);
	switch(t) {
	case WIRE_CHANNEL_ANNOUNCEMENT:
		handle_channel_announcement(rstate, msg, tal_count(msg));
		break;

	case WIRE_NODE_ANNOUNCEMENT:
		handle_node_announcement(rstate, msg, tal_count(msg));
		break;

	case WIRE_CHANNEL_UPDATE:
		handle_channel_update(rstate, msg, tal_count(msg));
		break;
	}
}

static bool handle_ping(struct peer *peer, u8 *ping)
{
	u8 *pong;

	if (!check_ping_make_pong(peer, ping, &pong)) {
		peer->error = "Bad ping";
		return false;
	}

	if (pong)
		msg_enqueue(&peer->peer_out, take(pong));
	return true;
}

static bool handle_pong(struct peer *peer, const u8 *pong)
{
	u8 *ignored;

	status_trace("Got pong!");
	if (!fromwire_pong(pong, pong, NULL, &ignored)) {
		peer->error = "pad pong";
		return false;
	}

	if (!peer->num_pings_outstanding) {
		peer->error = "unexpected pong";
		return false;
	}

	peer->num_pings_outstanding--;
	daemon_conn_send(&peer->daemon->master,
			 take(towire_gossip_ping_reply(pong, tal_len(pong))));
	return true;
}

static struct io_plan *peer_msgin(struct io_conn *conn,
				  struct peer *peer, u8 *msg)
{
	u8 *s;
	enum wire_type t = fromwire_peektype(msg);

	switch (t) {
	case WIRE_ERROR:
		/* FIXME: Report error from msg. */
		peer->error = "ERROR message received";
		return io_close(conn);

	case WIRE_CHANNEL_ANNOUNCEMENT:
	case WIRE_NODE_ANNOUNCEMENT:
	case WIRE_CHANNEL_UPDATE:
		handle_gossip_msg(peer->daemon->rstate, msg);
		return peer_read_message(conn, &peer->pcs, peer_msgin);

	case WIRE_INIT:
		peer->error = "Duplicate INIT message received";
		return io_close(conn);

	case WIRE_PING:
		if (!handle_ping(peer, msg))
			return io_close(conn);
		return peer_read_message(conn, &peer->pcs, peer_msgin);

	case WIRE_PONG:
		if (!handle_pong(peer, msg))
			return io_close(conn);
		return peer_read_message(conn, &peer->pcs, peer_msgin);

	case WIRE_OPEN_CHANNEL:
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
		/* Not our place to handle this, so we punt */
		s = towire_gossipstatus_peer_nongossip(msg, peer->unique_id,
						       &peer->pcs.cs, msg);
		send_peer_with_fds(peer, take(s));
		return io_close_taken_fd(conn);
	}

	/* BOLT #1:
	 *
	 * The type follows the _it's ok to be odd_ rule, so nodes MAY send
	 * odd-numbered types without ascertaining that the recipient
	 * understands it. */
	if (t & 1) {
		status_trace("Peer %"PRIu64" sent unknown packet %u, ignoring",
			     peer->unique_id, t);
		return peer_read_message(conn, &peer->pcs, peer_msgin);
	}
	peer->error = tal_fmt(peer, "Unknown packet %u", t);
	return io_close(conn);
}

/* Wake up the outgoing direction of the connection and write any
 * queued messages. Needed since the `io_wake` method signature does
 * not allow us to specify it as the callback for `new_reltimer`, but
 * it allows us to set an additional flag for the routing dump..
 */
static void wake_pkt_out(struct peer *peer)
{
	peer->gossip_sync = true;
	new_reltimer(&peer->daemon->timers, peer, time_from_sec(30),
		     wake_pkt_out, peer);
	/* Notify the peer-write loop */
	msg_wake(&peer->peer_out);
	/* Notify the daemon_conn-write loop */
	msg_wake(&peer->owner_conn.out);
}

static struct io_plan *peer_pkt_out(struct io_conn *conn, struct peer *peer)
{
	/* First priority is queued packets, if any */
	const u8 *out = msg_dequeue(&peer->peer_out);
	if (out)
		return peer_write_message(conn, &peer->pcs, take(out),
					  peer_pkt_out);

	/* If we're supposed to be sending gossip, do so now. */
	if (peer->gossip_sync) {
		struct queued_message *next;

		next = next_broadcast_message(peer->daemon->rstate->broadcasts,
					      &peer->broadcast_index);

		if (next)
			return peer_write_message(conn, &peer->pcs,
						  next->payload, peer_pkt_out);

		/* Gossip is drained.  Wait for next timer. */
		peer->gossip_sync = false;
	}

	return msg_queue_wait(conn, &peer->peer_out, peer_pkt_out, peer);
}

static bool has_even_bit(const u8 *bitmap)
{
	size_t len = tal_count(bitmap);

	while (len) {
		if (*bitmap & 0xAA)
			return true;
		len--;
		bitmap++;
	}
	return false;
}

/**
 * owner_msg_in - Called by the `peer->owner_conn` upon receiving a
 * message
 */
static struct io_plan *owner_msg_in(struct io_conn *conn,
				    struct daemon_conn *dc)
{
	struct peer *peer = container_of(dc, struct peer, owner_conn);
	u8 *msg = dc->msg_in;

	int type = fromwire_peektype(msg);
	if (type == WIRE_CHANNEL_ANNOUNCEMENT || type == WIRE_CHANNEL_UPDATE ||
	    type == WIRE_NODE_ANNOUNCEMENT) {
		handle_gossip_msg(peer->daemon->rstate, dc->msg_in);
	}
	return daemon_conn_read_next(conn, dc);
}

/**
 * nonlocal_dump_gossip - catch the nonlocal peer up with the latest gossip.
 *
 * Registered as `msg_queue_cleared_cb` by the `peer->owner_conn`.
 */
static struct io_plan *nonlocal_dump_gossip(struct io_conn *conn, struct daemon_conn *dc)
{
	struct queued_message *next;
	struct peer *peer = container_of(dc, struct peer, owner_conn);


	/* Make sure we are not connected directly */
	if (peer->local)
		return io_out_wait(conn, peer, daemon_conn_write_next, dc);

	next = next_broadcast_message(peer->daemon->rstate->broadcasts,
				      &peer->broadcast_index);

	if (!next) {
		return io_out_wait(conn, peer, daemon_conn_write_next, dc);
	} else {
		return io_write_wire(conn, next->payload, nonlocal_dump_gossip, dc);
	}
}

static struct io_plan *peer_parse_init(struct io_conn *conn,
				       struct peer *peer, u8 *msg)
{
	u8 *gfeatures, *lfeatures;

	if (!fromwire_init(msg, msg, NULL, &gfeatures, &lfeatures)) {
		peer->error = tal_fmt(msg, "Bad init: %s", tal_hex(msg, msg));
		return io_close(conn);
	}

	/* BOLT #1:
	 *
	 * The receiving node MUST fail the channels if it receives a
	 * `globalfeatures` or `localfeatures` with an even bit set which it
	 * does not understand.
	 */
	if (has_even_bit(gfeatures)) {
		peer->error = tal_fmt(msg, "Bad globalfeatures: %s",
				      tal_hex(msg, gfeatures));
		return io_close(conn);
	}

	if (has_even_bit(lfeatures)) {
		peer->error = tal_fmt(msg, "Bad localfeatures: %s",
				      tal_hex(msg, lfeatures));
		return io_close(conn);
	}

	/* BOLT #1:
	 *
	 * Each node MUST wait to receive `init` before sending any other
	 * messages.
	 */
	daemon_conn_send(&peer->daemon->master,
			 take(towire_gossipstatus_peer_ready(msg,
							     peer->unique_id)));

	/* Need to go duplex here, otherwise backpressure would mean
	 * we both wait indefinitely */
	return io_duplex(conn,
			 peer_read_message(conn, &peer->pcs, peer_msgin),
			 peer_pkt_out(conn, peer));
}

static struct io_plan *peer_init_sent(struct io_conn *conn, struct peer *peer)
{
	return peer_read_message(conn, &peer->pcs, peer_parse_init);
}

static struct io_plan *peer_send_init(struct io_conn *conn, struct peer *peer)
{
	/* BOLT #1:
	 *
	 * The sending node SHOULD use the minimum lengths required to
	 * represent the feature fields.  The sending node MUST set feature
	 * bits corresponding to features it requires the peer to support, and
	 * SHOULD set feature bits corresponding to features it optionally
	 * supports.
	 */
	return peer_write_message(conn, &peer->pcs,
				  take(towire_init(peer, NULL, NULL)),
				  peer_init_sent);
}

static struct io_plan *new_peer_got_fd(struct io_conn *conn, struct peer *peer)
{
	peer->conn = io_new_conn(conn, peer->fd, peer_send_init, peer);
	if (!peer->conn) {
		peer->error = "Could not create connection";
		tal_free(peer);
	}
	return daemon_conn_read_next(conn,&peer->daemon->master);
}

static struct io_plan *new_peer(struct io_conn *conn, struct daemon *daemon,
				const u8 *msg)
{
	struct peer *peer = setup_new_peer(daemon, msg);
	if (!peer)
		status_failed(WIRE_GOSSIPSTATUS_BAD_NEW_PEER_REQUEST,
			      "%s", tal_hex(trc, msg));
	return io_recv_fd(conn, &peer->fd, new_peer_got_fd, peer);
}

static struct peer *find_peer(struct daemon *daemon, u64 unique_id)
{
	struct peer *peer;

	list_for_each(&daemon->peers, peer, list)
		if (peer->unique_id == unique_id)
			return peer;
	return NULL;
}

static struct io_plan *release_peer(struct io_conn *conn, struct daemon *daemon,
				    const u8 *msg)
{
	u64 unique_id;
	struct peer *peer;

	if (!fromwire_gossipctl_release_peer(msg, NULL, &unique_id))
		status_failed(WIRE_GOSSIPSTATUS_BAD_RELEASE_REQUEST,
			      "%s", tal_hex(trc, msg));

	peer = find_peer(daemon, unique_id);
	if (!peer)
		status_failed(WIRE_GOSSIPSTATUS_BAD_RELEASE_REQUEST,
			      "Unknown peer %"PRIu64, unique_id);

	send_peer_with_fds(peer,
			   take(towire_gossipctl_release_peer_reply(msg,
								unique_id,
								&peer->pcs.cs)));
	io_close_taken_fd(peer->conn);
	return daemon_conn_read_next(conn, &daemon->master);
}

static struct io_plan *getroute_req(struct io_conn *conn, struct daemon *daemon,
				    u8 *msg)
{
	tal_t *tmpctx = tal_tmpctx(msg);
	struct pubkey source, destination;
	u32 msatoshi;
	u16 riskfactor;
	u8 *out;
	struct route_hop *hops;

	fromwire_gossip_getroute_request(msg, NULL, &source, &destination,
					 &msatoshi, &riskfactor);
	status_trace("Trying to find a route from %s to %s for %d msatoshi",
		     pubkey_to_hexstr(tmpctx, &source),
		     pubkey_to_hexstr(tmpctx, &destination), msatoshi);

	hops = get_route(tmpctx, daemon->rstate, &source, &destination,
			 msatoshi, 1);

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
			entries[num_chans].delay = n->out[j]->delay;
			entries[num_chans].fee_per_kw = n->out[j]->proportional_fee;
			entries[num_chans].last_update_timestamp = n->out[j]->last_timestamp;
			entries[num_chans].flags = n->out[j]->flags;
			entries[num_chans].short_channel_id = n->out[j]->short_channel_id;
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
		nodes[node_count].hostname = n->hostname;
		nodes[node_count].port = n->port;
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
	u64 unique_id;
	u16 num_pong_bytes, len;
	struct peer *peer;
	u8 *ping;

	if (!fromwire_gossip_ping(msg, NULL, &unique_id, &num_pong_bytes, &len))
		status_failed(WIRE_GOSSIPSTATUS_BAD_REQUEST,
			      "%s", tal_hex(trc, msg));

	peer = find_peer(daemon, unique_id);
	if (!peer)
		status_failed(WIRE_GOSSIPSTATUS_BAD_REQUEST,
			      "Unknown peer %"PRIu64, unique_id);

	ping = make_ping(peer, num_pong_bytes, len);
	if (tal_len(ping) > 65535)
		status_failed(WIRE_GOSSIPSTATUS_BAD_REQUEST, "Oversize ping");

	msg_enqueue(&peer->peer_out, take(ping));
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
				 take(towire_gossip_ping_reply(peer, 0)));
	else
		peer->num_pings_outstanding++;
	return daemon_conn_read_next(conn, &daemon->master);
}

static struct io_plan *recv_req(struct io_conn *conn, struct daemon_conn *master)
{
	struct daemon *daemon = container_of(master, struct daemon, master);
	enum gossip_wire_type t = fromwire_peektype(master->msg_in);

	status_trace("req: type %s len %zu",
		     gossip_wire_type_name(t), tal_count(master->msg_in));

	switch (t) {
	case WIRE_GOSSIPCTL_NEW_PEER:
		return new_peer(conn, daemon, master->msg_in);
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

	case WIRE_GOSSIPCTL_RELEASE_PEER_REPLY:
	case WIRE_GOSSIP_GETNODES_REPLY:
	case WIRE_GOSSIP_GETROUTE_REPLY:
	case WIRE_GOSSIP_GETCHANNELS_REPLY:
	case WIRE_GOSSIP_PING_REPLY:
	case WIRE_GOSSIPSTATUS_INIT_FAILED:
	case WIRE_GOSSIPSTATUS_BAD_NEW_PEER_REQUEST:
	case WIRE_GOSSIPSTATUS_BAD_RELEASE_REQUEST:
	case WIRE_GOSSIPSTATUS_BAD_REQUEST:
	case WIRE_GOSSIPSTATUS_FDPASS_FAILED:
	case WIRE_GOSSIPSTATUS_PEER_BAD_MSG:
	case WIRE_GOSSIPSTATUS_PEER_FAILED:
	case WIRE_GOSSIPSTATUS_PEER_READY:
	case WIRE_GOSSIPSTATUS_PEER_NONGOSSIP:
		break;
	}

	/* Control shouldn't give bad requests. */
	status_failed(WIRE_GOSSIPSTATUS_BAD_REQUEST, "%i", t);
}

#ifndef TESTING
int main(int argc, char *argv[])
{
	struct daemon *daemon;
	struct log_book *log_book;
	struct log *base_log;

	subdaemon_debug(argc, argv);

	if (argc == 2 && streq(argv[1], "--version")) {
		printf("%s\n", version());
		exit(0);
	}

	secp256k1_ctx = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY |
						 SECP256K1_CONTEXT_SIGN);

	daemon = tal(NULL, struct daemon);
	/* Do not log absolutely anything, stdout is now a socket
	 * connected to some other daemon. */
	log_book = new_log_book(daemon, 2 * 1024 * 1024, LOG_BROKEN + 1);
	base_log =
	    new_log(daemon, log_book, "lightningd_gossip(%u):", (int)getpid());
	daemon->rstate = new_routing_state(daemon, base_log);
	list_head_init(&daemon->peers);
	timers_init(&daemon->timers, time_mono());

	/* stdin == control */
	daemon_conn_init(daemon, &daemon->master, STDIN_FILENO, recv_req);
	status_setup_async(&daemon->master);

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
