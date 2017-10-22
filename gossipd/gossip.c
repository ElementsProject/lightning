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
#include <ccan/take/take.h>
#include <ccan/tal/str/str.h>
#include <ccan/timer/timer.h>
#include <common/cryptomsg.h>
#include <common/daemon_conn.h>
#include <common/debug.h>
#include <common/io_debug.h>
#include <common/ping.h>
#include <common/status.h>
#include <common/timeout.h>
#include <common/type_to_string.h>
#include <common/utils.h>
#include <common/version.h>
#include <common/wire_error.h>
#include <errno.h>
#include <fcntl.h>
#include <gossipd/broadcast.h>
#include <gossipd/gen_gossip_wire.h>
#include <gossipd/handshake.h>
#include <gossipd/routing.h>
#include <hsmd/client.h>
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
};

/* Peers we're trying to reach. */
struct reaching {
	struct daemon *daemon;

	/* daemon->reaching */
	struct list_node list;

	/* The ID of the peer (not necessarily unique, in transit!) */
	struct pubkey id;

	/* Did we succeed? */
	bool succeeded;
};

struct peer {
	struct daemon *daemon;

	/* daemon->peers */
	struct list_node list;

	/* The ID of the peer (not necessarily unique, in transit!) */
	struct pubkey id;

	/* Feature bitmaps. */
	u8 *gfeatures, *lfeatures;

	/* Cryptostate */
	struct peer_crypto_state pcs;

	/* File descriptor corresponding to conn. */
	int fd;

	/* Our connection (and owner) */
	struct io_conn *conn;

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

	/* If we die, should we reach again? */
	bool reach_again;
};

struct addrhint {
	/* Off ld->addrhints */
	struct list_node list;

	struct pubkey id;
	/* FIXME: use array... */
	struct ipaddr addr;
};

/* FIXME: Reorder */
static struct io_plan *peer_start_gossip(struct io_conn *conn,
					 struct peer *peer);
static void send_peer_with_fds(struct peer *peer, const u8 *msg);
static void wake_pkt_out(struct peer *peer);
static void try_reach_peer(struct daemon *daemon, const struct pubkey *id);

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

static struct peer *new_peer(const tal_t *ctx,
			     struct daemon *daemon,
			     const struct pubkey *their_id,
			     const struct crypto_state *cs)
{
	struct peer *peer = tal(ctx, struct peer);

	init_peer_crypto_state(peer, &peer->pcs);
	peer->pcs.cs = *cs;
	peer->id = *their_id;
	peer->daemon = daemon;
	peer->local = true;
	peer->reach_again = false;
	peer->num_pings_outstanding = 0;
	peer->broadcast_index = 0;
	msg_queue_init(&peer->peer_out, peer);

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
	msg_enqueue(&peer->peer_out,
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

	msg = towire_gossip_peer_connected(peer, &peer->id, &peer->pcs.cs,
					   peer->gfeatures, peer->lfeatures);
	send_peer_with_fds(peer, msg);

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
	return peer_read_message(conn, &peer->pcs, peer_init_received);
}

/* This creates a temporary peer which is not in the list and is owner
 * by the connection; it's placed in the list and owned by daemon once
 * we have the features. */
static struct io_plan *init_new_peer(struct io_conn *conn,
				     const struct pubkey *their_id,
				     const struct crypto_state *cs,
				     struct daemon *daemon)
{
	struct peer *peer = new_peer(conn, daemon, their_id, cs);
	u8 *initmsg;

	peer->fd = io_conn_fd(conn);

	/* BOLT #1:
	 *
	 * Each node MUST send `init` as the first lightning message for any
	 * connection.
	 */
	initmsg = towire_init(peer,
			      daemon->globalfeatures, daemon->localfeatures);
	return peer_write_message(conn, &peer->pcs, take(initmsg), read_init);
}

static struct io_plan *owner_msg_in(struct io_conn *conn,
				    struct daemon_conn *dc);
static struct io_plan *nonlocal_dump_gossip(struct io_conn *conn,
					    struct daemon_conn *dc);

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

static void handle_ping(struct peer *peer, u8 *ping)
{
	u8 *pong;

	if (!check_ping_make_pong(peer, ping, &pong)) {
		peer_error(peer, "Bad ping");
		return;
	}

	if (pong)
		msg_enqueue(&peer->peer_out, take(pong));
}

static void handle_pong(struct peer *peer, const u8 *pong)
{
	u8 *ignored;

	status_trace("Got pong!");
	if (!fromwire_pong(pong, pong, NULL, &ignored)) {
		peer_error(peer, "Bad pong");
		return;
	}

	if (!peer->num_pings_outstanding) {
		peer_error(peer, "Unexpected pong");
		return;
	}

	peer->num_pings_outstanding--;
	daemon_conn_send(&peer->daemon->master,
			 take(towire_gossip_ping_reply(pong, true,
						       tal_len(pong))));
}

static struct io_plan *peer_msgin(struct io_conn *conn,
				  struct peer *peer, u8 *msg)
{
	u8 *s;
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
		handle_gossip_msg(peer->daemon->rstate, msg);
		return peer_read_message(conn, &peer->pcs, peer_msgin);

	case WIRE_PING:
		handle_ping(peer, msg);
		return peer_read_message(conn, &peer->pcs, peer_msgin);

	case WIRE_PONG:
		handle_pong(peer, msg);
		return peer_read_message(conn, &peer->pcs, peer_msgin);

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
		s = towire_gossip_peer_nongossip(msg, &peer->id,
						 &peer->pcs.cs,
						 peer->gfeatures,
						 peer->lfeatures,
						 msg);
		send_peer_with_fds(peer, take(s));
		return io_close_taken_fd(conn);
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

	return peer_read_message(conn, &peer->pcs, peer_msgin);
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
	/* Notify the peer-write loop */
	msg_wake(&peer->peer_out);
	/* Notify the daemon_conn-write loop */
	msg_wake(&peer->owner_conn.out);
}

static struct io_plan *peer_pkt_out(struct io_conn *conn, struct peer *peer)
{
	/* First priority is queued packets, if any */
	const u8 *out = msg_dequeue(&peer->peer_out);
	if (out) {
		if (is_all_channel_error(out))
			return peer_write_message(conn, &peer->pcs, take(out),
						  peer_close_after_error);
		return peer_write_message(conn, &peer->pcs, take(out),
					  peer_pkt_out);
	}

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

/* Now we're a fully-fledged peer. */
static struct io_plan *peer_start_gossip(struct io_conn *conn, struct peer *peer)
{
	wake_pkt_out(peer);
	return io_duplex(conn,
			 peer_read_message(conn, &peer->pcs, peer_msgin),
			 peer_pkt_out(conn, peer));
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
static void send_peer_with_fds(struct peer *peer, const u8 *msg)
{
	int fds[2];

	if (socketpair(AF_LOCAL, SOCK_STREAM, 0, fds) != 0) {
		status_trace("Failed to create socketpair: %s",
			     strerror(errno));

		/* FIXME: Send error to peer? */
		/* Peer will be freed when caller closes conn. */
		return;
	}

	/* Now we talk to socket to get to peer's owner daemon. */
	peer->local = false;

	daemon_conn_init(peer, &peer->owner_conn, fds[0],
			 owner_msg_in, forget_peer);
	peer->owner_conn.msg_queue_cleared_cb = nonlocal_dump_gossip;

	/* Peer stays around, even though caller will close conn. */
	tal_steal(peer->daemon, peer);

	daemon_conn_send(&peer->daemon->master, msg);
	daemon_conn_send_fd(&peer->daemon->master, peer->fd);
	daemon_conn_send_fd(&peer->daemon->master, fds[1]);

	/* Don't get confused: we can't use this any more. */
	peer->fd = -1;
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
		return msg_queue_wait(conn, &peer->owner_conn.out,
				      daemon_conn_write_next, dc);

	next = next_broadcast_message(peer->daemon->rstate->broadcasts,
				      &peer->broadcast_index);

	if (!next) {
		return msg_queue_wait(conn, &peer->owner_conn.out,
				      daemon_conn_write_next, dc);
	} else {
		return io_write_wire(conn, next->payload, nonlocal_dump_gossip, dc);
	}
}

static struct io_plan *new_peer_got_fd(struct io_conn *conn, struct peer *peer)
{
	peer->conn = io_new_conn(conn, peer->fd, peer_start_gossip, peer);
	if (!peer->conn) {
		status_trace("Could not create connection for peer: %s",
			     strerror(errno));
		tal_free(peer);
	} else {
		/* If conn dies, we forget peer. */
		tal_steal(peer->conn, peer);
	}
	return daemon_conn_read_next(conn, &peer->daemon->master);
}

/* Read and close fd */
static struct io_plan *discard_peer_fd(struct io_conn *conn, int *fd)
{
	struct daemon *daemon = tal_parent(fd);
	close(*fd);
	tal_free(fd);
	return daemon_conn_read_next(conn, &daemon->master);
}

static struct io_plan *handle_peer(struct io_conn *conn, struct daemon *daemon,
				   const u8 *msg)
{
	struct peer *peer;
	struct crypto_state cs;
	struct pubkey id;
	u8 *gfeatures, *lfeatures;
	u8 *inner_msg;

	if (!fromwire_gossipctl_handle_peer(msg, msg, NULL, &id, &cs,
					    &gfeatures, &lfeatures, &inner_msg))
		master_badmsg(WIRE_GOSSIPCTL_HANDLE_PEER, msg);

	/* If it already exists locally, that's probably a reconnect:
	 * drop this one.  If it exists as remote, replace with this.*/
	peer = find_peer(daemon, &id);
	if (peer) {
		if (peer->local) {
			int *fd = tal(daemon, int);
			status_trace("handle_peer %s: duplicate, dropping",
				     type_to_string(trc, struct pubkey, &id));
			return io_recv_fd(conn, fd, discard_peer_fd, fd);
		}
		status_trace("handle_peer %s: found remote duplicate, dropping",
			     type_to_string(trc, struct pubkey, &id));
		tal_free(peer);
	}

	status_trace("handle_peer %s: new peer",
		     type_to_string(trc, struct pubkey, &id));
	peer = new_peer(daemon, daemon, &id, &cs);
	peer->gfeatures = tal_steal(peer, gfeatures);
	peer->lfeatures = tal_steal(peer, lfeatures);
	peer_finalized(peer);

	if (tal_len(inner_msg))
		msg_enqueue(&peer->peer_out, take(inner_msg));

	return io_recv_fd(conn, &peer->fd, new_peer_got_fd, peer);
}

static struct io_plan *release_peer(struct io_conn *conn, struct daemon *daemon,
				    const u8 *msg)
 {
	struct pubkey id;
 	struct peer *peer;

	if (!fromwire_gossipctl_release_peer(msg, NULL, &id))
		master_badmsg(WIRE_GOSSIPCTL_RELEASE_PEER, msg);

	peer = find_peer(daemon, &id);
	if (!peer || !peer->local) {
		status_trace("release_peer: peer %s not %s",
			     type_to_string(trc, struct pubkey, &id),
			     peer ? "local" : "found");
		/* This can happen with dying peers, or reconnect */
		msg = towire_gossipctl_release_peer_replyfail(msg);
		daemon_conn_send(&daemon->master, take(msg));
	} else {
		msg = towire_gossipctl_release_peer_reply(msg,
							  &peer->pcs.cs,
							  peer->gfeatures,
							  peer->lfeatures);
		send_peer_with_fds(peer, take(msg));
		io_close_taken_fd(peer->conn);
	}
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
			entries[num_chans].flags = n->out[j]->flags;
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
				 take(towire_gossip_ping_reply(peer, true, 0)));
	else
		peer->num_pings_outstanding++;

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
	/* FIXME: Timeout */
	return responder_handshake(conn, &daemon->id, init_new_peer, daemon);
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
	struct sha256_double chain_hash;
	u16 port;

	if (!fromwire_gossipctl_init(daemon, msg, NULL,
				     &daemon->broadcast_interval,
				     &chain_hash, &daemon->id, &port,
				     &daemon->localfeatures,
				     &daemon->globalfeatures)) {
		master_badmsg(WIRE_GOSSIPCTL_INIT, msg);
	}
	daemon->rstate = new_routing_state(daemon, &chain_hash);

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

static void handle_forwarded_msg(struct io_conn *conn, struct daemon *daemon, const u8 *msg)
{
	u8 *payload;
	if (!fromwire_gossip_forwarded_msg(msg, msg, NULL, &payload))
		master_badmsg(WIRE_GOSSIP_FORWARDED_MSG, msg);

	handle_gossip_msg(daemon->rstate, payload);
}

static struct io_plan *handshake_out_success(struct io_conn *conn,
					     const struct pubkey *id,
					     const struct crypto_state *cs,
					     struct reaching *reach)
{
	return init_new_peer(conn, id, cs, reach->daemon);
}


static struct io_plan *connection_out(struct io_conn *conn,
				      struct reaching *reach)
{
	/* FIXME: Timeout */
	status_trace("Connected out for %s",
		     type_to_string(trc, struct pubkey, &reach->id));

	return initiator_handshake(conn, &reach->daemon->id, &reach->id,
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

struct reach_addr {
	struct reaching *reach;
	struct ipaddr addr;
};

static struct io_plan *conn_init(struct io_conn *conn, struct reach_addr *r)
{
	struct reaching *reach = r->reach;
	struct addrinfo ai;
	struct sockaddr_in sin;
	struct sockaddr_in6 sin6;

	/* FIXME: make generic */
	ai.ai_flags = 0;
	ai.ai_socktype = SOCK_STREAM;
	ai.ai_protocol = 0;
	ai.ai_canonname = NULL;
	ai.ai_next = NULL;

	switch (r->addr.type) {
	case ADDR_TYPE_IPV4:
		ai.ai_family = AF_INET;
		sin.sin_family = AF_INET;
		sin.sin_port = htons(r->addr.port);
		memcpy(&sin.sin_addr, r->addr.addr, sizeof(sin.sin_addr));
		ai.ai_addrlen = sizeof(sin);
		ai.ai_addr = (struct sockaddr *)&sin;
		break;
	case ADDR_TYPE_IPV6:
		ai.ai_family = AF_INET6;
		memset(&sin6, 0, sizeof(sin6));
		sin6.sin6_family = AF_INET6;
		sin6.sin6_port = htons(r->addr.port);
		memcpy(&sin6.sin6_addr, r->addr.addr, sizeof(sin6.sin6_addr));
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
	struct reach_addr r;
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

	r.reach = reach;
	r.addr = a->addr;
	io_new_conn(reach, fd, conn_init, &r);
}

static void try_reach_peer(struct daemon *daemon, const struct pubkey *id)
{
	struct reaching *reach;
	struct peer *peer;

	if (find_reaching(daemon, id)) {
		/* FIXME: Perhaps kick timer in this case? */
		status_trace("try_reach_peer: already reaching %s",
			     type_to_string(trc, struct pubkey, id));
		return;
	}

	/* Master might find out before we do that a peer is dead; if we
	 * seem to be connected just mark it for reconnect. */
	peer = find_peer(daemon, id);
	if (peer) {
		status_trace("reach_peer: have %s, will retry if it dies",
			     type_to_string(trc, struct pubkey, id));
		peer->reach_again = true;
		return;
	}

	reach = tal(daemon, struct reaching);
	reach->succeeded = false;
	reach->daemon = daemon;
	reach->id = *id;
	list_add_tail(&daemon->reaching, &reach->list);
	tal_add_destructor(reach, destroy_reaching);

	try_connect(reach);
}

/* This catches all kinds of failures, like network errors. */
static struct io_plan *reach_peer(struct io_conn *conn,
				  struct daemon *daemon, const u8 *msg)
{
	struct pubkey id;

	if (!fromwire_gossipctl_reach_peer(msg, NULL, &id))
		master_badmsg(WIRE_GOSSIPCTL_REACH_PEER, msg);

	try_reach_peer(daemon, &id);

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

	case WIRE_GOSSIP_FORWARDED_MSG:
		handle_forwarded_msg(conn, daemon, daemon->master.msg_in);
		return daemon_conn_read_next(conn, &daemon->master);

	case WIRE_GOSSIPCTL_HANDLE_PEER:
		return handle_peer(conn, daemon, master->msg_in);

	case WIRE_GOSSIPCTL_REACH_PEER:
		return reach_peer(conn, daemon, master->msg_in);

	case WIRE_GOSSIPCTL_PEER_ADDRHINT:
		return addr_hint(conn, daemon, master->msg_in);

	case WIRE_GOSSIPCTL_RELEASE_PEER_REPLY:
	case WIRE_GOSSIPCTL_RELEASE_PEER_REPLYFAIL:
	case WIRE_GOSSIP_GETNODES_REPLY:
	case WIRE_GOSSIP_GETROUTE_REPLY:
	case WIRE_GOSSIP_GETCHANNELS_REPLY:
	case WIRE_GOSSIP_PING_REPLY:
	case WIRE_GOSSIP_RESOLVE_CHANNEL_REPLY:
	case WIRE_GOSSIP_PEER_CONNECTED:
	case WIRE_GOSSIP_PEER_NONGOSSIP:
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

	subdaemon_debug(argc, argv);
	io_poll_override(debug_poll);

	if (argc == 2 && streq(argv[1], "--version")) {
		printf("%s\n", version());
		exit(0);
	}

	secp256k1_ctx = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY |
						 SECP256K1_CONTEXT_SIGN);

	daemon = tal(NULL, struct daemon);
	list_head_init(&daemon->peers);
	list_head_init(&daemon->reaching);
	list_head_init(&daemon->addrhints);
	timers_init(&daemon->timers, time_mono());
	daemon->broadcast_interval = 30000;

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
