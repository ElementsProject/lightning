#include <ccan/breakpoint/breakpoint.h>
#include <ccan/container_of/container_of.h>
#include <ccan/crypto/hkdf_sha256/hkdf_sha256.h>
#include <ccan/endian/endian.h>
#include <ccan/fdpass/fdpass.h>
#include <ccan/io/fdpass/fdpass.h>
#include <ccan/io/io.h>
#include <ccan/list/list.h>
#include <ccan/noerr/noerr.h>
#include <ccan/read_write_all/read_write_all.h>
#include <ccan/tal/str/str.h>
#include <daemon/broadcast.h>
#include <daemon/routing.h>
#include <daemon/timeout.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <lightningd/cryptomsg.h>
#include <lightningd/gossip/gen_gossip_control_wire.h>
#include <lightningd/gossip/gen_gossip_status_wire.h>
#include <secp256k1_ecdh.h>
#include <sodium/randombytes.h>
#include <status.h>
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
	u8 *msg_in;

	/* Routing information */
	struct routing_state *rstate;

	struct timers timers;
};

struct peer {
	struct daemon *daemon;
	/* daemon->peers */
	struct list_node list;

	u64 unique_id;
	struct crypto_state *cs;

	/* File descriptor corresponding to conn. */
	int fd;

	/* Our connection (and owner) */
	struct io_conn *conn;

	/* If this is non-NULL, it means we failed. */
	const char *error;

	/* High water mark for the staggered broadcast */
	u64 broadcast_index;
	u8 **msg_out;
	/* Is it time to continue the staggered broadcast? */
	bool gossip_sync;
};

static void destroy_peer(struct peer *peer)
{
	list_del_from(&peer->daemon->peers, &peer->list);
	if (peer->error)
		status_send(towire_gossipstatus_peer_bad_msg(peer,
							     peer->unique_id,
							     (u8 *)peer->error));
}

static struct peer *setup_new_peer(struct daemon *daemon, const u8 *msg)
{
	struct peer *peer = tal(daemon, struct peer);
	peer->cs = tal(peer, struct crypto_state);
	if (!fromwire_gossipctl_new_peer(msg, NULL, &peer->unique_id, peer->cs))
		return tal_free(peer);
	peer->cs->peer = peer;
	peer->daemon = daemon;
	peer->error = NULL;
	peer->msg_out = tal_arr(peer, u8*, 0);
	list_add_tail(&daemon->peers, &peer->list);
	tal_add_destructor(peer, destroy_peer);
	return peer;
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
		handle_channel_announcement(peer->daemon->rstate, msg, tal_count(msg));
		return peer_read_message(conn, peer->cs, peer_msgin);

	case WIRE_NODE_ANNOUNCEMENT:
		handle_node_announcement(peer->daemon->rstate, msg, tal_count(msg));
		return peer_read_message(conn, peer->cs, peer_msgin);

	case WIRE_CHANNEL_UPDATE:
		handle_channel_update(peer->daemon->rstate, msg, tal_count(msg));
		return peer_read_message(conn, peer->cs, peer_msgin);

	case WIRE_INIT:
		peer->error = "Duplicate INIT message received";
		return io_close(conn);

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
	case WIRE_COMMIT_SIG:
	case WIRE_REVOKE_AND_ACK:
		/* Not our place to handle this, so we punt */
		s = towire_gossipstatus_peer_nongossip(msg, peer->unique_id,
						       peer->cs, msg);
		status_send(s);
		status_send_fd(io_conn_fd(conn));
		return io_close(conn);
	}

	/* BOLT #1:
	 *
	 * The type follows the _it's ok to be odd_ rule, so nodes MAY send
	 * odd-numbered types without ascertaining that the recipient
	 * understands it. */
	if (t & 1) {
		status_trace("Peer %"PRIu64" sent unknown packet %u, ignoring",
			     peer->unique_id, t);
		return peer_read_message(conn, peer->cs, peer_msgin);
	}
	peer->error = tal_fmt(peer, "Unknown packet %u", t);
	return io_close(conn);
}

/* Gets called by the outgoing IO loop when woken up. Sends messages
 * to the peer if there are any queued. Also checks if we have any
 * queued gossip messages and processes them. */
static struct io_plan *pkt_out(struct io_conn *conn, struct peer *peer);

/* Wake up the outgoing direction of the connection and write any
 * queued messages. Needed since the `io_wake` method signature does
 * not allow us to specify it as the callback for `new_reltimer`, but
 * it allows us to set an additional flag for the routing dump..
 */
static void wake_pkt_out(struct peer *peer)
{
	peer->gossip_sync = true;
	io_wake(peer);
}

/* Loop through the backlog of channel_{announcements,updates} and
 * node_announcements, writing out one on each iteration. Once we are
 * through wait for the broadcast interval and start again. */
static struct io_plan *peer_dump_gossip(struct io_conn *conn, struct peer *peer)
{
	struct queued_message *next;
	next = next_broadcast_message(
		peer->daemon->rstate->broadcasts, &peer->broadcast_index);

	if (!next) {
		new_reltimer(&peer->daemon->timers, peer, time_from_sec(30), wake_pkt_out, peer);
		/* Going to wake up in pkt_out since we mix time based and message based wakeups */
		return io_out_wait(conn, peer, pkt_out, peer);
	} else {
		return peer_write_message(conn, peer->cs, next->payload, peer_dump_gossip);
	}
}

static struct io_plan *pkt_out(struct io_conn *conn, struct peer *peer)
{
	/* First we process queued packets, if any */
	u8 *out;
	size_t n = tal_count(peer->msg_out);
	if (n > 0) {
		out = peer->msg_out[0];
		memmove(peer->msg_out, peer->msg_out + 1, (sizeof(*peer->msg_out)*(n-1)));
		tal_resize(&peer->msg_out, n-1);
		return peer_write_message(conn, peer->cs, out, pkt_out);
	}

	if (peer->gossip_sync){
		/* Send any queued up broadcast messages */
		peer->gossip_sync = false;
		return peer_dump_gossip(conn, peer);
	} else {
		return io_out_wait(conn, peer, pkt_out, peer);
	}
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
	status_send(towire_gossipstatus_peer_ready(msg, peer->unique_id));

	/* Need to go duplex here, otherwise backpressure would mean
	 * we both wait indefinitely */
	return io_duplex(conn,
			 peer_read_message(conn, peer->cs, peer_msgin),
			 peer_dump_gossip(conn, peer));
}

static struct io_plan *peer_init_sent(struct io_conn *conn, struct peer *peer)
{
	return peer_read_message(conn, peer->cs, peer_parse_init);
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
	return peer_write_message(conn, peer->cs, towire_init(peer, NULL, NULL),
				  peer_init_sent);
}

static struct io_plan *next_req_in(struct io_conn *conn, struct daemon *daemon);

static struct io_plan *new_peer_got_fd(struct io_conn *conn, struct peer *peer)
{
	peer->conn = io_new_conn(conn, peer->fd, peer_send_init, peer);
	if (!peer->conn) {
		peer->error = "Could not create connection";
		tal_free(peer);
	} else
		/* Free peer if conn closed. */
		tal_steal(peer->conn, peer);

	return next_req_in(conn, peer->daemon);
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

static struct io_plan *release_peer_fd(struct io_conn *conn, struct peer *peer)
{
	int fd = peer->fd;
	struct daemon *daemon = peer->daemon;

	tal_free(peer);
	return io_send_fd(conn, fd, next_req_in, daemon);
}

static struct io_plan *release_peer(struct io_conn *conn, struct daemon *daemon,
				    const u8 *msg)
{
	u64 unique_id;
	struct peer *peer;

	if (!fromwire_gossipctl_release_peer(msg, NULL, &unique_id))
		status_failed(WIRE_GOSSIPSTATUS_BAD_RELEASE_REQUEST,
			      "%s", tal_hex(trc, msg));

	list_for_each(&daemon->peers, peer, list) {
		if (peer->unique_id == unique_id) {
			u8 *out;

			/* Don't talk to this peer any more. */
			peer->fd = io_conn_fd(peer->conn);
			tal_steal(daemon, peer);
			io_close_taken_fd(peer->conn);

			out = towire_gossipctl_release_peer_response(msg,
								     unique_id,
								     peer->cs);
			return io_write_wire(conn, out, release_peer_fd, peer);
		}
	}
	status_failed(WIRE_GOSSIPSTATUS_BAD_RELEASE_REQUEST,
		      "Unknown peer %"PRIu64, unique_id);
}

static struct io_plan *recv_req(struct io_conn *conn, struct daemon *daemon)
{
	enum gossip_control_wire_type t = fromwire_peektype(daemon->msg_in);

	status_trace("req: type %s len %zu",
		     gossip_control_wire_type_name(t),
		     tal_count(daemon->msg_in));

	switch (t) {
	case WIRE_GOSSIPCTL_NEW_PEER:
		return new_peer(conn, daemon, daemon->msg_in);
	case WIRE_GOSSIPCTL_RELEASE_PEER:
		return release_peer(conn, daemon, daemon->msg_in);

	case WIRE_GOSSIPCTL_RELEASE_PEER_RESPONSE:
		break;
	}

	/* Control shouldn't give bad requests. */
	status_failed(WIRE_GOSSIPSTATUS_BAD_REQUEST, "%i", t);
}

static struct io_plan *next_req_in(struct io_conn *conn, struct daemon *daemon)
{
	daemon->msg_in = tal_free(daemon->msg_in);
	return io_read_wire(conn, daemon, &daemon->msg_in, recv_req, daemon);
}

#ifndef TESTING
int main(int argc, char *argv[])
{
	struct daemon *daemon;

	breakpoint();

	if (argc == 2 && streq(argv[1], "--version")) {
		printf("%s\n", version());
		exit(0);
	}

	daemon = tal(NULL, struct daemon);
	daemon->rstate = new_routing_state(daemon, NULL);
	list_head_init(&daemon->peers);
	timers_init(&daemon->timers, time_mono());
	daemon->msg_in = NULL;

	/* Stdout == status, stdin == requests */
	status_setup(STDOUT_FILENO);

	io_new_conn(NULL, STDIN_FILENO, next_req_in, daemon);

	for (;;) {
		struct timer *expired = NULL;
		io_loop(&daemon->timers, &expired);

		if (!expired) {
			break;
		} else {
			timer_expired(daemon, expired);
		}
	}

	tal_free(daemon);
	return 0;
}
#endif
