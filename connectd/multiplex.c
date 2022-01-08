/*~ This contains all the code to shuffle data between socket to the peer
 * itself, and the subdaemons. */
#include "config.h"
#include <assert.h>
#include <ccan/io/io.h>
#include <common/cryptomsg.h>
#include <common/dev_disconnect.h>
#include <common/per_peer_state.h>
#include <common/status.h>
#include <common/utils.h>
#include <connectd/multiplex.h>
#include <errno.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <wire/peer_wire.h>
#include <wire/wire.h>
#include <wire/wire_io.h>

void queue_peer_msg(struct peer *peer, const u8 *msg TAKES)
{
	msg_enqueue(peer->peer_outq, msg);
}

/* These four function handle subd->peer */
static struct io_plan *after_final_msg(struct io_conn *peer_conn,
				       struct peer *peer)
{
	/* io_close will want to free this itself! */
	assert(peer->to_peer == peer_conn);

	/* Invert ownership, so io_close frees peer for us */
	tal_steal(NULL, peer_conn);
	tal_steal(peer_conn, peer);

	return io_close(peer_conn);
}

#if DEVELOPER
static struct io_plan *write_to_peer(struct io_conn *peer_conn,
				     struct peer *peer);

static struct io_plan *dev_leave_hanging(struct io_conn *peer_conn,
					 struct peer *peer)
{
	/* We don't tell the peer we're disconnecting, but from now on
	 * our writes go nowhere, and there's nothing to read. */
	dev_sabotage_fd(io_conn_fd(peer_conn), false);
	return write_to_peer(peer_conn, peer);
}
#endif /* DEVELOPER */

/* We're happy for the kernel to batch update and gossip messages, but a
 * commitment message, for example, should be instantly sent.  There's no
 * great way of doing this, unfortunately.
 *
 * Setting TCP_NODELAY on Linux flushes the socket, which really means
 * we'd want to toggle on then off it *after* sending.  But Linux has
 * TCP_CORK.  On FreeBSD, it seems (looking at source) not to, so
 * there we'd want to set it before the send, and reenable it
 * afterwards.  Even if this is wrong on other non-Linux platforms, it
 * only means one extra packet.
 */
static void set_urgent_flag(struct peer *peer, bool urgent)
{
	int val;
	int opt;
	const char *optname;
	static bool complained = false;

	if (urgent == peer->urgent)
		return;

#ifdef TCP_CORK
	opt = TCP_CORK;
	optname = "TCP_CORK";
#elif defined(TCP_NODELAY)
	opt = TCP_NODELAY;
	optname = "TCP_NODELAY";
#else
#error "Please report platform with neither TCP_CORK nor TCP_NODELAY?"
#endif

	val = urgent;
	if (setsockopt(io_conn_fd(peer->to_peer),
		       IPPROTO_TCP, opt, &val, sizeof(val)) != 0) {
		/* This actually happens in testing, where we blackhole the fd */
		if (!complained) {
			status_unusual("setsockopt %s=1: %s",
				       optname,
				       strerror(errno));
			complained = true;
		}
	}
	peer->urgent = urgent;
}

static bool is_urgent(enum peer_wire type)
{
	switch (type) {
	case WIRE_INIT:
	case WIRE_ERROR:
	case WIRE_WARNING:
	case WIRE_TX_ADD_INPUT:
	case WIRE_TX_ADD_OUTPUT:
	case WIRE_TX_REMOVE_INPUT:
	case WIRE_TX_REMOVE_OUTPUT:
	case WIRE_TX_COMPLETE:
	case WIRE_TX_SIGNATURES:
	case WIRE_OPEN_CHANNEL:
	case WIRE_ACCEPT_CHANNEL:
	case WIRE_FUNDING_CREATED:
	case WIRE_FUNDING_SIGNED:
	case WIRE_FUNDING_LOCKED:
	case WIRE_OPEN_CHANNEL2:
	case WIRE_ACCEPT_CHANNEL2:
	case WIRE_INIT_RBF:
	case WIRE_ACK_RBF:
	case WIRE_SHUTDOWN:
	case WIRE_CLOSING_SIGNED:
	case WIRE_UPDATE_ADD_HTLC:
	case WIRE_UPDATE_FULFILL_HTLC:
	case WIRE_UPDATE_FAIL_HTLC:
	case WIRE_UPDATE_FAIL_MALFORMED_HTLC:
	case WIRE_UPDATE_FEE:
	case WIRE_UPDATE_BLOCKHEIGHT:
	case WIRE_CHANNEL_REESTABLISH:
	case WIRE_ANNOUNCEMENT_SIGNATURES:
	case WIRE_CHANNEL_ANNOUNCEMENT:
	case WIRE_NODE_ANNOUNCEMENT:
	case WIRE_CHANNEL_UPDATE:
	case WIRE_QUERY_SHORT_CHANNEL_IDS:
	case WIRE_REPLY_SHORT_CHANNEL_IDS_END:
	case WIRE_QUERY_CHANNEL_RANGE:
	case WIRE_REPLY_CHANNEL_RANGE:
	case WIRE_GOSSIP_TIMESTAMP_FILTER:
	case WIRE_OBS2_ONION_MESSAGE:
	case WIRE_ONION_MESSAGE:
#if EXPERIMENTAL_FEATURES
	case WIRE_STFU:
#endif
		return false;

	/* These are time-sensitive, and so send without delay. */
	case WIRE_PING:
	case WIRE_PONG:
	case WIRE_COMMITMENT_SIGNED:
	case WIRE_REVOKE_AND_ACK:
		return true;
	};

	/* plugins can inject other messages; assume not urgent. */
	return false;
}

static struct io_plan *encrypt_and_send(struct peer *peer,
					const u8 *msg TAKES,
					struct io_plan *(*next)
					(struct io_conn *peer_conn,
					 struct peer *peer))
{
	int type = fromwire_peektype(msg);

#if DEVELOPER
	switch (dev_disconnect(&peer->id, type)) {
	case DEV_DISCONNECT_BEFORE:
		if (taken(msg))
			tal_free(msg);
		return io_close(peer->to_peer);
	case DEV_DISCONNECT_AFTER:
		next = (void *)io_close_cb;
		break;
	case DEV_DISCONNECT_BLACKHOLE:
		dev_blackhole_fd(io_conn_fd(peer->to_peer));
		break;
	case DEV_DISCONNECT_NORMAL:
		break;
	case DEV_DISCONNECT_DISABLE_AFTER:
		next = dev_leave_hanging;
		break;
	}
#endif
	set_urgent_flag(peer, is_urgent(type));

	/* We free this and the encrypted version in next write_to_peer */
	peer->sent_to_peer = cryptomsg_encrypt_msg(peer, &peer->cs, msg);
	return io_write(peer->to_peer,
			peer->sent_to_peer,
			tal_bytelen(peer->sent_to_peer),
			next, peer);
}

static struct io_plan *write_to_peer(struct io_conn *peer_conn,
				     struct peer *peer)
{
	const u8 *msg;
	assert(peer->to_peer == peer_conn);

	/* Free last sent one (if any) */
	peer->sent_to_peer = tal_free(peer->sent_to_peer);

	/* Pop tail of send queue */
	msg = msg_dequeue(peer->peer_outq);

	/* Nothing to send? */
	if (!msg) {
		/* Send final once subd is not longer connected */
		if (peer->final_msg && !peer->to_subd) {
			return encrypt_and_send(peer,
						peer->final_msg,
						after_final_msg);
		}
		/* Tell them to read again, */
		io_wake(&peer->subd_in);

		/* Wait for them to wake us */
		return msg_queue_wait(peer_conn, peer->peer_outq,
				      write_to_peer, peer);
	}

	return encrypt_and_send(peer, take(msg), write_to_peer);
}

static struct io_plan *read_from_subd(struct io_conn *subd_conn,
				      struct peer *peer);
static struct io_plan *read_from_subd_done(struct io_conn *subd_conn,
					   struct peer *peer)
{
	/* Tell them to encrypt & write. */
	queue_peer_msg(peer, take(peer->subd_in));
	peer->subd_in = NULL;

	/* Wait for them to wake us */
	return io_wait(subd_conn, &peer->subd_in, read_from_subd, peer);
}

static struct io_plan *read_from_subd(struct io_conn *subd_conn,
				      struct peer *peer)
{
	return io_read_wire(subd_conn, peer, &peer->subd_in,
			    read_from_subd_done, peer);
}

/* These four function handle peer->subd */
static struct io_plan *write_to_subd(struct io_conn *subd_conn,
				     struct peer *peer)
{
	const u8 *msg;
	assert(peer->to_subd == subd_conn);

	/* Pop tail of send queue */
	msg = msg_dequeue(peer->subd_outq);

	/* Nothing to send? */
	if (!msg) {
		/* Tell them to read again. */
		io_wake(&peer->peer_in);

		/* Wait for them to wake us */
		return msg_queue_wait(subd_conn, peer->subd_outq,
				      write_to_subd, peer);
	}

	return io_write_wire(subd_conn, take(msg), write_to_subd, peer);
}

static struct io_plan *read_hdr_from_peer(struct io_conn *peer_conn,
					  struct peer *peer);
static struct io_plan *read_body_from_peer_done(struct io_conn *peer_conn,
						struct peer *peer)
{
       u8 *decrypted;

       decrypted = cryptomsg_decrypt_body(NULL, &peer->cs,
					  peer->peer_in);
       if (!decrypted)
               return io_close(peer_conn);
       tal_free(peer->peer_in);

       /* Tell them to write. */
       msg_enqueue(peer->subd_outq, take(decrypted));

       /* Wait for them to wake us */
       return io_wait(peer_conn, &peer->peer_in, read_hdr_from_peer, peer);
}

static struct io_plan *read_body_from_peer(struct io_conn *peer_conn,
					   struct peer *peer)
{
       u16 len;

       if (!cryptomsg_decrypt_header(&peer->cs, peer->peer_in, &len))
               return io_close(peer_conn);

       tal_resize(&peer->peer_in, (u32)len + CRYPTOMSG_BODY_OVERHEAD);
       return io_read(peer_conn, peer->peer_in, tal_count(peer->peer_in),
		      read_body_from_peer_done, peer);
}

static struct io_plan *read_hdr_from_peer(struct io_conn *peer_conn,
					  struct peer *peer)
{
	assert(peer->to_peer == peer_conn);

	/* BOLT #8:
	 *
	 * ### Receiving and Decrypting Messages
	 *
	 * In order to decrypt the _next_ message in the network
	 * stream, the following steps are completed:
	 *
	 *  1. Read _exactly_ 18 bytes from the network buffer.
	 */
	peer->peer_in = tal_arr(peer, u8, CRYPTOMSG_HDR_SIZE);
	return io_read(peer_conn, peer->peer_in, CRYPTOMSG_HDR_SIZE,
		       read_body_from_peer, peer);
}

static struct io_plan *subd_conn_init(struct io_conn *subd_conn, struct peer *peer)
{
	peer->to_subd = subd_conn;
	return io_duplex(subd_conn,
			 read_from_subd(subd_conn, peer),
			 write_to_subd(subd_conn, peer));
}

static void destroy_subd_conn(struct io_conn *subd_conn, struct peer *peer)
{
	assert(subd_conn == peer->to_subd);
	peer->to_subd = NULL;
	/* In case they were waiting for this to send final_msg */
	if (peer->final_msg)
		msg_wake(peer->peer_outq);
}

bool multiplex_subd_setup(struct peer *peer, int *fd_for_subd)
{
	int fds[2];

	if (socketpair(AF_LOCAL, SOCK_STREAM, 0, fds) != 0) {
		status_broken("Failed to create socketpair: %s",
			      strerror(errno));
		return false;
	}
	peer->to_subd = io_new_conn(peer, fds[0], subd_conn_init, peer);
	tal_add_destructor2(peer->to_subd, destroy_subd_conn, peer);
	*fd_for_subd = fds[1];
	return true;
}

static void destroy_peer_conn(struct io_conn *peer_conn, struct peer *peer)
{
	assert(peer->to_peer == peer_conn);
	peer->to_peer = NULL;

	/* Close internal connections if not already. */
	if (peer->to_subd)
		io_close(peer->to_subd);
}

struct io_plan *multiplex_peer_setup(struct io_conn *peer_conn,
				     struct peer *peer)
{
	/*~ If conn closes, we close the subd connections and wait for
	 * lightningd to tell us to close with the peer */
	tal_add_destructor2(peer_conn, destroy_peer_conn, peer);

	return io_duplex(peer_conn,
			 read_hdr_from_peer(peer_conn, peer),
			 write_to_peer(peer_conn, peer));
}

void multiplex_final_msg(struct peer *peer, const u8 *final_msg TAKES)
{
	peer->final_msg = tal_dup_talarr(peer, u8, final_msg);
	if (!peer->to_subd)
		io_wake(peer->peer_outq);
}
