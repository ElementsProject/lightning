/*~ This contains all the code to shuffle data between socket to the peer
 * itself, and the subdaemons. */
#include "config.h"
#include <assert.h>
#include <bitcoin/block.h>
#include <bitcoin/chainparams.h>
#include <ccan/io/io.h>
#include <common/cryptomsg.h>
#include <common/dev_disconnect.h>
#include <common/features.h>
#include <common/gossip_constants.h>
#include <common/gossip_rcvd_filter.h>
#include <common/gossip_store.h>
#include <common/per_peer_state.h>
#include <common/status.h>
#include <common/timeout.h>
#include <common/utils.h>
#include <common/wire_error.h>
#include <connectd/connectd.h>
#include <connectd/multiplex.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <wire/peer_wire.h>
#include <wire/wire.h>
#include <wire/wire_io.h>

void queue_peer_msg(struct peer *peer, const u8 *msg TAKES)
{
	msg_enqueue(peer->peer_outq, msg);
}

/* Send warning, close connection to peer */
static void send_warning(struct peer *peer, const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	status_vfmt(LOG_UNUSUAL, &peer->id, fmt, ap);
	va_end(ap);

	/* Close locally, send msg as final warning */
	io_close(peer->to_subd);

	va_start(ap, fmt);
	peer->final_msg = towire_warningfmtv(peer, NULL, fmt, ap);
	va_end(ap);
}

/* Either for initial setup, or when they ask by timestamp */
static bool setup_gossip_filter(struct peer *peer,
				u32 first_timestamp,
				u32 timestamp_range)
{
	bool immediate_sync;

	/* If this is the first filter, we gossip sync immediately. */
	if (!peer->gs) {
		peer->gs = tal(peer, struct gossip_state);
		peer->gs->next_gossip = time_mono();
		immediate_sync = true;
	} else
		immediate_sync = false;

	/* BOLT #7:
	 *
	 * The receiver:
	 *   - SHOULD send all gossip messages whose `timestamp` is greater or
	 *     equal to `first_timestamp`, and less than `first_timestamp` plus
	 *     `timestamp_range`.
	 * 	- MAY wait for the next outgoing gossip flush to send these.
	 *   ...
	 *   - SHOULD restrict future gossip messages to those whose `timestamp`
	 *     is greater or equal to `first_timestamp`, and less than
	 *     `first_timestamp` plus `timestamp_range`.
	 */
	peer->gs->timestamp_min = first_timestamp;
	peer->gs->timestamp_max = first_timestamp + timestamp_range - 1;
	/* Make sure we never leave it on an impossible value. */
	if (peer->gs->timestamp_max < peer->gs->timestamp_min)
		peer->gs->timestamp_max = UINT32_MAX;

	peer->gossip_store_off = 1;
	return immediate_sync;
}

/* This is called once we need it: otherwise, the gossip_store may not exist,
 * since we start at the same time as gossipd itself. */
static void setup_gossip_store(struct daemon *daemon)
{
	daemon->gossip_store_fd = open(GOSSIP_STORE_FILENAME, O_RDONLY);
	if (daemon->gossip_store_fd < 0)
		status_failed(STATUS_FAIL_INTERNAL_ERROR,
			      "Opening gossip_store %s: %s",
			      GOSSIP_STORE_FILENAME, strerror(errno));
	/* gossipd will be writing to this, and it's not atomic!  Safest
	 * way to find the "end" is to walk through. */
	daemon->gossip_store_end
		= find_gossip_store_end(daemon->gossip_store_fd, 1);
}

void setup_peer_gossip_store(struct peer *peer,
			     const struct feature_set *our_features,
			     const u8 *their_features)
{
	/* Lazy setup */
	if (peer->daemon->gossip_store_fd == -1)
		setup_gossip_store(peer->daemon);

	peer->gossip_timer = NULL;

	/* BOLT #7:
	 *
	 * A node:
	 *   - if the `gossip_queries` feature is negotiated:
	 * 	- MUST NOT relay any gossip messages it did not generate itself,
	 *        unless explicitly requested.
	 */
	if (feature_negotiated(our_features, their_features, OPT_GOSSIP_QUERIES))
		return;

	setup_gossip_filter(peer, 0, UINT32_MAX);

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
	if (!feature_offered(their_features, OPT_INITIAL_ROUTING_SYNC)) {
		/* During tests, particularly, we find that the gossip_store
		 * moves fast, so make sure it really does start at the end. */
		peer->gossip_store_off
			= find_gossip_store_end(peer->daemon->gossip_store_fd,
						peer->daemon->gossip_store_end);
	}
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

/* Kicks off write_to_peer() to look for more gossip to send from store */
static void wake_gossip(struct peer *peer)
{
	peer->gossip_timer = NULL;
	io_wake(peer->peer_outq);
}

/* If we are streaming gossip, get something from gossip store */
static u8 *maybe_from_gossip_store(const tal_t *ctx, struct peer *peer)
{
	u8 *msg;

	/* Not streaming yet? */
	if (!peer->gs)
		return NULL;

	/* Still waiting for timer? */
	if (peer->gossip_timer != NULL)
		return NULL;

	msg = gossip_store_iter(ctx, &peer->daemon->gossip_store_fd,
				peer->gs, peer->grf, &peer->gossip_store_off);

	/* Cache highest valid offset (FIXME: doesn't really work when
	 * gossip_store gets rewritten!) */
	if (peer->gossip_store_off > peer->daemon->gossip_store_end)
		peer->daemon->gossip_store_end = peer->gossip_store_off;

	if (msg) {
		status_peer_io(LOG_IO_OUT, &peer->id, msg);
		return msg;
	}

	/* BOLT #7:
	 *
	 * A node:
	 *...
	 *  - SHOULD flush outgoing gossip messages once every 60 seconds,
	 *    independently of the arrival times of the messages.
	 *    - Note: this results in staggered announcements that are unique
	 *      (not duplicated).
	 */
	/* We do 60 seconds from *start*, not from *now* */
	peer->gs->next_gossip
		= timemono_add(time_mono(),
			       time_from_sec(GOSSIP_FLUSH_INTERVAL(
						     peer->daemon->dev_fast_gossip)));
	peer->gossip_timer = new_abstimer(&peer->daemon->timers, peer,
					  peer->gs->next_gossip,
					  wake_gossip, peer);
	return NULL;
}

/* We only handle gossip_timestamp_filter for now */
static bool handle_message_locally(struct peer *peer, const u8 *msg)
{
	struct bitcoin_blkid chain_hash;
	u32 first_timestamp, timestamp_range;

	/* We remember these so we don't rexmit them */
	if (is_msg_gossip_broadcast(msg))
		gossip_rcvd_filter_add(peer->grf, msg);

	if (!fromwire_gossip_timestamp_filter(msg, &chain_hash,
					      &first_timestamp,
					      &timestamp_range)) {
		return false;
	}

	if (!bitcoin_blkid_eq(&chainparams->genesis_blockhash, &chain_hash)) {
		send_warning(peer, "gossip_timestamp_filter for bad chain: %s",
			     tal_hex(tmpctx, msg));
		return true;
	}

	/* Returns true the first time. */
	if (setup_gossip_filter(peer, first_timestamp, timestamp_range))
		wake_gossip(peer);
	return true;
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
		/* If they want us to send gossip, do so now. */
		msg = maybe_from_gossip_store(NULL, peer);
		if (!msg) {
			/* Tell them to read again, */
			io_wake(&peer->subd_in);

			/* Wait for them to wake us */
			return msg_queue_wait(peer_conn, peer->peer_outq,
					      write_to_peer, peer);
		}
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

       /* If we swallow this, just try again. */
       if (handle_message_locally(peer, decrypted)) {
	       tal_free(decrypted);
	       return read_hdr_from_peer(peer_conn, peer);
       }

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
