/*~ This contains all the code to shuffle data between socket to the peer
 * itself, and the subdaemons. */
#include "config.h"
#include <assert.h>
#include <bitcoin/block.h>
#include <bitcoin/chainparams.h>
#include <ccan/io/io.h>
#include <common/cryptomsg.h>
#include <common/daemon_conn.h>
#include <common/dev_disconnect.h>
#include <common/features.h>
#include <common/gossip_constants.h>
#include <common/gossip_rcvd_filter.h>
#include <common/gossip_store.h>
#include <common/memleak.h>
#include <common/per_peer_state.h>
#include <common/ping.h>
#include <common/status.h>
#include <common/timeout.h>
#include <common/utils.h>
#include <common/wire_error.h>
#include <connectd/connectd.h>
#include <connectd/connectd_gossipd_wiregen.h>
#include <connectd/connectd_wiregen.h>
#include <connectd/multiplex.h>
#include <connectd/onion_message.h>
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
#include <wire/wire_sync.h>

void inject_peer_msg(struct peer *peer, const u8 *msg TAKES)
{
	status_peer_io(LOG_IO_OUT, &peer->id, msg);
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
	peer->to_subd = NULL;

	va_start(ap, fmt);
	peer->final_msg = towire_warningfmtv(peer, NULL, fmt, ap);
	va_end(ap);
}

/* Kicks off write_to_peer() to look for more gossip to send from store */
static void wake_gossip(struct peer *peer);

static struct oneshot *gossip_stream_timer(struct peer *peer)
{
	u32 next;

	/* BOLT #7:
	 *
	 * A node:
	 *...
	 *  - SHOULD flush outgoing gossip messages once every 60 seconds,
	 *    independently of the arrival times of the messages.
	 *    - Note: this results in staggered announcements that are unique
	 *      (not duplicated).
	 */
	/* We shorten this for dev_fast_gossip! */
	next = GOSSIP_FLUSH_INTERVAL(peer->daemon->dev_fast_gossip);

	return new_reltimer(&peer->daemon->timers,
			    peer, time_from_sec(next),
			    wake_gossip, peer);
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

	peer->gs.grf = new_gossip_rcvd_filter(peer);

	/* BOLT #7:
	 *
	 * A node:
	 *   - if the `gossip_queries` feature is negotiated:
	 * 	- MUST NOT relay any gossip messages it did not generate itself,
	 *        unless explicitly requested.
	 */
	if (feature_negotiated(our_features, their_features, OPT_GOSSIP_QUERIES)) {
		peer->gs.gossip_timer = NULL;
		peer->gs.active = false;
		peer->gs.off = 1;
		return;
	}

	peer->gs.gossip_timer = gossip_stream_timer(peer);
	peer->gs.active = true;
	peer->gs.timestamp_min = 0;
	peer->gs.timestamp_max = UINT32_MAX;

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
	if (feature_offered(their_features, OPT_INITIAL_ROUTING_SYNC))
		peer->gs.off = 1;
	else {
		/* During tests, particularly, we find that the gossip_store
		 * moves fast, so make sure it really does start at the end. */
		peer->gs.off
			= find_gossip_store_end(peer->daemon->gossip_store_fd,
						peer->daemon->gossip_store_end);
	}
}

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
		/* Disallow reads from now on */
		peer->dev_read_enabled = false;
		next = (void *)io_close_cb;
		break;
	case DEV_DISCONNECT_BLACKHOLE:
		/* Disable both reads and writes from now on */
		peer->dev_read_enabled = false;
		peer->dev_writes_enabled = talz(peer, u32);
		break;
	case DEV_DISCONNECT_NORMAL:
		break;
	case DEV_DISCONNECT_DISABLE_AFTER:
		peer->dev_read_enabled = false;
		peer->dev_writes_enabled = tal(peer, u32);
		*peer->dev_writes_enabled = 1;
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
	peer->gs.active = true;
	io_wake(peer->peer_outq);

	/* And go again in 60 seconds (from now, now when we finish!) */
	peer->gs.gossip_timer = gossip_stream_timer(peer);
}

/* If we are streaming gossip, get something from gossip store */
static u8 *maybe_from_gossip_store(const tal_t *ctx, struct peer *peer)
{
	u8 *msg;

	/* Not streaming yet? */
	if (!peer->gs.active)
		return NULL;

	/* This should be around to kick us every 60 seconds */
	assert(peer->gs.gossip_timer);

again:
	msg = gossip_store_next(ctx, &peer->daemon->gossip_store_fd,
				peer->gs.timestamp_min,
				peer->gs.timestamp_max,
				&peer->gs.off,
				&peer->daemon->gossip_store_end);
	/* Don't send back gossip they sent to us! */
	if (msg) {
		status_peer_debug(&peer->id,
				  "Sending gossip %s",
				  peer_wire_name(fromwire_peektype(msg)));
		if (gossip_rcvd_filter_del(peer->gs.grf, msg)) {
			msg = tal_free(msg);
			goto again;
		}
		status_peer_io(LOG_IO_OUT, &peer->id, msg);
		return msg;
	}

	peer->gs.active = false;
	return NULL;
}

/* Mutual recursion */
static void send_ping(struct peer *peer);

static void set_ping_timer(struct peer *peer)
{
	peer->ping_timer = new_reltimer(&peer->daemon->timers, peer,
					time_from_sec(15 + pseudorand(30)),
					send_ping, peer);
}

static void send_ping(struct peer *peer)
{
	/* Already have a ping in flight? */
	if (peer->expecting_pong != PONG_UNEXPECTED) {
		status_peer_debug(&peer->id, "Last ping unreturned: hanging up");
		if (peer->to_peer)
			io_close(peer->to_peer);
		return;
	}

	inject_peer_msg(peer, take(make_ping(NULL, 1, 0)));
	peer->expecting_pong = PONG_EXPECTED_PROBING;
	set_ping_timer(peer);
}

void send_custommsg(struct daemon *daemon, const u8 *msg)
{
	struct node_id id;
	u8 *custommsg;
	struct peer *peer;

	if (!fromwire_connectd_custommsg_out(tmpctx, msg, &id, &custommsg))
		master_badmsg(WIRE_CONNECTD_CUSTOMMSG_OUT, msg);

	/* Races can happen: this might be gone by now. */
	peer = peer_htable_get(&daemon->peers, &id);
	if (peer)
		inject_peer_msg(peer, take(custommsg));
}

static void handle_ping_in(struct peer *peer, const u8 *msg)
{
	u8 *pong;

	/* gossipd doesn't log IO, so we log it here. */
	status_peer_io(LOG_IO_IN, &peer->id, msg);

	if (!check_ping_make_pong(NULL, msg, &pong)) {
		send_warning(peer, "Invalid ping %s", tal_hex(msg, msg));
		return;
	}

	if (pong)
		inject_peer_msg(peer, take(pong));
}

static void handle_ping_reply(struct peer *peer, const u8 *msg)
{
	u8 *ignored;
	size_t i;

	/* We print this out because we asked for pong, so can't spam us... */
	if (!fromwire_pong(msg, msg, &ignored))
		status_peer_unusual(&peer->id, "Got malformed ping reply %s",
				    tal_hex(tmpctx, msg));

	/* We print this because dev versions of c-lightning embed
	 * version here: see check_ping_make_pong! */
	for (i = 0; i < tal_count(ignored); i++) {
		if (ignored[i] < ' ' || ignored[i] == 127)
			break;
	}
	status_debug("Got pong %zu bytes (%.*s...)",
		     tal_count(ignored), (int)i, (char *)ignored);
	daemon_conn_send(peer->daemon->master,
			 take(towire_connectd_ping_reply(NULL, true,
							 tal_bytelen(msg))));
}

static void handle_pong_in(struct peer *peer, const u8 *msg)
{
	/* gossipd doesn't log IO, so we log it here. */
	status_peer_io(LOG_IO_IN, &peer->id, msg);

	switch (peer->expecting_pong) {
	case PONG_EXPECTED_COMMAND:
		handle_ping_reply(peer, msg);
		/* fall thru */
	case PONG_EXPECTED_PROBING:
		peer->expecting_pong = PONG_UNEXPECTED;
		return;
	case PONG_UNEXPECTED:
		status_debug("Unexpected pong?");
		return;
	}
	abort();
}

/* Forward to gossipd */
static void handle_gossip_in(struct peer *peer, const u8 *msg)
{
	u8 *gmsg = towire_gossipd_recv_gossip(NULL, &peer->id, msg);

	/* gossipd doesn't log IO, so we log it here. */
	status_peer_io(LOG_IO_IN, &peer->id, msg);
	daemon_conn_send(peer->daemon->gossipd, take(gmsg));
}

static void handle_gossip_timetamp_filter_in(struct peer *peer, const u8 *msg)
{
	struct bitcoin_blkid chain_hash;
	u32 first_timestamp, timestamp_range;

	if (!fromwire_gossip_timestamp_filter(msg, &chain_hash,
					      &first_timestamp,
					      &timestamp_range)) {
		send_warning(peer, "gossip_timestamp_filter invalid: %s",
			     tal_hex(tmpctx, msg));
		return;
	}

	/* gossipd doesn't log IO, so we log it here. */
	status_peer_io(LOG_IO_IN, &peer->id, msg);

	if (!bitcoin_blkid_eq(&chainparams->genesis_blockhash, &chain_hash)) {
		send_warning(peer, "gossip_timestamp_filter for bad chain: %s",
			     tal_hex(tmpctx, msg));
		return;
	}

	peer->gs.timestamp_min = first_timestamp;
	peer->gs.timestamp_max = first_timestamp + timestamp_range - 1;
	/* Make sure we never leave it on an impossible value. */
	if (peer->gs.timestamp_max < peer->gs.timestamp_min)
		peer->gs.timestamp_max = UINT32_MAX;

	peer->gs.off = 1;

	/* BOLT #7:
	 *    - MAY wait for the next outgoing gossip flush to send these.
	 */
	/* We send immediately the first time, after that we wait. */
	if (!peer->gs.gossip_timer)
		wake_gossip(peer);
}

static bool handle_custommsg(struct daemon *daemon,
			     struct peer *peer,
			     const u8 *msg)
{
	enum peer_wire type = fromwire_peektype(msg);
	if (type % 2 == 1 && !peer_wire_is_defined(type)) {
		/* The message is not part of the messages we know how to
		 * handle. Assuming this is a custommsg, we just forward it to the
		 * master. */
		status_peer_io(LOG_IO_IN, &peer->id, msg);
		daemon_conn_send(daemon->master,
				 take(towire_connectd_custommsg_in(NULL,
								   &peer->id,
								   msg)));
		return true;
	} else {
		return false;
	}
}

/* We handle pings and gossip messages. */
static bool handle_message_locally(struct peer *peer, const u8 *msg)
{
	enum peer_wire type = fromwire_peektype(msg);

	/* We remember these so we don't rexmit them */
	if (is_msg_gossip_broadcast(msg))
		gossip_rcvd_filter_add(peer->gs.grf, msg);

	if (type == WIRE_GOSSIP_TIMESTAMP_FILTER) {
		handle_gossip_timetamp_filter_in(peer, msg);
		return true;
	} else if (type == WIRE_PING) {
		handle_ping_in(peer, msg);
		return true;
	} else if (type == WIRE_PONG) {
		handle_pong_in(peer, msg);
		return true;
	} else if (type == WIRE_OBS2_ONION_MESSAGE) {
		handle_obs2_onion_message(peer->daemon, peer, msg);
		return true;
	} else if (type == WIRE_ONION_MESSAGE) {
		handle_onion_message(peer->daemon, peer, msg);
		return true;
	} else if (handle_custommsg(peer->daemon, peer, msg)) {
		return true;
	}

	/* Do we want to divert to gossipd? */
	if (is_msg_for_gossipd(msg)) {
		handle_gossip_in(peer, msg);
		return true;
	}

	return false;
}

static void close_timeout(struct peer *peer)
{
	/* BROKEN means we'll trigger CI if we see it, though it's possible */
	status_peer_broken(&peer->id, "Peer did not close, forcing close");
	tal_free(peer->to_peer);
}

/* Close this in 5 seconds if it doesn't do so by itself. */
static void set_closing_timer(struct peer *peer,
			      struct io_conn *peer_conn)
{
	notleak(new_reltimer(&peer->daemon->timers,
			     peer_conn, time_from_sec(5),
			     close_timeout, peer));
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

	/* Is it time to send final? */
	if (!msg && peer->final_msg && !peer->to_subd) {
		/* OK, send this then close. */
		msg = peer->final_msg;
		peer->final_msg = NULL;
	}

	/* Still nothing to send? */
	if (!msg) {
		/* We close once subds are all closed. */
		if (!peer->to_subd) {
			set_closing_timer(peer, peer_conn);
			return io_sock_shutdown(peer_conn);
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

	/* dev_disconnect can disable writes */
#if DEVELOPER
	if (peer->dev_writes_enabled) {
		if (*peer->dev_writes_enabled == 0) {
			tal_free(msg);
			/* Continue, to drain queue */
			return write_to_peer(peer_conn, peer);
		}
		(*peer->dev_writes_enabled)--;
	}
#endif

	return encrypt_and_send(peer, take(msg), write_to_peer);
}

static struct io_plan *read_from_subd(struct io_conn *subd_conn,
				      struct peer *peer);
static struct io_plan *read_from_subd_done(struct io_conn *subd_conn,
					   struct peer *peer)
{
	/* Tell them to encrypt & write. */
	msg_enqueue(peer->peer_outq, take(peer->subd_in));
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
		/* If peer is closed, close this. */
		if (!peer->to_peer)
			return io_close(subd_conn);

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
       if (!decrypted) {
	       status_peer_debug(&peer->id, "Bad encrypted packet len %zu",
				 tal_bytelen(peer->peer_in));
               return io_close(peer_conn);
       }
       tal_free(peer->peer_in);

       /* dev_disconnect can disable read */
       if (!IFDEV(peer->dev_read_enabled, true)) {
	       tal_free(decrypted);
	       return read_hdr_from_peer(peer_conn, peer);
       }

       /* Don't process packets while we're closing */
       if (peer->told_to_close) {
	       tal_free(decrypted);
	       return read_hdr_from_peer(peer_conn, peer);
       }

       /* If we swallow this, just try again. */
       if (handle_message_locally(peer, decrypted)) {
	       tal_free(decrypted);
	       return read_hdr_from_peer(peer_conn, peer);
       }

       /* If there's no subd, discard and keep reading. */
       if (!peer->to_subd) {
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

	/* Make sure we try to keep reading from peer, so we know if
	 * it hangs up! */
	io_wake(&peer->peer_in);

	/* If no peer, finally time to close */
	if (!peer->to_peer && peer->told_to_close)
		peer_conn_closed(peer);
}

void close_peer_conn(struct peer *peer)
{
	/* Make write_to_peer do flush after writing */
	peer->told_to_close = true;

	/* Already dead? */
	if (!peer->to_subd && !peer->to_peer) {
		peer_conn_closed(peer);
		return;
	}

	/* In case it's not currently writing, wake write_to_peer */
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

	/* Flush internal connections if not already. */
	if (peer->to_subd) {
		msg_wake(peer->subd_outq);
		return;
	}

	if (peer->told_to_close)
		peer_conn_closed(peer);
}

struct io_plan *multiplex_peer_setup(struct io_conn *peer_conn,
				     struct peer *peer)
{
	/*~ If conn closes, we close the subd connections and wait for
	 * lightningd to tell us to close with the peer */
	tal_add_destructor2(peer_conn, destroy_peer_conn, peer);

	/* Start keepalives */
	peer->expecting_pong = PONG_UNEXPECTED;
	set_ping_timer(peer);

	return io_duplex(peer_conn,
			 read_hdr_from_peer(peer_conn, peer),
			 write_to_peer(peer_conn, peer));
}

void multiplex_final_msg(struct peer *peer, const u8 *final_msg TAKES)
{
	peer->told_to_close = true;
	peer->final_msg = tal_dup_talarr(peer, u8, final_msg);
	if (!peer->to_subd)
		io_wake(peer->peer_outq);
}

/* Lightningd says to send a ping */
void send_manual_ping(struct daemon *daemon, const u8 *msg)
{
	u8 *ping;
	struct node_id id;
	u16 len, num_pong_bytes;
	struct peer *peer;

	if (!fromwire_connectd_ping(msg, &id, &num_pong_bytes, &len))
		master_badmsg(WIRE_CONNECTD_PING, msg);

	peer = peer_htable_get(&daemon->peers, &id);
	if (!peer) {
		daemon_conn_send(daemon->master,
				 take(towire_connectd_ping_reply(NULL,
								 false, 0)));
		return;
	}

	/* We're not supposed to send another ping until previous replied */
	if (peer->expecting_pong != PONG_UNEXPECTED) {
		daemon_conn_send(daemon->master,
				 take(towire_connectd_ping_reply(NULL,
								 false, 0)));
		return;
	}

	/* It should never ask for an oversize ping. */
	ping = make_ping(NULL, num_pong_bytes, len);
	if (tal_count(ping) > 65535)
		status_failed(STATUS_FAIL_MASTER_IO, "Oversize ping");

	inject_peer_msg(peer, take(ping));

	status_debug("sending ping expecting %sresponse",
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
	if (num_pong_bytes >= 65532) {
		daemon_conn_send(daemon->master,
				 take(towire_connectd_ping_reply(NULL,
								 true, 0)));
		return;
	}

	/* We'll respond to lightningd once the pong comes in */
	peer->expecting_pong = PONG_EXPECTED_COMMAND;

	/* Since we're doing this manually, kill and restart timer. */
	tal_free(peer->ping_timer);
	set_ping_timer(peer);
}
