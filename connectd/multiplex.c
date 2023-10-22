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
#include <common/memleak.h>
#include <common/per_peer_state.h>
#include <common/ping.h>
#include <common/status.h>
#include <common/timeout.h>
#include <common/type_to_string.h>
#include <common/utils.h>
#include <common/wire_error.h>
#include <connectd/connectd.h>
#include <connectd/connectd_gossipd_wiregen.h>
#include <connectd/connectd_wiregen.h>
#include <connectd/gossip_rcvd_filter.h>
#include <connectd/gossip_store.h>
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

struct subd {
	/* Owner: we are in peer->subds[] */
	struct peer *peer;

	/* The temporary or permanant channel_id */
	struct channel_id channel_id;

	/* In passing, we can have a temporary one, too. */
	struct channel_id *temporary_channel_id;

	/* The opening revocation basepoint, for v2 channel_id. */
	struct pubkey *opener_revocation_basepoint;

	/* The actual connection to talk to it (NULL if it's not connected yet)  */
	struct io_conn *conn;

	/* Input buffer */
	u8 *in;

	/* Output buffer */
	struct msg_queue *outq;
};

static struct subd *find_subd(struct peer *peer,
			      const struct channel_id *channel_id)
{
	for (size_t i = 0; i < tal_count(peer->subds); i++) {
		struct subd *subd = peer->subds[i];

		/* Once we see a message using the real channel_id, we
		 * clear the temporary_channel_id */
		if (channel_id_eq(&subd->channel_id, channel_id)) {
			subd->temporary_channel_id
				= tal_free(subd->temporary_channel_id);
			return subd;
		}
		if (subd->temporary_channel_id
		    && channel_id_eq(subd->temporary_channel_id, channel_id)) {
			return subd;
		}
	}
	return NULL;
}

/* Except for a reconnection, we finally free a peer when the io_conn
 * is closed and all subds are gone. */
static void maybe_free_peer(struct peer *peer)
{
	if (peer->to_peer)
		return;
	if (tal_count(peer->subds) != 0)
		return;
	status_debug("maybe_free_peer freeing peer!");
	tal_free(peer);
}

/* We try to send the final messages, but if buffer is full and they're
 * not reading, we have to give up. */
static void close_peer_io_timeout(struct peer *peer)
{
	/* BROKEN means we'll trigger CI if we see it, though it's possible */
	status_peer_broken(&peer->id, "Peer did not close, forcing close");
	io_close(peer->to_peer);
}

static void close_subd_timeout(struct subd *subd)
{
	status_peer_debug(&subd->peer->id, "Subd did not close, forcing close");
	io_close(subd->conn);
}

void drain_peer(struct peer *peer)
{
	status_debug("drain_peer");
	assert(!peer->draining);

	/* Since we immediately free any subds we didn't connect yet,
	 * we need peer->to_peer set so it won't free peer! */
	assert(peer->to_peer);

	/* Give the subds 5 seconds to close their fds to us. */
	for (size_t i = 0; i < tal_count(peer->subds); i++) {
		if (!peer->subds[i]->conn) {
			/* Deletes itself from array, so be careful! */
			tal_free(peer->subds[i]);
			i--;
			continue;
		}
		status_debug("drain_peer draining subd!");
		notleak(new_reltimer(&peer->daemon->timers,
				     peer->subds[i], time_from_sec(5),
				     close_subd_timeout, peer->subds[i]));
		/* Wake any outgoing queued on subd */
		io_wake(peer->subds[i]->outq);
	}

	/* Wake them to ensure they notice the close! */
	io_wake(&peer->subds);

	if (peer->to_peer) {
		/* You have 5 seconds to drain... */
		notleak(new_reltimer(&peer->daemon->timers,
				     peer->to_peer, time_from_sec(5),
				     close_peer_io_timeout, peer));
	}

	/* Clean peer from hashtable; we no longer exist. */
	destroy_peer(peer);
	tal_del_destructor(peer, destroy_peer);

	/* This is a 5-second leak, worst case! */
	notleak(peer);

	/* Start draining process! */
	io_wake(peer->peer_outq);
}

void inject_peer_msg(struct peer *peer, const u8 *msg TAKES)
{
	status_peer_io(LOG_IO_OUT, &peer->id, msg);
	msg_enqueue(peer->peer_outq, msg);
}

void multiplex_final_msg(struct peer *peer, const u8 *final_msg TAKES)
{
	inject_peer_msg(peer, final_msg);
	drain_peer(peer);
}

/* Send warning, close connection to peer */
static void send_warning(struct peer *peer, const char *fmt, ...)
{
	va_list ap;
	u8 *msg;

	va_start(ap, fmt);
	status_vfmt(LOG_UNUSUAL, &peer->id, fmt, ap);
	va_end(ap);

	va_start(ap, fmt);
	msg = towire_warningfmtv(NULL, NULL, fmt, ap);
	va_end(ap);

	multiplex_final_msg(peer, take(msg));
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

/* It's so common to ask for "recent" gossip (we ask for 10 minutes
 * ago, LND and Eclair ask for now, LDK asks for 1 hour ago) that it's
 * worth keeping track of where that starts, so we can skip most of
 * the store. */
static void update_recent_timestamp(struct daemon *daemon)
{
	/* 2 hours allows for some clock drift, not too much gossip */
	u32 recent = time_now().ts.tv_sec - 7200;

	/* Only update every minute */
	if (daemon->gossip_recent_time + 60 > recent)
		return;

	daemon->gossip_recent_time = recent;
	daemon->gossip_store_recent_off
		= find_gossip_store_by_timestamp(daemon->gossip_store_fd,
						 daemon->gossip_store_recent_off,
						 daemon->gossip_recent_time);
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

	daemon->gossip_recent_time = 0;
	daemon->gossip_store_recent_off = 1;
	update_recent_timestamp(daemon);

	/* gossipd will be writing to this, and it's not atomic!  Safest
	 * way to find the "end" is to walk through. */
	daemon->gossip_store_end
		= find_gossip_store_end(daemon->gossip_store_fd,
					daemon->gossip_store_recent_off);
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
	peer->gs.active = !peer->daemon->dev_suppress_gossip;
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

	if (urgent == peer->urgent)
		return;

	/* FIXME: We can't do this on websockets, but we could signal our
	 * websocket proxy via some magic message to do so! */
	if (peer->is_websocket != NORMAL_SOCKET)
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
		       IPPROTO_TCP, opt, &val, sizeof(val)) != 0
	    /* This actually happens in testing, where we blackhole the fd */
	    && peer->daemon->dev_disconnect_fd == -1) {
		status_broken("setsockopt %s=1 fd=%u: %s",
			      optname, io_conn_fd(peer->to_peer),
			      strerror(errno));
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
	case WIRE_TX_ABORT:
	case WIRE_TX_SIGNATURES:
	case WIRE_OPEN_CHANNEL:
	case WIRE_ACCEPT_CHANNEL:
	case WIRE_FUNDING_CREATED:
	case WIRE_FUNDING_SIGNED:
	case WIRE_CHANNEL_READY:
	case WIRE_OPEN_CHANNEL2:
	case WIRE_ACCEPT_CHANNEL2:
	case WIRE_TX_INIT_RBF:
	case WIRE_TX_ACK_RBF:
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
	case WIRE_ONION_MESSAGE:
	case WIRE_PEER_STORAGE:
	case WIRE_YOUR_PEER_STORAGE:
	case WIRE_STFU:
	case WIRE_SPLICE:
	case WIRE_SPLICE_ACK:
	case WIRE_SPLICE_LOCKED:
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
	bool flush_gossip_filter = true;
	/* With dev-fast-gossip, we clean every 2 seconds, which is too
	 * fast for our slow tests!  So we only call this one time in 5
	 * actually twice that, as it's not per-peer! */
	static int gossip_age_count;

	if (peer->daemon->dev_fast_gossip && gossip_age_count++ % 5 != 0)
		flush_gossip_filter = false;

	/* Don't remember sent per-peer gossip forever. */
	if (flush_gossip_filter)
		gossip_rcvd_filter_age(peer->gs.grf);

	peer->gs.active = !peer->daemon->dev_suppress_gossip;
	io_wake(peer->peer_outq);

	/* And go again in 60 seconds (from now, now when we finish!) */
	peer->gs.gossip_timer = gossip_stream_timer(peer);
}

/* If we are streaming gossip, get something from gossip store */
static u8 *maybe_from_gossip_store(const tal_t *ctx, struct peer *peer)
{
	u8 *msg;

	/* dev-mode can suppress all gossip */
	if (peer->daemon->dev_suppress_gossip)
		return NULL;

	/* Not streaming right now? */
	if (!peer->gs.active)
		return NULL;

	/* This should be around to kick us every 60 seconds */
	assert(peer->gs.gossip_timer);

again:
	msg = gossip_store_next(ctx, &peer->daemon->gossip_store_fd,
				peer->gs.timestamp_min,
				peer->gs.timestamp_max,
				false,
				&peer->gs.off,
				&peer->daemon->gossip_store_end);
	/* Don't send back gossip they sent to us! */
	if (msg) {
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
	if (peer->daemon->dev_no_ping_timer) {
		peer->ping_timer = NULL;
		return;
	}
	peer->ping_timer = new_reltimer(&peer->daemon->timers, peer,
					time_from_sec(15 + pseudorand(30)),
					send_ping, peer);
}

static void send_ping(struct peer *peer)
{
	/* If it's still sending us traffic, maybe ping reply is backed up?
	 * That's OK, ping is just to make sure it's still alive, and clearly
	 * it is. */
	if (time_before(peer->last_recv_time,
			timeabs_sub(time_now(), time_from_sec(60)))) {
		/* Already have a ping in flight? */
		if (peer->expecting_pong != PONG_UNEXPECTED) {
			status_peer_debug(&peer->id, "Last ping unreturned: hanging up");
			if (peer->to_peer)
				io_close(peer->to_peer);
			return;
		}

		inject_peer_msg(peer, take(make_ping(NULL, 1, 0)));
		peer->expecting_pong = PONG_EXPECTED_PROBING;
	}

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
	peer = peer_htable_get(daemon->peers, &id);
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

	/* We print this because dev versions of Core Lightning embed
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

static void handle_gossip_timestamp_filter_in(struct peer *peer, const u8 *msg)
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

	/* BOLT-gossip-filter-simplify #7:
	 * The receiver:
	 *...
	 *   - if `first_timestamp` is 0:
	 *     - SHOULD send all known gossip messages.
	 *   - otherwise, if `first_timestamp` is 0xFFFFFFFF:
	 *     - SHOULD NOT send any gossip messages (except its own).
	 *   - otherwise:
	 *     - SHOULD send gossip messages it receives from now own.
	 */
	/* For us, this means we only sweep the gossip store for messages
	 * if the first_timestamp is 0 */
	if (first_timestamp == 0)
		peer->gs.off = 1;
	else if (first_timestamp == 0xFFFFFFFF)
		peer->gs.off = peer->daemon->gossip_store_end;
	else {
		/* We are actually a bit nicer than the spec, and we include
		 * "recent" gossip here. */
		update_recent_timestamp(peer->daemon);
		peer->gs.off = peer->daemon->gossip_store_recent_off;
	}

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
	if (type % 2 == 1 && !peer_wire_is_internal(type)) {
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
	gossip_rcvd_filter_add(peer->gs.grf, msg);

	if (type == WIRE_GOSSIP_TIMESTAMP_FILTER) {
		handle_gossip_timestamp_filter_in(peer, msg);
		return true;
	} else if (type == WIRE_PING) {
		handle_ping_in(peer, msg);
		return true;
	} else if (type == WIRE_PONG) {
		handle_pong_in(peer, msg);
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

/* Move "channel_id" to temporary. */
static void move_channel_id_to_temp(struct subd *subd)
{
	tal_free(subd->temporary_channel_id);
	subd->temporary_channel_id
		= tal_dup(subd, struct channel_id, &subd->channel_id);
}

/* Only works for open_channel2 and accept_channel2 */
static struct pubkey *extract_revocation_basepoint(const tal_t *ctx,
						   const u8 *msg)
{
	const u8 *cursor = msg;
	size_t max = tal_bytelen(msg);
	enum peer_wire t;
	struct pubkey pubkey;

	t = fromwire_u16(&cursor, &max);

	switch (t) {
 	case WIRE_OPEN_CHANNEL2:
		/* BOLT-dualfund #2:
		 * 1. type: 64 (`open_channel2`)
		 * 2. data:
		 *    * [`chain_hash`:`chain_hash`]
		 *    * [`channel_id`:`zerod_channel_id`]
		 *    * [`u32`:`funding_feerate_perkw`]
		 *    * [`u32`:`commitment_feerate_perkw`]
		 *    * [`u64`:`funding_satoshis`]
		 *    * [`u64`:`dust_limit_satoshis`]
		 *    * [`u64`:`max_htlc_value_in_flight_msat`]
		 *    * [`u64`:`htlc_minimum_msat`]
		 *    * [`u16`:`to_self_delay`]
		 *    * [`u16`:`max_accepted_htlcs`]
		 *    * [`u32`:`locktime`]
		 *    * [`point`:`funding_pubkey`]
		 *    * [`point`:`revocation_basepoint`]
		 */
		fromwire_pad(&cursor, &max,
			     sizeof(struct bitcoin_blkid)
			     + sizeof(struct channel_id)
			     + sizeof(u32)
			     + sizeof(u32)
			     + sizeof(u64)
			     + sizeof(u64)
			     + sizeof(u64)
			     + sizeof(u64)
			     + sizeof(u16)
			     + sizeof(u16)
			     + sizeof(u32)
			     + PUBKEY_CMPR_LEN);
		break;
 	case WIRE_ACCEPT_CHANNEL2:
		/* BOLT-dualfund #2:
		 * 1. type: 65 (`accept_channel2`)
		 * 2. data:
		 *     * [`channel_id`:`zerod_channel_id`]
		 *     * [`u64`:`funding_satoshis`]
		 *     * [`u64`:`dust_limit_satoshis`]
		 *     * [`u64`:`max_htlc_value_in_flight_msat`]
		 *     * [`u64`:`htlc_minimum_msat`]
		 *     * [`u32`:`minimum_depth`]
		 *     * [`u16`:`to_self_delay`]
		 *     * [`u16`:`max_accepted_htlcs`]
		 *     * [`point`:`funding_pubkey`]
		 *     * [`point`:`revocation_basepoint`]
		 */
		fromwire_pad(&cursor, &max,
			     sizeof(struct channel_id)
			     + sizeof(u64)
			     + sizeof(u64)
			     + sizeof(u64)
			     + sizeof(u64)
			     + sizeof(u32)
			     + sizeof(u16)
			     + sizeof(u16)
			     + PUBKEY_CMPR_LEN);
		break;
	default:
		abort();
	}

	fromwire_pubkey(&cursor, &max, &pubkey);
	if (!cursor)
		return NULL;
	return tal_dup(ctx, struct pubkey, &pubkey);
}

/* Only works for funding_created */
static bool extract_funding_created_funding(const u8 *funding_created,
					    struct bitcoin_outpoint *outp)
{
	const u8 *cursor = funding_created;
	size_t max = tal_bytelen(funding_created);
	enum peer_wire t;

	t = fromwire_u16(&cursor, &max);

	switch (t) {
 	case WIRE_FUNDING_CREATED:
	/* BOLT #2:
	 * 1. type: 34 (`funding_created`)
	 * 2. data:
	 *     * [`32*byte`:`temporary_channel_id`]
	 *     * [`sha256`:`funding_txid`]
	 *     * [`u16`:`funding_output_index`]
	 */
		fromwire_pad(&cursor, &max, 32);
		fromwire_bitcoin_txid(&cursor, &max, &outp->txid);
		outp->n = fromwire_u16(&cursor, &max);
		break;
	default:
		abort();
	}

	return cursor != NULL;
}

static void update_v1_channelid(struct subd *subd, const u8 *funding_created)
{
	struct bitcoin_outpoint outp;

	if (!extract_funding_created_funding(funding_created, &outp)) {
		status_peer_unusual(&subd->peer->id, "WARNING: funding_created no tx info?");
		return;
	}
	move_channel_id_to_temp(subd);
	derive_channel_id(&subd->channel_id, &outp);
}

static void update_v2_channelid(struct subd *subd, const u8 *accept_channel2)
{
	struct pubkey *acc_basepoint;

	acc_basepoint = extract_revocation_basepoint(tmpctx, accept_channel2);
	if (!acc_basepoint) {
		status_peer_unusual(&subd->peer->id, "WARNING: accept_channel2 no revocation_basepoint?");
		return;
	}
	if (!subd->opener_revocation_basepoint) {
		status_peer_unusual(&subd->peer->id, "WARNING: accept_channel2 without open_channel2?");
		return;
	}

	move_channel_id_to_temp(subd);
	derive_channel_id_v2(&subd->channel_id,
			     subd->opener_revocation_basepoint, acc_basepoint);
}

/* We maintain channel_id matching for subds by snooping: we set it manually
 * for first packet (open_channel or open_channel2). */
static void maybe_update_channelid(struct subd *subd, const u8 *msg)
{
	switch (fromwire_peektype(msg)) {
	case WIRE_OPEN_CHANNEL:
		extract_channel_id(msg, &subd->channel_id);
		break;
	case WIRE_OPEN_CHANNEL2:
		subd->opener_revocation_basepoint
			= extract_revocation_basepoint(subd, msg);
		break;
	case WIRE_ACCEPT_CHANNEL2:
		update_v2_channelid(subd, msg);
		break;
	case WIRE_FUNDING_CREATED:
		update_v1_channelid(subd, msg);
		break;
	}
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

	/* Still nothing to send? */
	if (!msg) {
		/* Draining?  We're done when subds are done. */
		if (peer->draining && tal_count(peer->subds) == 0)
			return io_sock_shutdown(peer_conn);

		/* If they want us to send gossip, do so now. */
		if (!peer->draining)
			msg = maybe_from_gossip_store(NULL, peer);
		if (!msg) {
			/* Tell them to read again, */
			io_wake(&peer->subds);

			/* Wait for them to wake us */
			return msg_queue_wait(peer_conn, peer->peer_outq,
					      write_to_peer, peer);
		}
	}

	/* dev_disconnect can disable writes */
	if (peer->dev_writes_enabled) {
		if (*peer->dev_writes_enabled == 0) {
			tal_free(msg);
			/* Continue, to drain queue */
			return write_to_peer(peer_conn, peer);
		}
		(*peer->dev_writes_enabled)--;
	}

	return encrypt_and_send(peer, take(msg), write_to_peer);
}

static struct io_plan *read_from_subd(struct io_conn *subd_conn,
				      struct subd *subd);
static struct io_plan *read_from_subd_done(struct io_conn *subd_conn,
					   struct subd *subd)
{
	maybe_update_channelid(subd, subd->in);

	/* Tell them to encrypt & write. */
	msg_enqueue(subd->peer->peer_outq, take(subd->in));
	subd->in = NULL;

	/* Wait for them to wake us */
	return io_wait(subd_conn, &subd->peer->subds, read_from_subd, subd);
}

static struct io_plan *read_from_subd(struct io_conn *subd_conn,
				      struct subd *subd)
{
	return io_read_wire(subd_conn, subd, &subd->in,
			    read_from_subd_done, subd);
}

/* These four function handle peer->subd */
static struct io_plan *write_to_subd(struct io_conn *subd_conn,
				     struct subd *subd)
{
	const u8 *msg;
	assert(subd->conn == subd_conn);

	/* Pop tail of send queue */
	msg = msg_dequeue(subd->outq);

	/* Nothing to send? */
	if (!msg) {
		/* If peer is closed, close this. */
		if (!subd->peer->to_peer)
			return io_close(subd_conn);

		/* Tell them to read again. */
		io_wake(&subd->peer->peer_in);

		/* Wait for them to wake us */
		return msg_queue_wait(subd_conn, subd->outq,
				      write_to_subd, subd);
	}

	return io_write_wire(subd_conn, take(msg), write_to_subd, subd);
}

static void destroy_subd(struct subd *subd)
{
	struct peer *peer = subd->peer;
	size_t pos;

	for (pos = 0; peer->subds[pos] != subd; pos++)
		assert(pos < tal_count(peer->subds));

	tal_arr_remove(&peer->subds, pos);

	/* Make sure we try to keep reading from peer (might
	 * have been waiting for write_to_subd) */
	io_wake(&peer->peer_in);

	/* Maybe we were last subd out? */
	maybe_free_peer(peer);
}

static struct subd *new_subd(struct peer *peer,
			     const struct channel_id *channel_id)
{
	struct subd *subd;

	subd = tal(peer, struct subd);
	subd->peer = peer;
	subd->outq = msg_queue_new(subd, false);
	subd->channel_id = *channel_id;
	subd->temporary_channel_id = NULL;
	subd->opener_revocation_basepoint = NULL;
	subd->conn = NULL;

	/* Connect it to the peer */
	tal_arr_expand(&peer->subds, subd);
	tal_add_destructor(subd, destroy_subd);

	return subd;
}

static struct io_plan *read_hdr_from_peer(struct io_conn *peer_conn,
					  struct peer *peer);
static struct io_plan *read_body_from_peer_done(struct io_conn *peer_conn,
						struct peer *peer)
{
       u8 *decrypted;
       struct channel_id channel_id;
       struct subd *subd;

       decrypted = cryptomsg_decrypt_body(tmpctx, &peer->cs,
					  peer->peer_in);
       if (!decrypted) {
	       status_peer_debug(&peer->id, "Bad encrypted packet len %zu",
				 tal_bytelen(peer->peer_in));
               return io_close(peer_conn);
       }
       tal_free(peer->peer_in);

       /* dev_disconnect can disable read */
       if (!peer->dev_read_enabled)
	       return read_hdr_from_peer(peer_conn, peer);

       /* We got something! */
       peer->last_recv_time = time_now();

       /* Don't process packets while we're closing */
       if (peer->draining)
	       return read_hdr_from_peer(peer_conn, peer);

       /* If we swallow this, just try again. */
       if (handle_message_locally(peer, decrypted))
	       return read_hdr_from_peer(peer_conn, peer);

       /* After this we should be able to match to subd by channel_id */
       if (!extract_channel_id(decrypted, &channel_id)) {
	       enum peer_wire type = fromwire_peektype(decrypted);

	       /* We won't log this anywhere else, so do it here. */
	       status_peer_io(LOG_IO_IN, &peer->id, decrypted);

	       /* Could be a all-channel error or warning?  Log it
		* more verbose: hang up on error. */
	       if (type == WIRE_ERROR || type == WIRE_WARNING) {
		       char *desc = sanitize_error(tmpctx, decrypted, NULL);
		       status_peer_info(&peer->id,
					"Received %s: %s",
					peer_wire_name(type), desc);
		       if (type == WIRE_WARNING)
			       return read_hdr_from_peer(peer_conn, peer);
		       return io_close(peer_conn);
	       }

	       /* This sets final_msg: will close after sending warning */
	       send_warning(peer, "Unexpected message %s: %s",
			    peer_wire_name(type),
			    tal_hex(tmpctx, decrypted));
	       return read_hdr_from_peer(peer_conn, peer);
       }

       /* If we don't find a subdaemon for this, create a new one. */
       subd = find_subd(peer, &channel_id);
       if (!subd) {
	       enum peer_wire t = fromwire_peektype(decrypted);

	       /* Simplest to close on them at this point. */
	       if (peer->daemon->shutting_down) {
		       status_peer_debug(&peer->id,
					 "Shutting down: hanging up for %s",
					 peer_wire_name(t));
		       return io_close(peer_conn);
	       }
	       status_peer_debug(&peer->id, "Activating for message %s",
				 peer_wire_name(t));
	       subd = new_subd(peer, &channel_id);
	       /* We tell lightningd to fire up a subdaemon to handle this! */
	       daemon_conn_send(peer->daemon->master,
				take(towire_connectd_peer_spoke(NULL, &peer->id,
								peer->counter,
								t,
								&channel_id)));
       }

       /* Even if we just created it, call this to catch open_channel2 */
       maybe_update_channelid(subd, decrypted);

       /* Tell them to write. */
       msg_enqueue(subd->outq, take(decrypted));

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

static struct io_plan *subd_conn_init(struct io_conn *subd_conn,
				      struct subd *subd)
{
	subd->conn = subd_conn;

	/* subd is a child of the conn: free when it closes! */
	tal_steal(subd->conn, subd);
	return io_duplex(subd_conn,
			 read_from_subd(subd_conn, subd),
			 write_to_subd(subd_conn, subd));
}

static void destroy_peer_conn(struct io_conn *peer_conn, struct peer *peer)
{
	assert(peer->to_peer == peer_conn);

	/* If subds need cleaning, this will do it */
	if (!peer->draining)
		drain_peer(peer);

	peer->to_peer = NULL;

	/* Or if there were no subds, this will free the peer. */
	maybe_free_peer(peer);
}

struct io_plan *multiplex_peer_setup(struct io_conn *peer_conn,
				     struct peer *peer)
{
	/*~ If conn closes, we drain the subd connections and wait for
	 * lightningd to tell us to close with the peer */
	tal_add_destructor2(peer_conn, destroy_peer_conn, peer);

	/* Start keepalives */
	peer->expecting_pong = PONG_UNEXPECTED;
	set_ping_timer(peer);

	/* This used to be in openingd; don't break tests. */
	status_peer_debug(&peer->id, "Handed peer, entering loop");

	return io_duplex(peer_conn,
			 read_hdr_from_peer(peer_conn, peer),
			 write_to_peer(peer_conn, peer));
}

void peer_connect_subd(struct daemon *daemon, const u8 *msg, int fd)
{
	struct node_id id;
	u64 counter;
	struct peer *peer;
	struct channel_id channel_id;
	struct subd *subd;

	if (!fromwire_connectd_peer_connect_subd(msg, &id, &counter, &channel_id))
		master_badmsg(WIRE_CONNECTD_PEER_CONNECT_SUBD, msg);

	/* Races can happen: this might be gone by now (or reconnected!). */
	peer = peer_htable_get(daemon->peers, &id);
	if (!peer || peer->counter != counter) {
		close(fd);
		return;
	}

	/* Could be disconnecting now */
	if (!peer->to_peer) {
		close(fd);
		return;
	}

	/* If peer said something, we created this and queued msg. */
	subd = find_subd(peer, &channel_id);
	if (!subd)
		subd = new_subd(peer, &channel_id);

	assert(!subd->conn);

	/* This sets subd->conn inside subd_conn_init, and reparents subd! */
	io_new_conn(peer, fd, subd_conn_init, subd);
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

	peer = peer_htable_get(daemon->peers, &id);
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
