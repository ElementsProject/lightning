/*~ Welcome to the gossip daemon: keeper of maps!
 *
 * This is the last "global" daemon; it has three purposes.
 *
 * 1. To determine routes for payments when lightningd asks.
 * 2. The second purpose is to receive gossip from peers (via their
 *    per-peer daemons) and send it out to them.
 * 3. Talk to `connectd` to to answer address queries for nodes.
 *
 * The gossip protocol itself is fairly simple, but has some twists which
 * add complexity to this daemon.
 */
#include "config.h"
#include <ccan/cast/cast.h>
#include <ccan/tal/str/str.h>
#include <common/daemon_conn.h>
#include <common/ecdh_hsmd.h>
#include <common/lease_rates.h>
#include <common/memleak.h>
#include <common/pseudorand.h>
#include <common/status.h>
#include <common/subdaemon.h>
#include <common/timeout.h>
#include <common/wire_error.h>
#include <common/wireaddr.h>
#include <connectd/connectd_gossipd_wiregen.h>
#include <errno.h>
#include <gossipd/gossip_store.h>
#include <gossipd/gossip_store_wiregen.h>
#include <gossipd/gossipd.h>
#include <gossipd/gossipd_wiregen.h>
#include <gossipd/gossmap_manage.h>
#include <gossipd/queries.h>
#include <gossipd/seeker.h>
#include <sodium/crypto_aead_chacha20poly1305.h>

const struct node_id *peer_node_id(const struct peer *peer)
{
	return &peer->id;
}

bool peer_node_id_eq(const struct peer *peer, const struct node_id *node_id)
{
	return node_id_eq(&peer->id, node_id);
}

/*~ Destroy a peer, usually because the per-peer daemon has exited.
 *
 * Were you wondering why we call this "destroy_peer" and not "peer_destroy"?
 * I thought not!  But while CCAN modules are required to keep to their own
 * prefix namespace, leading to unnatural word order, we couldn't stomach that
 * for our own internal use.  We use 'find_foo', 'destroy_foo' and 'new_foo'.
 */
static void destroy_peer(struct peer *peer)
{
	/* Remove it from the peers table */
	peer_node_id_map_del(peer->daemon->peers, peer);

	/* Sorry seeker, this one is gone. */
	seeker_peer_gone(peer->daemon->seeker, peer);
}

/* Search for a peer. */
struct peer *find_peer(struct daemon *daemon, const struct node_id *id)
{
	return peer_node_id_map_get(daemon->peers, id);
}

/* Increase a peer's gossip_counter, if peer not NULL */
void peer_supplied_good_gossip(struct daemon *daemon,
			       const struct node_id *source_peer,
			       size_t amount)
{
	struct peer *peer;

	if (!source_peer)
		return;

	peer = find_peer(daemon, source_peer);
	if (!peer)
		return;

	peer->gossip_counter += amount;
}

/* Increase a peer's query_reply_counter, if peer not NULL */
void peer_supplied_query_response(struct daemon *daemon,
				  const struct node_id *source_peer,
				  size_t amount)
{
	struct peer *peer;

	if (!source_peer)
		return;

	peer = find_peer(daemon, source_peer);
	if (!peer)
		return;

	peer->query_reply_counter += amount;
}

/* Queue a gossip message for the peer: connectd simply forwards it to
 * the peer. */
void queue_peer_msg(struct daemon *daemon,
		    const struct node_id *peer,
		    const u8 *msg TAKES)
{
	u8 *outermsg = towire_gossipd_send_gossip(NULL, peer, msg);
	daemon_conn_send(daemon->connectd, take(outermsg));

	if (taken(msg))
		tal_free(msg);
}

/*~Routines to handle gossip messages from peer, forwarded by connectd.
 *-----------------------------------------------------------------------
 *
 * We send back a warning if they send us something bogus.
 */

/*~ This is where connectd tells us about a new peer we might want to
 *  gossip with. */
static void connectd_new_peer(struct daemon *daemon, const u8 *msg)
{
	struct peer *peer = tal(daemon, struct peer);

	if (!fromwire_gossipd_new_peer(msg, &peer->id,
				      &peer->gossip_queries_feature)) {
		status_failed(STATUS_FAIL_INTERNAL_ERROR,
			      "Bad new_peer msg from connectd: %s",
			      tal_hex(tmpctx, msg));
	}

	if (find_peer(daemon, &peer->id)) {
		status_broken("Peer %s already here?",
			      fmt_node_id(tmpctx, &peer->id));
		tal_free(find_peer(daemon, &peer->id));
	}

	/* Populate the rest of the peer info. */
	peer->daemon = daemon;
	peer->gossip_counter = 0;
	peer->query_reply_counter = 0;
	peer->scid_queries = NULL;
	peer->scid_query_idx = 0;
	peer->scid_query_nodes = NULL;
	peer->scid_query_nodes_idx = 0;
	peer->scid_query_outstanding = false;
	peer->range_replies = NULL;
	peer->query_channel_range_cb = NULL;

	/* We keep a htable so we can find peer by id */
	peer_node_id_map_add(daemon->peers, peer);
	tal_add_destructor(peer, destroy_peer);

	/* Send everything we know about our own channels */
	gossmap_manage_new_peer(daemon->gm, &peer->id);

	/* This sends the initial timestamp filter. */
	seeker_setup_peer_gossip(daemon->seeker, peer);
}

static void connectd_peer_gone(struct daemon *daemon, const u8 *msg)
{
	struct node_id id;
	struct peer *peer;

	if (!fromwire_gossipd_peer_gone(msg, &id)) {
		status_failed(STATUS_FAIL_INTERNAL_ERROR,
			      "Bad peer_gone msg from connectd: %s",
			      tal_hex(tmpctx, msg));
	}

	peer = find_peer(daemon, &id);
	if (!peer)
		status_broken("Peer %s already gone?",
			      fmt_node_id(tmpctx, &id));
	tal_free(peer);
}

/*~ lightningd asks us if we know any addresses for a given id. */
static struct io_plan *handle_get_address(struct io_conn *conn,
					  struct daemon *daemon,
					  const u8 *msg)
{
	struct node_id id;
	struct wireaddr *addrs;

	if (!fromwire_gossipd_get_addrs(msg, &id))
		master_badmsg(WIRE_GOSSIPD_GET_ADDRS, msg);

	addrs = gossmap_manage_get_node_addresses(tmpctx,
						  daemon->gm,
						  &id);

	daemon_conn_send(daemon->master,
			 take(towire_gossipd_get_addrs_reply(NULL, addrs)));
	return daemon_conn_read_next(conn, daemon->master);
}

static void handle_recv_gossip(struct daemon *daemon, const u8 *outermsg)
{
	struct node_id source;
	u8 *msg;
	const u8 *err;
	const char *errmsg;
	struct peer *peer;

	if (!fromwire_gossipd_recv_gossip(outermsg, outermsg, &source, &msg)) {
		status_failed(STATUS_FAIL_INTERNAL_ERROR,
			      "Bad gossipd_recv_gossip msg from connectd: %s",
			      tal_hex(tmpctx, outermsg));
	}

	peer = find_peer(daemon, &source);
	if (!peer) {
		status_broken("connectd sent gossip msg %s from unknown peer %s",
			      peer_wire_name(fromwire_peektype(msg)),
			      fmt_node_id(tmpctx, &source));
		return;
	}

	status_peer_trace(&source, "handle_recv_gossip: %s", peer_wire_name(fromwire_peektype(msg)));
	/* These are messages relayed from peer */
	switch ((enum peer_wire)fromwire_peektype(msg)) {
	case WIRE_CHANNEL_ANNOUNCEMENT:
		errmsg = gossmap_manage_channel_announcement(tmpctx,
							     daemon->gm,
							     msg, &source, NULL);
		goto handled_msg_errmsg;
	case WIRE_CHANNEL_UPDATE:
		errmsg = gossmap_manage_channel_update(tmpctx,
						       daemon->gm,
						       msg, &source);
		goto handled_msg_errmsg;
	case WIRE_NODE_ANNOUNCEMENT:
		errmsg = gossmap_manage_node_announcement(tmpctx,
							  daemon->gm,
							  msg, &source);
		goto handled_msg_errmsg;
	case WIRE_REPLY_CHANNEL_RANGE:
		err = handle_reply_channel_range(peer, msg);
		goto handled_msg;
	case WIRE_REPLY_SHORT_CHANNEL_IDS_END:
		err = handle_reply_short_channel_ids_end(peer, msg);
		goto handled_msg;

	/* These are non-gossip messages (!is_msg_for_gossipd()) */
	case WIRE_QUERY_SHORT_CHANNEL_IDS:
	case WIRE_QUERY_CHANNEL_RANGE:
	case WIRE_WARNING:
	case WIRE_INIT:
	case WIRE_ERROR:
	case WIRE_PING:
	case WIRE_PONG:
	case WIRE_OPEN_CHANNEL:
	case WIRE_ACCEPT_CHANNEL:
	case WIRE_FUNDING_CREATED:
	case WIRE_FUNDING_SIGNED:
	case WIRE_CHANNEL_READY:
	case WIRE_SHUTDOWN:
	case WIRE_CLOSING_SIGNED:
	case WIRE_UPDATE_ADD_HTLC:
	case WIRE_UPDATE_FULFILL_HTLC:
	case WIRE_UPDATE_FAIL_HTLC:
	case WIRE_UPDATE_FAIL_MALFORMED_HTLC:
	case WIRE_COMMITMENT_SIGNED:
	case WIRE_REVOKE_AND_ACK:
	case WIRE_UPDATE_FEE:
	case WIRE_UPDATE_BLOCKHEIGHT:
	case WIRE_CHANNEL_REESTABLISH:
	case WIRE_ANNOUNCEMENT_SIGNATURES:
	case WIRE_GOSSIP_TIMESTAMP_FILTER:
	case WIRE_TX_ADD_INPUT:
	case WIRE_TX_REMOVE_INPUT:
	case WIRE_TX_ADD_OUTPUT:
	case WIRE_TX_REMOVE_OUTPUT:
	case WIRE_TX_COMPLETE:
	case WIRE_TX_ABORT:
	case WIRE_TX_SIGNATURES:
	case WIRE_TX_INIT_RBF:
	case WIRE_TX_ACK_RBF:
	case WIRE_OPEN_CHANNEL2:
	case WIRE_ACCEPT_CHANNEL2:
	case WIRE_ONION_MESSAGE:
	case WIRE_PEER_STORAGE:
	case WIRE_YOUR_PEER_STORAGE:
	case WIRE_STFU:
	case WIRE_SPLICE:
	case WIRE_SPLICE_ACK:
	case WIRE_SPLICE_LOCKED:
		break;
	}

	status_failed(STATUS_FAIL_INTERNAL_ERROR,
		      "connectd sent unexpected gossip msg %s for peer %s",
		      peer_wire_name(fromwire_peektype(msg)),
		      fmt_node_id(tmpctx, &peer->id));

handled_msg_errmsg:
	if (errmsg)
		err = towire_warningfmt(NULL, NULL, "%s", errmsg);
	else
		err = NULL;

handled_msg:
	if (err) {
		queue_peer_msg(daemon, &source, take(err));
	} else {
		/* Some peer gave us gossip, so we're not at zero. */
		peer->daemon->gossip_store_populated = true;
	}
}

/*~ connectd's input handler is very simple. */
static struct io_plan *connectd_req(struct io_conn *conn,
				    const u8 *msg,
				    struct daemon *daemon)
{
	enum connectd_gossipd_wire t = fromwire_peektype(msg);

	switch (t) {
	case WIRE_GOSSIPD_RECV_GOSSIP:
		handle_recv_gossip(daemon, msg);
		goto handled;

	case WIRE_GOSSIPD_NEW_PEER:
		connectd_new_peer(daemon, msg);
		goto handled;

	case WIRE_GOSSIPD_PEER_GONE:
		connectd_peer_gone(daemon, msg);
		goto handled;

	/* We send these, don't receive them. */
	case WIRE_GOSSIPD_SEND_GOSSIP:
		break;
	}

	status_failed(STATUS_FAIL_INTERNAL_ERROR,
		      "Bad msg from connectd2: %s", tal_hex(tmpctx, msg));

handled:
	return daemon_conn_read_next(conn, daemon->connectd);
}

void tell_lightningd_peer_update(struct daemon *daemon,
				 const struct node_id *source_peer,
				 struct short_channel_id scid,
				 u32 fee_base_msat,
				 u32 fee_ppm,
				 u16 cltv_delta,
				 struct amount_msat htlc_minimum,
				 struct amount_msat htlc_maximum)
{
	struct peer_update remote_update;
	u8* msg;
	remote_update.scid = scid;
	remote_update.fee_base = fee_base_msat;
	remote_update.fee_ppm = fee_ppm;
	remote_update.cltv_delta = cltv_delta;
	remote_update.htlc_minimum_msat = htlc_minimum;
	remote_update.htlc_maximum_msat = htlc_maximum;
	msg = towire_gossipd_remote_channel_update(NULL, source_peer, &remote_update);
	daemon_conn_send(daemon->master, take(msg));
}

struct peer *first_random_peer(struct daemon *daemon,
			       struct peer_node_id_map_iter *it)
{
	return peer_node_id_map_pick(daemon->peers, pseudorand_u64(), it);
}

struct peer *next_random_peer(struct daemon *daemon,
			      const struct peer *first,
			      struct peer_node_id_map_iter *it)
{
	struct peer *p;

	p = peer_node_id_map_next(daemon->peers, it);
	if (!p)
		p = peer_node_id_map_first(daemon->peers, it);

	/* Full circle? */
	if (p == first)
		return NULL;
	return p;
}

/* This is called when lightningd or connectd closes its connection to
 * us.  We simply exit. */
static void master_or_connectd_gone(struct daemon_conn *dc UNUSED)
{
	daemon_shutdown();
	/* Can't tell master, it's gone. */
	exit(2);
}

struct timeabs gossip_time_now(const struct daemon *daemon)
{
	if (daemon->dev_gossip_time)
		return *daemon->dev_gossip_time;

	return time_now();
}

/* We don't check this when loading from the gossip_store: that would break
 * our canned tests, and usually old gossip is better than no gossip */
bool timestamp_reasonable(const struct daemon *daemon, u32 timestamp)
{
	u64 now = gossip_time_now(daemon).ts.tv_sec;

	/* More than one day ahead? */
	if (timestamp > now + 24*60*60)
		return false;
	/* More than 2 weeks behind? */
	if (timestamp < now - GOSSIP_PRUNE_INTERVAL(daemon->dev_fast_gossip_prune))
		return false;
	return true;
}

/*~ Parse init message from lightningd: starts the daemon properly. */
static void gossip_init(struct daemon *daemon, const u8 *msg)
{
	u32 *dev_gossip_time;
	struct chan_dying *dying;

	if (!fromwire_gossipd_init(daemon, msg,
				     &chainparams,
				     &daemon->our_features,
				     &daemon->id,
				     &dev_gossip_time,
				     &daemon->dev_fast_gossip,
				     &daemon->dev_fast_gossip_prune)) {
		master_badmsg(WIRE_GOSSIPD_INIT, msg);
	}

	if (dev_gossip_time) {
		assert(daemon->developer);
		daemon->dev_gossip_time = tal(daemon, struct timeabs);
		daemon->dev_gossip_time->ts.tv_sec = *dev_gossip_time;
		daemon->dev_gossip_time->ts.tv_nsec = 0;
		tal_free(dev_gossip_time);
	}

	daemon->gs = gossip_store_new(daemon,
				      daemon,
				      &daemon->gossip_store_populated,
				      &dying);

	/* Gossmap manager starts up */
	daemon->gm = gossmap_manage_new(daemon, daemon, take(dying));

	/* Fire up the seeker! */
	daemon->seeker = new_seeker(daemon);

	/* connectd is already started, and uses this fd to feed/recv gossip. */
	daemon->connectd = daemon_conn_new(daemon, CONNECTD_FD,
					   connectd_req,
					   NULL, daemon);
	tal_add_destructor(daemon->connectd, master_or_connectd_gone);

	/* Tell it about all our local (public) channel_update messages,
	 * and node_announcement, so it doesn't unnecessarily regenerate them. */
	gossmap_manage_tell_lightningd_locals(daemon, daemon->gm);

	/* OK, we are ready. */
	daemon_conn_send(daemon->master,
			 take(towire_gossipd_init_reply(NULL)));
}

static void new_blockheight(struct daemon *daemon, const u8 *msg)
{
	if (!fromwire_gossipd_new_blockheight(msg, &daemon->current_blockheight))
		master_badmsg(WIRE_GOSSIPD_NEW_BLOCKHEIGHT, msg);

	/* Check if we can now send any deferred queries. */
	for (size_t i = 0; i < tal_count(daemon->deferred_txouts); i++) {
		const struct short_channel_id scid
			= daemon->deferred_txouts[i];

		if (!is_scid_depth_announceable(scid,
						daemon->current_blockheight))
			continue;

		/* short_channel_id is deep enough, now ask about it. */
		daemon_conn_send(daemon->master,
				 take(towire_gossipd_get_txout(NULL, scid)));

		tal_arr_remove(&daemon->deferred_txouts, i);
		i--;
	}

	gossmap_manage_new_block(daemon->gm, daemon->current_blockheight);

	daemon_conn_send(daemon->master,
			 take(towire_gossipd_new_blockheight_reply(NULL)));
}

static void dev_gossip_memleak(struct daemon *daemon, const u8 *msg)
{
	struct htable *memtable;
	bool found_leak;

	memtable = memleak_start(tmpctx);
	memleak_ptr(memtable, msg);
	/* Now delete daemon and those which it has pointers to. */
	memleak_scan_obj(memtable, daemon);
	memleak_scan_htable(memtable, &daemon->peers->raw);
	dev_seeker_memleak(memtable, daemon->seeker);

	found_leak = dump_memleak(memtable, memleak_status_broken, NULL);
	daemon_conn_send(daemon->master,
			 take(towire_gossipd_dev_memleak_reply(NULL,
							      found_leak)));
}

static void dev_gossip_set_time(struct daemon *daemon, const u8 *msg)
{
	u32 time;

	if (!fromwire_gossipd_dev_set_time(msg, &time))
		master_badmsg(WIRE_GOSSIPD_DEV_SET_TIME, msg);
	if (!daemon->dev_gossip_time)
		daemon->dev_gossip_time = tal(daemon, struct timeabs);
	daemon->dev_gossip_time->ts.tv_sec = time;
	daemon->dev_gossip_time->ts.tv_nsec = 0;
}

/*~ lightningd tells us when about a gossip message directly, when told to by
 * the addgossip RPC call.  That's usually used when a plugin gets an update
 * returned in an payment error. */
static void inject_gossip(struct daemon *daemon, const u8 *msg)
{
	u8 *goss;
	const char *err;
	struct amount_sat *known_amount;

	if (!fromwire_gossipd_addgossip(msg, msg, &goss, &known_amount))
		master_badmsg(WIRE_GOSSIPD_ADDGOSSIP, msg);

	status_debug("inject_gossip: %s", peer_wire_name(fromwire_peektype(goss)));
	switch (fromwire_peektype(goss)) {
	case WIRE_CHANNEL_ANNOUNCEMENT:
		err = gossmap_manage_channel_announcement(tmpctx,
							  daemon->gm,
							  take(goss), NULL,
							  known_amount);
		break;
	case WIRE_NODE_ANNOUNCEMENT:
		err = gossmap_manage_node_announcement(tmpctx,
						       daemon->gm,
						       take(goss), NULL);
		break;
	case WIRE_CHANNEL_UPDATE:
		err = gossmap_manage_channel_update(tmpctx,
						    daemon->gm,
						    take(goss), NULL);
		break;
	default:
		err = tal_fmt(tmpctx, "unknown gossip type %i",
			      fromwire_peektype(goss));
	}

	/* FIXME: Make this an optional string in gossipd_addgossip_reply */
	daemon_conn_send(daemon->master,
			 take(towire_gossipd_addgossip_reply(NULL, err ? err : "")));
}

/*~ This is where lightningd tells us that a channel's funding transaction has
 * been spent. */
static void handle_outpoints_spent(struct daemon *daemon, const u8 *msg)
{
	struct short_channel_id *scids;
	u32 blockheight;

	if (!fromwire_gossipd_outpoints_spent(msg, msg, &blockheight, &scids))
		master_badmsg(WIRE_GOSSIPD_OUTPOINTS_SPENT, msg);

	for (size_t i = 0; i < tal_count(scids); i++)
		gossmap_manage_channel_spent(daemon->gm, blockheight, scids[i]);
}

/*~ This routine handles all the commands from lightningd. */
static struct io_plan *recv_req(struct io_conn *conn,
				const u8 *msg,
				struct daemon *daemon)
{
	enum gossipd_wire t = fromwire_peektype(msg);

	switch (t) {
	case WIRE_GOSSIPD_INIT:
		gossip_init(daemon, msg);
		goto done;

	case WIRE_GOSSIPD_GET_TXOUT_REPLY:
		gossmap_manage_handle_get_txout_reply(daemon->gm, msg);
		goto done;

	case WIRE_GOSSIPD_OUTPOINTS_SPENT:
		handle_outpoints_spent(daemon, msg);
		goto done;

	case WIRE_GOSSIPD_NEW_BLOCKHEIGHT:
		new_blockheight(daemon, msg);
		goto done;

	case WIRE_GOSSIPD_ADDGOSSIP:
		inject_gossip(daemon, msg);
		goto done;

	case WIRE_GOSSIPD_GET_ADDRS:
		return handle_get_address(conn, daemon, msg);

	case WIRE_GOSSIPD_DEV_MEMLEAK:
		if (daemon->developer) {
			dev_gossip_memleak(daemon, msg);
			goto done;
		}
		/* fall thru */
	case WIRE_GOSSIPD_DEV_SET_TIME:
		if (daemon->developer) {
			dev_gossip_set_time(daemon, msg);
			goto done;
		}
		/* fall thru */

	/* We send these, we don't receive them */
	case WIRE_GOSSIPD_INIT_CUPDATE:
	case WIRE_GOSSIPD_INIT_NANNOUNCE:
	case WIRE_GOSSIPD_INIT_REPLY:
	case WIRE_GOSSIPD_GET_TXOUT:
	case WIRE_GOSSIPD_DEV_MEMLEAK_REPLY:
	case WIRE_GOSSIPD_ADDGOSSIP_REPLY:
	case WIRE_GOSSIPD_NEW_BLOCKHEIGHT_REPLY:
	case WIRE_GOSSIPD_GET_ADDRS_REPLY:
	case WIRE_GOSSIPD_REMOTE_CHANNEL_UPDATE:
	case WIRE_GOSSIPD_CONNECT_TO_PEER:
		break;
	}

	/* Master shouldn't give bad requests. */
	status_failed(STATUS_FAIL_MASTER_IO, "%i: %s",
		      t, tal_hex(tmpctx, msg));

done:
	return daemon_conn_read_next(conn, daemon->master);
}

int main(int argc, char *argv[])
{
	struct daemon *daemon;
	bool developer;

	setup_locale();

	developer = subdaemon_setup(argc, argv);

	daemon = tal(NULL, struct daemon);
	daemon->developer = developer;
	daemon->dev_gossip_time = NULL;
	daemon->peers = tal(daemon, struct peer_node_id_map);
	peer_node_id_map_init(daemon->peers);
	daemon->deferred_txouts = tal_arr(daemon, struct short_channel_id, 0);
	daemon->current_blockheight = 0; /* i.e. unknown */

	/* Tell the ecdh() function how to talk to hsmd */
	ecdh_hsmd_setup(HSM_FD, status_failed);

	/* Note the use of time_mono() here.  That's a monotonic clock, which
	 * is really useful: it can only be used to measure relative events
	 * (there's no correspondence to time-since-Ken-grew-a-beard or
	 * anything), but unlike time_now(), this will never jump backwards by
	 * half a second and leave me wondering how my tests failed CI! */
	timers_init(&daemon->timers, time_mono());

	/* Our daemons always use STDIN for commands from lightningd. */
	daemon->master = daemon_conn_new(daemon, STDIN_FILENO,
					 recv_req, NULL, daemon);
	tal_add_destructor(daemon->master, master_or_connectd_gone);

	status_setup_async(daemon->master);

	/* This loop never exits.  io_loop() only returns if a timer has
	 * expired, or io_break() is called, or all fds are closed.  We don't
	 * use io_break and closing the lightningd fd calls master_gone()
	 * which exits. */
	for (;;) {
		struct timer *expired = NULL;
		io_loop(&daemon->timers, &expired);

		timer_expired(expired);
	}
}

/*~ Note that the actual routing stuff is in routing.c; you might want to
 * check that out later.
 *
 * But that's the last of the global daemons.  We now move on to the first of
 * the per-peer daemons: openingd/openingd.c.
 */
