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
#include <common/private_channel_announcement.h>
#include <common/pseudorand.h>
#include <common/status.h>
#include <common/subdaemon.h>
#include <common/timeout.h>
#include <common/type_to_string.h>
#include <common/wire_error.h>
#include <connectd/connectd_gossipd_wiregen.h>
#include <errno.h>
#include <gossipd/gossip_generation.h>
#include <gossipd/gossip_store_wiregen.h>
#include <gossipd/gossipd.h>
#include <gossipd/gossipd_peerd_wiregen.h>
#include <gossipd/gossipd_wiregen.h>
#include <gossipd/queries.h>
#include <gossipd/routing.h>
#include <gossipd/seeker.h>
#include <sodium/crypto_aead_chacha20poly1305.h>

/*~ A channel consists of a `struct half_chan` for each direction, each of
 * which has a `flags` word from the `channel_update`; bit 1 is
 * ROUTING_FLAGS_DISABLED in the `channel_update`.  But we also keep a local
 * whole-channel flag which indicates it's not available; we use this when a
 * peer disconnects, and generate a `channel_update` to tell the world lazily
 * when someone asks. */
static void peer_disable_channels(struct daemon *daemon, const struct node *node)
{
	/* If this peer had a channel with us, mark it disabled. */
	struct chan_map_iter i;
	const struct chan *c;

	for (c = first_chan(node, &i); c; c = next_chan(node, &i)) {
		int direction;
		if (!local_direction(daemon->rstate, c, &direction))
			continue;
		local_disable_chan(daemon, c, direction);
	}
}

/*~ This cancels the soft-disables when the peer reconnects. */
static void peer_enable_channels(struct daemon *daemon, const struct node *node)
{
	/* If this peer had a channel with us, mark it disabled. */
	struct chan_map_iter i;
	const struct chan *c;

	for (c = first_chan(node, &i); c; c = next_chan(node, &i)) {
		int direction;
		if (!local_direction(daemon->rstate, c, &direction))
			continue;
		local_enable_chan(daemon, c, direction);
	}
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
	struct node *node;

	/* Remove it from the peers list */
	list_del_from(&peer->daemon->peers, &peer->list);

	/* If we have a channel with this peer, disable it. */
	node = get_node(peer->daemon->rstate, &peer->id);
	if (node)
		peer_disable_channels(peer->daemon, node);
}

/* Search for a peer. */
struct peer *find_peer(struct daemon *daemon, const struct node_id *id)
{
	struct peer *peer;

	list_for_each(&daemon->peers, peer, list)
		if (node_id_eq(&peer->id, id))
			return peer;
	return NULL;
}

/* Increase a peer's gossip_counter, if peer not NULL */
void peer_supplied_good_gossip(struct peer *peer, size_t amount)
{
	if (peer)
		peer->gossip_counter += amount;
}

/* Queue a gossip message for the peer: connectd simply forwards it to
 * the peer. */
void queue_peer_msg(struct peer *peer, const u8 *msg TAKES)
{
	u8 *outermsg = towire_gossipd_send_gossip(NULL, &peer->id, msg);
	daemon_conn_send(peer->daemon->connectd, take(outermsg));

	if (taken(msg))
		tal_free(msg);
}

/*~ We have a helper for messages from the store. */
void queue_peer_from_store(struct peer *peer,
			   const struct broadcastable *bcast)
{
	struct gossip_store *gs = peer->daemon->rstate->gs;
	queue_peer_msg(peer, take(gossip_store_get(NULL, gs, bcast->index)));
}

/*~ We don't actually keep node_announcements in memory; we keep them in
 * a file called `gossip_store`.  If we need some node details, we reload
 * and reparse.  It's slow, but generally rare. */
static bool get_node_announcement(const tal_t *ctx,
				  struct daemon *daemon,
				  const struct node *n,
				  u8 rgb_color[3],
				  u8 alias[32],
				  u8 **features,
				  struct wireaddr **wireaddrs,
				  struct lease_rates **rates)
{
	const u8 *msg;
	struct node_id id;
	secp256k1_ecdsa_signature signature;
	u32 timestamp;
	u8 *addresses;
	struct tlv_node_ann_tlvs *na_tlvs;

	if (!n->bcast.index)
		return false;

	msg = gossip_store_get(tmpctx, daemon->rstate->gs, n->bcast.index);

	/* Note: validity of node_id is already checked. */
	na_tlvs = tlv_node_ann_tlvs_new(ctx);
	if (!fromwire_node_announcement(ctx, msg,
					&signature, features,
					&timestamp,
					&id, rgb_color, alias,
					&addresses,
					na_tlvs)) {
		status_broken("Bad local node_announcement @%u: %s",
			      n->bcast.index, tal_hex(tmpctx, msg));
		return false;
	}

	if (!node_id_eq(&id, &n->id) || timestamp != n->bcast.timestamp) {
		status_broken("Wrong node_announcement @%u:"
			      " expected %s timestamp %u "
			      " got %s timestamp %u",
			      n->bcast.index,
			      type_to_string(tmpctx, struct node_id, &n->id),
			      timestamp,
			      type_to_string(tmpctx, struct node_id, &id),
			      n->bcast.timestamp);
		return false;
	}

	*wireaddrs = fromwire_wireaddr_array(ctx, addresses);
	*rates = tal_steal(ctx, na_tlvs->option_will_fund);

	tal_free(addresses);
	return true;
}

/* Version which also does nodeid lookup */
static bool get_node_announcement_by_id(const tal_t *ctx,
					struct daemon *daemon,
					const struct node_id *node_id,
					u8 rgb_color[3],
					u8 alias[32],
					u8 **features,
					struct wireaddr **wireaddrs,
					struct lease_rates **rates)
{
	struct node *n = get_node(daemon->rstate, node_id);
	if (!n)
		return false;

	return get_node_announcement(ctx, daemon, n, rgb_color, alias,
				     features, wireaddrs, rates);
}

/*~Routines to handle gossip messages from peer, forwarded by subdaemons.
 *-----------------------------------------------------------------------
 *
 * It's not the subdaemon's fault if they're malformed or invalid; so these
 * all return an error packet which gets sent back to the subdaemon in that
 * case.
 */

/* The routing code checks that it's basically valid, returning an
 * error message for the peer or NULL.  NULL means it's OK, but the
 * message might be redundant, in which case scid is also NULL.
 * Otherwise `scid` gives us the short_channel_id claimed by the
 * message, and puts the announcemnt on an internal 'pending'
 * queue.  We'll send a request to lightningd to look it up, and continue
 * processing in `handle_txout_reply`. */
static const u8 *handle_channel_announcement_msg(struct daemon *daemon,
						 struct peer *peer,
						 const u8 *msg)
{
	const struct short_channel_id *scid;
	const u8 *err;

	/* If it's OK, tells us the short_channel_id to lookup; it notes
	 * if this is the unknown channel the peer was looking for (in
	 * which case, it frees and NULLs that ptr) */
	err = handle_channel_announcement(daemon->rstate, msg,
					  daemon->current_blockheight,
					  &scid, peer);
	if (err)
		return err;
	else if (scid) {
		/* We give them some grace period, in case we don't know about
		 * block yet. */
		if (daemon->current_blockheight == 0
		    || !is_scid_depth_announceable(scid,
						   daemon->current_blockheight)) {
			tal_arr_expand(&daemon->deferred_txouts, *scid);
		} else {
			daemon_conn_send(daemon->master,
					 take(towire_gossipd_get_txout(NULL,
								      scid)));
		}
	}
	return NULL;
}

static u8 *handle_channel_update_msg(struct peer *peer, const u8 *msg)
{
	struct short_channel_id unknown_scid;
	/* Hand the channel_update to the routing code */
	u8 *err;

	unknown_scid.u64 = 0;
	err = handle_channel_update(peer->daemon->rstate, msg, peer,
				    &unknown_scid, false);
	if (err)
		return err;

	/* If it's an unknown channel, ask someone about it */
	if (unknown_scid.u64 != 0)
		query_unknown_channel(peer->daemon, peer, &unknown_scid);

	/*~ As a nasty compromise in the spec, we only forward `channel_announce`
	 * once we have a `channel_update`; the channel isn't *usable* for
	 * routing until you have both anyway.  For this reason, we might have
	 * just sent out our own channel_announce, so we check if it's time to
	 * send a node_announcement too. */
	maybe_send_own_node_announce(peer->daemon, false);
	return NULL;
}

static u8 *handle_node_announce(struct peer *peer, const u8 *msg)
{
	bool was_unknown = false;
	u8 *err;

	err = handle_node_announcement(peer->daemon->rstate, msg, peer,
				       &was_unknown);
	if (was_unknown)
		query_unknown_node(peer->daemon->seeker, peer);
	return err;
}

static void handle_local_channel_announcement(struct daemon *daemon, const u8 *msg)
{
	u8 *cannouncement;
	const u8 *err;
	struct node_id id;
	struct peer *peer;

	if (!fromwire_gossipd_local_channel_announcement(msg, msg,
							 &id,
							 &cannouncement))
		master_badmsg(WIRE_GOSSIPD_LOCAL_CHANNEL_ANNOUNCEMENT, msg);

	/* We treat it OK even if peer has disconnected since (unlikely though!) */
	peer = find_peer(daemon, &id);
	if (!peer)
		status_broken("Unknown peer %s for local_channel_announcement",
			      type_to_string(tmpctx, struct node_id, &id));

	err = handle_channel_announcement_msg(daemon, peer, cannouncement);
	if (err) {
		status_broken("peer %s invalid local_channel_announcement %s (%s)",
			      type_to_string(tmpctx, struct node_id, &id),
			      tal_hex(tmpctx, msg),
			      tal_hex(tmpctx, err));
	}
}


/* channeld (via lightningd) tells us about (as-yet?) unannounce channel.
 * It needs us to put it in gossip_store. */
static void handle_local_private_channel(struct daemon *daemon, const u8 *msg)
{
	struct node_id id;
	struct amount_sat capacity;
	u8 *features;
	struct short_channel_id scid;
	const u8 *cannounce;

	if (!fromwire_gossipd_local_private_channel(msg, msg,
						    &id, &capacity, &scid,
						    &features))
		master_badmsg(WIRE_GOSSIPD_LOCAL_PRIVATE_CHANNEL, msg);

	cannounce = private_channel_announcement(tmpctx,
						 &scid,
						 &daemon->id,
						 &id,
						 features);

	if (!routing_add_private_channel(daemon->rstate, &id, capacity,
					 cannounce, 0)) {
		status_peer_broken(&id, "bad add_private_channel %s",
				   tal_hex(tmpctx, cannounce));
	}
}

/*~ This is where connectd tells us about a new peer we might want to
 *  gossip with. */
static void connectd_new_peer(struct daemon *daemon, const u8 *msg)
{
	struct peer *peer = tal(daemon, struct peer);
	struct node *node;

	if (!fromwire_gossipd_new_peer(msg, &peer->id,
				      &peer->gossip_queries_feature)) {
		status_failed(STATUS_FAIL_INTERNAL_ERROR,
			      "Bad new_peer msg from connectd: %s",
			      tal_hex(tmpctx, msg));
	}

	if (find_peer(daemon, &peer->id)) {
		status_broken("Peer %s already here?",
			      type_to_string(tmpctx, struct node_id, &peer->id));
		tal_free(find_peer(daemon, &peer->id));
	}

	/* Populate the rest of the peer info. */
	peer->daemon = daemon;
	peer->gossip_counter = 0;
	peer->scid_queries = NULL;
	peer->scid_query_idx = 0;
	peer->scid_query_nodes = NULL;
	peer->scid_query_nodes_idx = 0;
	peer->scid_query_outstanding = false;
	peer->range_replies = NULL;
	peer->query_channel_range_cb = NULL;

	/* We keep a list so we can find peer by id */
	list_add_tail(&peer->daemon->peers, &peer->list);
	tal_add_destructor(peer, destroy_peer);

	node = get_node(daemon->rstate, &peer->id);
	if (node)
		peer_enable_channels(daemon, node);

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
			      type_to_string(tmpctx, struct node_id, &id));
	tal_free(peer);
}

/*~ lightningd asks us if we know any addresses for a given id. */
static struct io_plan *handle_get_address(struct io_conn *conn,
					  struct daemon *daemon,
					  const u8 *msg)
{
	struct node_id id;
	u8 rgb_color[3];
	u8 alias[32];
	u8 *features;
	struct wireaddr *addrs;
	struct lease_rates *rates;

	if (!fromwire_gossipd_get_addrs(msg, &id))
		master_badmsg(WIRE_GOSSIPD_GET_ADDRS, msg);

	if (!get_node_announcement_by_id(tmpctx, daemon, &id,
					 rgb_color, alias, &features, &addrs,
					 &rates))
		addrs = NULL;

	daemon_conn_send(daemon->master,
			 take(towire_gossipd_get_addrs_reply(NULL, addrs)));
	return daemon_conn_read_next(conn, daemon->master);
}

static void handle_recv_gossip(struct daemon *daemon, const u8 *outermsg)
{
	struct node_id id;
	u8 *msg;
	const u8 *err;
	struct peer *peer;

	if (!fromwire_gossipd_recv_gossip(outermsg, outermsg, &id, &msg)) {
		status_failed(STATUS_FAIL_INTERNAL_ERROR,
			      "Bad gossipd_recv_gossip msg from connectd: %s",
			      tal_hex(tmpctx, outermsg));
	}

	peer = find_peer(daemon, &id);
	if (!peer) {
		status_broken("connectd sent gossip msg %s from unknown peer %s",
			      peer_wire_name(fromwire_peektype(msg)),
			      type_to_string(tmpctx, struct node_id, &id));
		return;
	}

	/* These are messages relayed from peer */
	switch ((enum peer_wire)fromwire_peektype(msg)) {
	case WIRE_CHANNEL_ANNOUNCEMENT:
		err = handle_channel_announcement_msg(peer->daemon, peer, msg);
		goto handled_msg;
	case WIRE_CHANNEL_UPDATE:
		err = handle_channel_update_msg(peer, msg);
		goto handled_msg;
	case WIRE_NODE_ANNOUNCEMENT:
		err = handle_node_announce(peer, msg);
		goto handled_msg;
	case WIRE_QUERY_CHANNEL_RANGE:
		err = handle_query_channel_range(peer, msg);
		goto handled_msg;
	case WIRE_REPLY_CHANNEL_RANGE:
		err = handle_reply_channel_range(peer, msg);
		goto handled_msg;
	case WIRE_QUERY_SHORT_CHANNEL_IDS:
		err = handle_query_short_channel_ids(peer, msg);
		goto handled_msg;
	case WIRE_REPLY_SHORT_CHANNEL_IDS_END:
		err = handle_reply_short_channel_ids_end(peer, msg);
		goto handled_msg;

	/* These are non-gossip messages (!is_msg_for_gossipd()) */
	case WIRE_WARNING:
	case WIRE_INIT:
	case WIRE_ERROR:
	case WIRE_PING:
	case WIRE_PONG:
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
	case WIRE_UPDATE_BLOCKHEIGHT:
	case WIRE_CHANNEL_REESTABLISH:
	case WIRE_ANNOUNCEMENT_SIGNATURES:
	case WIRE_GOSSIP_TIMESTAMP_FILTER:
	case WIRE_TX_ADD_INPUT:
	case WIRE_TX_REMOVE_INPUT:
	case WIRE_TX_ADD_OUTPUT:
	case WIRE_TX_REMOVE_OUTPUT:
	case WIRE_TX_COMPLETE:
	case WIRE_TX_SIGNATURES:
	case WIRE_OPEN_CHANNEL2:
	case WIRE_ACCEPT_CHANNEL2:
	case WIRE_INIT_RBF:
	case WIRE_ACK_RBF:
	case WIRE_OBS2_ONION_MESSAGE:
	case WIRE_ONION_MESSAGE:
#if EXPERIMENTAL_FEATURES
	case WIRE_STFU:
#endif
		break;
	}

	status_failed(STATUS_FAIL_INTERNAL_ERROR,
		      "connectd sent unexpected gossip msg %s for peer %s",
		      peer_wire_name(fromwire_peektype(msg)),
		      type_to_string(tmpctx, struct node_id, &peer->id));

handled_msg:
	if (err)
		queue_peer_msg(peer, take(err));
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

/* BOLT #7:
 *
 * A node:
 *  - if a channel's oldest `channel_update`s `timestamp` is older than two weeks
 *    (1209600 seconds):
 *     - MAY prune the channel.
 *     - MAY ignore the channel.
 */
static void gossip_refresh_network(struct daemon *daemon)
{
	u64 now = gossip_time_now(daemon->rstate).ts.tv_sec;
	s64 highwater;
	struct node *n;

	/* Send out 1 day before deadline */
	highwater = now - (GOSSIP_PRUNE_INTERVAL(daemon->rstate->dev_fast_gossip)
			   - GOSSIP_BEFORE_DEADLINE(daemon->rstate->dev_fast_gossip_prune));

	/* Schedule next run now */
	notleak(new_reltimer(&daemon->timers, daemon,
			     time_from_sec(GOSSIP_PRUNE_INTERVAL(daemon->rstate->dev_fast_gossip_prune)/4),
			     gossip_refresh_network, daemon));

	/* Find myself in the network */
	n = get_node(daemon->rstate, &daemon->id);
	if (n) {
		/* Iterate through all outgoing connection and check whether
		 * it's time to re-announce */
		struct chan_map_iter i;
		struct chan *c;

		for (c = first_chan(n, &i); c; c = next_chan(n, &i)) {
			struct half_chan *hc;
			int direction;

			if (!local_direction(daemon->rstate, c, &direction))
				continue;

			hc = &c->half[direction];

			if (!is_halfchan_defined(hc)) {
				/* Connection is not announced yet, so don't even
				 * try to re-announce it */
				continue;
			}

			if (hc->bcast.timestamp > highwater) {
				/* No need to send a keepalive update message */
				continue;
			}

			status_debug("Sending keepalive channel_update"
				     " for %s/%u",
				     type_to_string(tmpctx,
						    struct short_channel_id,
						    &c->scid), direction);
			refresh_local_channel(daemon, c, direction);
		}
	}

	/* Now we've refreshed our channels, we can prune without clobbering
	 * them */
	route_prune(daemon->rstate);
}

/* Disables all channels connected to our node. */
static void gossip_disable_local_channels(struct daemon *daemon)
{
	struct node *local_node = get_node(daemon->rstate, &daemon->id);
	struct chan_map_iter i;
	struct chan *c;

	/* We don't have a local_node, so we don't have any channels yet
	 * either */
	if (!local_node)
		return;

	for (c = first_chan(local_node, &i); c; c = next_chan(local_node, &i))
		local_disable_chan(daemon, c, half_chan_idx(local_node, c));
}

struct peer *random_peer(struct daemon *daemon,
			 bool (*check_peer)(const struct peer *peer))
{
	u64 target = UINT64_MAX;
	struct peer *best = NULL, *i;

	/* Reservoir sampling */
	list_for_each(&daemon->peers, i, list) {
		u64 r;

		if (!check_peer(i))
			continue;

		r = pseudorand_u64();
		if (r <= target) {
			best = i;
			target = r;
		}
	}
	return best;
}

/*~ Parse init message from lightningd: starts the daemon properly. */
static void gossip_init(struct daemon *daemon, const u8 *msg)
{
	u32 *dev_gossip_time;
	bool dev_fast_gossip, dev_fast_gossip_prune;
	u32 timestamp;

	if (!fromwire_gossipd_init(daemon, msg,
				     &chainparams,
				     &daemon->our_features,
				     &daemon->id,
				     daemon->rgb,
				     daemon->alias,
				     &daemon->announcable,
				     &dev_gossip_time,
				     &dev_fast_gossip,
				     &dev_fast_gossip_prune)) {
		master_badmsg(WIRE_GOSSIPD_INIT, msg);
	}

	daemon->rstate = new_routing_state(daemon,
					   &daemon->id,
					   &daemon->peers,
					   &daemon->timers,
					   take(dev_gossip_time),
					   dev_fast_gossip,
					   dev_fast_gossip_prune);

	/* Load stored gossip messages, get last modified time of file */
	timestamp = gossip_store_load(daemon->rstate, daemon->rstate->gs);

	/* If last_timestamp was > modified time of file, reduce it.
	 * Usually it's capped to "now", but in the reload case it needs to
	 * be the gossip_store mtime. */
	if (daemon->rstate->last_timestamp > timestamp)
		daemon->rstate->last_timestamp = timestamp;

	/* Now disable all local channels, they can't be connected yet. */
	gossip_disable_local_channels(daemon);

	/* If that announced channels, we can announce ourselves (options
	 * or addresses might have changed!) */
	maybe_send_own_node_announce(daemon, true);

	/* Start the twice- weekly refresh timer. */
	notleak(new_reltimer(&daemon->timers, daemon,
			     time_from_sec(GOSSIP_PRUNE_INTERVAL(daemon->rstate->dev_fast_gossip_prune) / 4),
			     gossip_refresh_network, daemon));

	/* Fire up the seeker! */
	daemon->seeker = new_seeker(daemon);

	/* connectd is already started, and uses this fd to feed/recv gossip. */
	daemon->connectd = daemon_conn_new(daemon, CONNECTD_FD,
					   connectd_req,
					   maybe_send_query_responses, daemon);

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
		const struct short_channel_id *scid
			= &daemon->deferred_txouts[i];

		if (!is_scid_depth_announceable(scid,
						daemon->current_blockheight))
			continue;

		/* short_channel_id is deep enough, now ask about it. */
		daemon_conn_send(daemon->master,
				 take(towire_gossipd_get_txout(NULL, scid)));

		tal_arr_remove(&daemon->deferred_txouts, i);
		i--;
	}

	daemon_conn_send(daemon->master,
			 take(towire_gossipd_new_blockheight_reply(NULL)));
}

#if DEVELOPER
/* Another testing hack */
static void dev_gossip_suppress(struct daemon *daemon, const u8 *msg)
{
	if (!fromwire_gossipd_dev_suppress(msg))
		master_badmsg(WIRE_GOSSIPD_DEV_SUPPRESS, msg);

	status_unusual("Suppressing all gossip");
	dev_suppress_gossip = true;
}

static void dev_gossip_memleak(struct daemon *daemon, const u8 *msg)
{
	struct htable *memtable;
	bool found_leak;

	memtable = memleak_find_allocations(tmpctx, msg, msg);

	/* Now delete daemon and those which it has pointers to. */
	memleak_remove_region(memtable, daemon, sizeof(*daemon));

	found_leak = dump_memleak(memtable, memleak_status_broken);
	daemon_conn_send(daemon->master,
			 take(towire_gossipd_dev_memleak_reply(NULL,
							      found_leak)));
}

static void dev_compact_store(struct daemon *daemon, const u8 *msg)
{
	bool done = gossip_store_compact(daemon->rstate->gs);

	daemon_conn_send(daemon->master,
			 take(towire_gossipd_dev_compact_store_reply(NULL,
								    done)));
}

static void dev_gossip_set_time(struct daemon *daemon, const u8 *msg)
{
	u32 time;

	if (!fromwire_gossipd_dev_set_time(msg, &time))
		master_badmsg(WIRE_GOSSIPD_DEV_SET_TIME, msg);
	if (!daemon->rstate->gossip_time)
		daemon->rstate->gossip_time = tal(daemon->rstate, struct timeabs);
	daemon->rstate->gossip_time->ts.tv_sec = time;
	daemon->rstate->gossip_time->ts.tv_nsec = 0;
}
#endif /* DEVELOPER */

/*~ We queue incoming channel_announcement pending confirmation from lightningd
 * that it really is an unspent output.  Here's its reply. */
static void handle_txout_reply(struct daemon *daemon, const u8 *msg)
{
	struct short_channel_id scid;
	u8 *outscript;
	struct amount_sat sat;
	bool good;

	if (!fromwire_gossipd_get_txout_reply(msg, msg, &scid, &sat, &outscript))
		master_badmsg(WIRE_GOSSIPD_GET_TXOUT_REPLY, msg);

	/* Outscript is NULL if it's not an unspent output */
	good = handle_pending_cannouncement(daemon, daemon->rstate,
					    &scid, sat, outscript);

	/* If we looking specifically for this, we no longer are. */
	remove_unknown_scid(daemon->seeker, &scid, good);

	/* Anywhere we might have announced a channel, we check if it's time to
	 * announce ourselves (ie. if we just announced our own first channel) */
	maybe_send_own_node_announce(daemon, false);
}

/*~ lightningd tells us when about a gossip message directly, when told to by
 * the addgossip RPC call.  That's usually used when a plugin gets an update
 * returned in an payment error. */
static void inject_gossip(struct daemon *daemon, const u8 *msg)
{
	u8 *goss;
	const u8 *errmsg;
	const char *err;

	if (!fromwire_gossipd_addgossip(msg, msg, &goss))
		master_badmsg(WIRE_GOSSIPD_ADDGOSSIP, msg);

	switch (fromwire_peektype(goss)) {
	case WIRE_CHANNEL_ANNOUNCEMENT:
		errmsg = handle_channel_announcement_msg(daemon, NULL, goss);
		break;
	case WIRE_NODE_ANNOUNCEMENT:
		errmsg = handle_node_announcement(daemon->rstate, goss,
						  NULL, NULL);
		break;
	case WIRE_CHANNEL_UPDATE:
		errmsg = handle_channel_update(daemon->rstate, goss,
					       NULL, NULL, true);
		break;
	default:
		err = tal_fmt(tmpctx, "unknown gossip type %i",
			      fromwire_peektype(goss));
		goto err_extracted;
	}

	/* The APIs above are designed to send error messages back to peers:
	 * we extract the raw string instead. */
	if (errmsg) {
		err = sanitize_error(tmpctx, errmsg, NULL);
		tal_free(errmsg);
	} else
		/* Send empty string if no error. */
		err = "";

err_extracted:
	daemon_conn_send(daemon->master,
			 take(towire_gossipd_addgossip_reply(NULL, err)));
}

static void handle_new_lease_rates(struct daemon *daemon, const u8 *msg)
{
	struct lease_rates *rates = tal(daemon, struct lease_rates);

	if (!fromwire_gossipd_new_lease_rates(msg, rates))
		master_badmsg(WIRE_GOSSIPD_NEW_LEASE_RATES, msg);

	daemon->rates = tal_free(daemon->rates);
	if (!lease_rates_empty(rates))
		daemon->rates = rates;
	else
		tal_free(rates);

	/* Send the update over to the peer */
	maybe_send_own_node_announce(daemon, false);
}

/*~ This is where lightningd tells us that a channel's funding transaction has
 * been spent. */
static void handle_outpoint_spent(struct daemon *daemon, const u8 *msg)
{
	struct short_channel_id scid;
	struct chan *chan;
	struct routing_state *rstate = daemon->rstate;
	if (!fromwire_gossipd_outpoint_spent(msg, &scid))
		master_badmsg(WIRE_GOSSIPD_OUTPOINT_SPENT, msg);

	chan = get_channel(rstate, &scid);
	if (chan) {
		status_debug(
		    "Deleting channel %s due to the funding outpoint being "
		    "spent",
		    type_to_string(msg, struct short_channel_id, &scid));
		/* Suppress any now-obsolete updates/announcements */
		add_to_txout_failures(rstate, &scid);
		remove_channel_from_store(rstate, chan);
		/* Freeing is sufficient since everything else is allocated off
		 * of the channel and this takes care of unregistering
		 * the channel */
		free_chan(rstate, chan);
	}
}

/*~ This is sent by lightningd when it kicks off 'closingd': we disable it
 * in both directions.
 *
 * We'll leave it to handle_outpoint_spent to delete the channel from our view
 * once the close gets confirmed. This avoids having strange states in which the
 * channel is list in our peer list but won't be returned when listing public
 * channels. This does not send out updates since that's triggered by the peer
 * connection closing.
 */
static void handle_local_channel_close(struct daemon *daemon, const u8 *msg)
{
	struct short_channel_id scid;
	struct chan *chan;
	struct routing_state *rstate = daemon->rstate;
	if (!fromwire_gossipd_local_channel_close(msg, &scid))
		master_badmsg(WIRE_GOSSIPD_LOCAL_CHANNEL_CLOSE, msg);

	chan = get_channel(rstate, &scid);
	if (chan) {
		int direction;

		if (!local_direction(rstate, chan, &direction)) {
			status_broken("Non-local channel close %s",
				      type_to_string(tmpctx,
						     struct short_channel_id,
						     &scid));
		} else {
			local_disable_chan(daemon, chan, direction);
		}
	}
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
		handle_txout_reply(daemon, msg);
		goto done;

	case WIRE_GOSSIPD_OUTPOINT_SPENT:
		handle_outpoint_spent(daemon, msg);
		goto done;

	case WIRE_GOSSIPD_LOCAL_CHANNEL_CLOSE:
		handle_local_channel_close(daemon, msg);
		goto done;

	case WIRE_GOSSIPD_NEW_BLOCKHEIGHT:
		new_blockheight(daemon, msg);
		goto done;

	case WIRE_GOSSIPD_ADDGOSSIP:
		inject_gossip(daemon, msg);
		goto done;

	case WIRE_GOSSIPD_NEW_LEASE_RATES:
		handle_new_lease_rates(daemon, msg);
		goto done;

	case WIRE_GOSSIPD_GET_ADDRS:
		return handle_get_address(conn, daemon, msg);

	case WIRE_GOSSIPD_USED_LOCAL_CHANNEL_UPDATE:
		handle_used_local_channel_update(daemon, msg);
		goto done;

	case WIRE_GOSSIPD_LOCAL_CHANNEL_UPDATE:
		handle_local_channel_update(daemon, msg);
		goto done;

	case WIRE_GOSSIPD_LOCAL_CHANNEL_ANNOUNCEMENT:
		handle_local_channel_announcement(daemon, msg);
		goto done;

	case WIRE_GOSSIPD_LOCAL_PRIVATE_CHANNEL:
		handle_local_private_channel(daemon, msg);
		goto done;
#if DEVELOPER
	case WIRE_GOSSIPD_DEV_SET_MAX_SCIDS_ENCODE_SIZE:
		dev_set_max_scids_encode_size(daemon, msg);
		goto done;
	case WIRE_GOSSIPD_DEV_SUPPRESS:
		dev_gossip_suppress(daemon, msg);
		goto done;
	case WIRE_GOSSIPD_DEV_MEMLEAK:
		dev_gossip_memleak(daemon, msg);
		goto done;
	case WIRE_GOSSIPD_DEV_COMPACT_STORE:
		dev_compact_store(daemon, msg);
		goto done;
	case WIRE_GOSSIPD_DEV_SET_TIME:
		dev_gossip_set_time(daemon, msg);
		goto done;
#else
	case WIRE_GOSSIPD_DEV_SET_MAX_SCIDS_ENCODE_SIZE:
	case WIRE_GOSSIPD_DEV_SUPPRESS:
	case WIRE_GOSSIPD_DEV_MEMLEAK:
	case WIRE_GOSSIPD_DEV_COMPACT_STORE:
	case WIRE_GOSSIPD_DEV_SET_TIME:
		break;
#endif /* !DEVELOPER */

	/* We send these, we don't receive them */
	case WIRE_GOSSIPD_INIT_REPLY:
	case WIRE_GOSSIPD_GET_TXOUT:
	case WIRE_GOSSIPD_DEV_MEMLEAK_REPLY:
	case WIRE_GOSSIPD_DEV_COMPACT_STORE_REPLY:
	case WIRE_GOSSIPD_ADDGOSSIP_REPLY:
	case WIRE_GOSSIPD_NEW_BLOCKHEIGHT_REPLY:
	case WIRE_GOSSIPD_GET_ADDRS_REPLY:
	case WIRE_GOSSIPD_GOT_LOCAL_CHANNEL_UPDATE:
		break;
	}

	/* Master shouldn't give bad requests. */
	status_failed(STATUS_FAIL_MASTER_IO, "%i: %s",
		      t, tal_hex(tmpctx, msg));

done:
	return daemon_conn_read_next(conn, daemon->master);
}

/* This is called when lightningd closes its connection to us.  We simply
 * exit. */
static void master_gone(struct daemon_conn *master UNUSED)
{
	daemon_shutdown();
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
	daemon->deferred_txouts = tal_arr(daemon, struct short_channel_id, 0);
	daemon->node_announce_timer = NULL;
	daemon->current_blockheight = 0; /* i.e. unknown */
	daemon->rates = NULL;
	list_head_init(&daemon->deferred_updates);

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
	tal_add_destructor(daemon->master, master_gone);

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
