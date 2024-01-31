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
#include <common/wireaddr.h>
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

const struct node_id *peer_node_id(const struct peer *peer)
{
	return &peer->id;
}

bool peer_node_id_eq(const struct peer *peer, const struct node_id *node_id)
{
	return node_id_eq(&peer->id, node_id);
}

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

	/* Remove it from the peers table */
	peer_node_id_map_del(peer->daemon->peers, peer);;

	/* If we have a channel with this peer, disable it. */
	node = get_node(peer->daemon->rstate, &peer->id);
	if (node)
		peer_disable_channels(peer->daemon, node);

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

static void queue_priv_update(struct peer *peer,
			      const struct broadcastable *bcast)
{
	struct gossip_store *gs = peer->daemon->rstate->gs;
	queue_peer_msg(peer,
		       take(gossip_store_get_private_update(NULL, gs,
							    bcast->index)));
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
	if (!fromwire_node_announcement(ctx, msg,
					&signature, features,
					&timestamp,
					&id, rgb_color, alias,
					&addresses,
					&na_tlvs)) {
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
						 const struct node_id *source_peer,
						 const u8 *msg)
{
	const struct short_channel_id *scid;
	const u8 *err;

	/* If it's OK, tells us the short_channel_id to lookup; it notes
	 * if this is the unknown channel the peer was looking for (in
	 * which case, it frees and NULLs that ptr) */
	err = handle_channel_announcement(daemon->rstate, msg,
					  daemon->current_blockheight,
					  &scid, source_peer);
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
	err = handle_channel_update(peer->daemon->rstate, msg, &peer->id,
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

	err = handle_node_announcement(peer->daemon->rstate, msg, &peer->id,
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

	if (!fromwire_gossipd_local_channel_announcement(msg, msg,
							 &id,
							 &cannouncement))
		master_badmsg(WIRE_GOSSIPD_LOCAL_CHANNEL_ANNOUNCEMENT, msg);

	err = handle_channel_announcement_msg(daemon, &id, cannouncement);
	if (err) {
		status_peer_broken(&id, "invalid local_channel_announcement %s (%s)",
				   tal_hex(tmpctx, msg),
				   tal_hex(tmpctx, err));
	}
}


/* lightningd tells us it has discovered and verified new `remote_addr`.
 * We can use this to update our node announcement. */
static void handle_discovered_ip(struct daemon *daemon, const u8 *msg)
{
	struct wireaddr discovered_ip;
	size_t count_announceable;

	if (!fromwire_gossipd_discovered_ip(msg, &discovered_ip))
		master_badmsg(WIRE_GOSSIPD_DISCOVERED_IP, msg);

	switch (discovered_ip.type) {
	case ADDR_TYPE_IPV4:
		if (daemon->discovered_ip_v4 != NULL &&
		    wireaddr_eq_without_port(daemon->discovered_ip_v4,
					     &discovered_ip))
			break;
		tal_free(daemon->discovered_ip_v4);
		daemon->discovered_ip_v4 = tal_dup(daemon, struct wireaddr,
						 &discovered_ip);
		goto update_node_annoucement;
	case ADDR_TYPE_IPV6:
		if (daemon->discovered_ip_v6 != NULL &&
		    wireaddr_eq_without_port(daemon->discovered_ip_v6,
					     &discovered_ip))
			break;
		tal_free(daemon->discovered_ip_v6);
		daemon->discovered_ip_v6 = tal_dup(daemon, struct wireaddr,
						 &discovered_ip);
		goto update_node_annoucement;

	/* ignore all other cases */
	case ADDR_TYPE_TOR_V2_REMOVED:
	case ADDR_TYPE_TOR_V3:
	case ADDR_TYPE_DNS:
		break;
	}
	return;

update_node_annoucement:
	count_announceable = tal_count(daemon->announceable);
	if ((daemon->ip_discovery == OPT_AUTOBOOL_AUTO && count_announceable == 0) ||
	     daemon->ip_discovery == OPT_AUTOBOOL_TRUE)
		status_debug("Update our node_announcement for discovered address: %s",
			     fmt_wireaddr(tmpctx, &discovered_ip));
	maybe_send_own_node_announce(daemon, false);
}

/* Statistically, how many peers to we tell about each channel? */
#define GOSSIP_SPAM_REDUNDANCY 5

/* BOLT #7:
 *   - if the `gossip_queries` feature is negotiated:
 *     - MUST NOT relay any gossip messages it did not generate itself,
 *       unless explicitly requested.
 */
/* i.e. the strong implication is that we spam our own gossip aggressively!
 * "Look at me!"  "Look at me!!!!".
 */
static void dump_our_gossip(struct daemon *daemon, struct peer *peer)
{
	struct node *me;
	struct chan_map_iter it;
	const struct chan *chan, **chans = tal_arr(tmpctx, const struct chan *, 0);
	size_t num_to_send;

	/* Find ourselves; if no channels, nothing to send */
	me = get_node(daemon->rstate, &daemon->id);
	if (!me)
		return;

	for (chan = first_chan(me, &it); chan; chan = next_chan(me, &it)) {
		/* Don't leak private channels, unless it's with you! */
		if (!is_chan_public(chan)) {
			int dir = half_chan_idx(me, chan);

			if (node_id_eq(&chan->nodes[!dir]->id, &peer->id)
			    && is_halfchan_defined(&chan->half[dir])) {
				/* There's no announce for this, of course! */
				/* Private channel updates are wrapped in the store. */
				queue_priv_update(peer, &chan->half[dir].bcast);
			}
			continue;
		}

		tal_arr_expand(&chans, chan);
	}

	/* Just in case we have many peers and not all are connecting or
	 * some other corner case, send everything to first few. */
	if (peer_node_id_map_count(daemon->peers) <= GOSSIP_SPAM_REDUNDANCY)
		num_to_send = tal_count(chans);
	else {
		if (tal_count(chans) < GOSSIP_SPAM_REDUNDANCY)
			num_to_send = tal_count(chans);
		else {
			/* Pick victims at random */
			tal_arr_randomize(chans, const struct chan *);
			num_to_send = GOSSIP_SPAM_REDUNDANCY;
		}
	}

	for (size_t i = 0; i < num_to_send; i++) {
		chan = chans[i];

		/* Send channel_announce */
		queue_peer_from_store(peer, &chan->bcast);

		/* Send both channel_updates (if they exist): both help people
		 * use our channel, so we care! */
		for (int dir = 0; dir < 2; dir++) {
			if (is_halfchan_defined(&chan->half[dir]))
				queue_peer_from_store(peer, &chan->half[dir].bcast);
		}
	}

	/* If we have one, we should send our own node_announcement */
	if (me->bcast.index)
		queue_peer_from_store(peer, &me->bcast);
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

	/* We keep a htable so we can find peer by id */
	peer_node_id_map_add(daemon->peers, peer);
	tal_add_destructor(peer, destroy_peer);

	node = get_node(daemon->rstate, &peer->id);
	if (node)
		peer_enable_channels(daemon, node);

	/* Send everything we know about our own channels */
	dump_our_gossip(daemon, peer);

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
		err = handle_channel_announcement_msg(peer->daemon, &id, msg);
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
 * - if the `timestamp` of the latest `channel_update` in
 *   either direction is older than two weeks (1209600 seconds):
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

static void tell_master_local_cupdates(struct daemon *daemon)
{
	struct chan_map_iter i;
	struct chan *c;
	struct node *me;

	me = get_node(daemon->rstate, &daemon->id);
	if (!me)
		return;

	for (c = first_chan(me, &i); c; c = next_chan(me, &i)) {
		struct half_chan *hc;
		int direction;
		const u8 *cupdate;

		/* We don't provide update_channel for unannounced channels */
		if (!is_chan_public(c))
			continue;

		if (!local_direction(daemon->rstate, c, &direction))
			continue;

		hc = &c->half[direction];
		if (!is_halfchan_defined(hc))
			continue;

		cupdate = gossip_store_get(tmpctx,
					   daemon->rstate->gs,
					   hc->bcast.index);
		daemon_conn_send(daemon->master,
				 take(towire_gossipd_init_cupdate(NULL,
								  &c->scid,
								  cupdate)));
	}
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
				     &daemon->announceable,
				     &dev_gossip_time,
				     &dev_fast_gossip,
				     &dev_fast_gossip_prune,
				     &daemon->ip_discovery)) {
		master_badmsg(WIRE_GOSSIPD_INIT, msg);
	}

	daemon->rstate = new_routing_state(daemon,
					   daemon,
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
	tal_add_destructor(daemon->connectd, master_or_connectd_gone);

	/* Tell it about all our local (public) channel_update messages,
	 * so it doesn't unnecessarily regenerate them. */
	tell_master_local_cupdates(daemon);

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

	routing_expire_channels(daemon->rstate, daemon->current_blockheight);

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

	found_leak = dump_memleak(memtable, memleak_status_broken, NULL);
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
	if (!daemon->rstate->dev_gossip_time)
		daemon->rstate->dev_gossip_time = tal(daemon->rstate, struct timeabs);
	daemon->rstate->dev_gossip_time->ts.tv_sec = time;
	daemon->rstate->dev_gossip_time->ts.tv_nsec = 0;
}

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
static void handle_outpoints_spent(struct daemon *daemon, const u8 *msg)
{
	struct short_channel_id *scids;
	u32 blockheight;

	if (!fromwire_gossipd_outpoints_spent(msg, msg, &blockheight, &scids))
		master_badmsg(WIRE_GOSSIPD_OUTPOINTS_SPENT, msg);

	for (size_t i = 0; i < tal_count(scids); i++) {
		struct chan *chan = get_channel(daemon->rstate, &scids[i]);

		if (!chan)
			continue;

		/* We have a current_blockheight, but it's not necessarily
		 * updated first. */
		routing_channel_spent(daemon->rstate, blockheight, chan);
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

	case WIRE_GOSSIPD_OUTPOINTS_SPENT:
		handle_outpoints_spent(daemon, msg);
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

	case WIRE_GOSSIPD_DISCOVERED_IP:
		handle_discovered_ip(daemon, msg);
		goto done;
	case WIRE_GOSSIPD_DEV_SET_MAX_SCIDS_ENCODE_SIZE:
		if (daemon->developer) {
			dev_set_max_scids_encode_size(daemon, msg);
			goto done;
		}
		/* fall thru */
	case WIRE_GOSSIPD_DEV_MEMLEAK:
		if (daemon->developer) {
			dev_gossip_memleak(daemon, msg);
			goto done;
		}
		/* fall thru */
	case WIRE_GOSSIPD_DEV_COMPACT_STORE:
		if (daemon->developer) {
			dev_compact_store(daemon, msg);
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
	case WIRE_GOSSIPD_INIT_REPLY:
	case WIRE_GOSSIPD_GET_TXOUT:
	case WIRE_GOSSIPD_DEV_MEMLEAK_REPLY:
	case WIRE_GOSSIPD_DEV_COMPACT_STORE_REPLY:
	case WIRE_GOSSIPD_ADDGOSSIP_REPLY:
	case WIRE_GOSSIPD_NEW_BLOCKHEIGHT_REPLY:
	case WIRE_GOSSIPD_GET_ADDRS_REPLY:
	case WIRE_GOSSIPD_GOT_LOCAL_CHANNEL_UPDATE:
	case WIRE_GOSSIPD_REMOTE_CHANNEL_UPDATE:
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
	daemon->peers = tal(daemon, struct peer_node_id_map);
	peer_node_id_map_init(daemon->peers);
	daemon->deferred_txouts = tal_arr(daemon, struct short_channel_id, 0);
	daemon->node_announce_timer = NULL;
	daemon->node_announce_regen_timer = NULL;
	daemon->current_blockheight = 0; /* i.e. unknown */
	daemon->rates = NULL;
	daemon->discovered_ip_v4 = NULL;
	daemon->discovered_ip_v6 = NULL;
	daemon->ip_discovery = OPT_AUTOBOOL_AUTO;
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
