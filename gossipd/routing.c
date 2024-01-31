#include "config.h"
#include <bitcoin/chainparams.h>
#include <bitcoin/script.h>
#include <ccan/array_size/array_size.h>
#include <ccan/mem/mem.h>
#include <ccan/tal/str/str.h>
#include <common/daemon_conn.h>
#include <common/gossip_store.h>
#include <common/memleak.h>
#include <common/pseudorand.h>
#include <common/status.h>
#include <common/timeout.h>
#include <common/type_to_string.h>
#include <common/wire_error.h>
#include <gossipd/gossip_store_wiregen.h>
#include <gossipd/gossipd_wiregen.h>
#include <gossipd/queries.h>
#include <gossipd/routing.h>
#include <gossipd/sigcheck.h>
#include <gossipd/txout_failures.h>

#ifndef SUPERVERBOSE
#define SUPERVERBOSE(...)
#endif

/* 365.25 * 24 * 60 / 10 */
#define BLOCKS_PER_YEAR 52596

struct pending_spam_node_announce {
	u8 *node_announcement;
	u32 index;
};

struct pending_node_announce {
	struct routing_state *rstate;
	struct node_id nodeid;
	size_t refcount;
	u8 *node_announcement;
	u32 timestamp;
	u32 index;
	/* If non-NULL this is peer to credit it with */
	struct node_id *source_peer;
	/* required for loading gossip store */
	struct pending_spam_node_announce spam;
};

/* As per the below BOLT #7 quote, we delay forgetting a channel until 12
 * blocks after we see it close.  This gives time for splicing (or even other
 * opens) to replace the channel, and broadcast it after 6 blocks. */
struct dying_channel {
	struct short_channel_id scid;
	u32 deadline_blockheight;
	/* Where the dying_channel marker is in the store. */
	struct broadcastable marker;
};

/* We consider a reasonable gossip rate to be 2 per day, with burst of
 * 4 per day.  So we use a granularity of one hour. */
#define TOKENS_PER_MSG 12
#define TOKEN_MAX (12 * 4)

static u8 update_tokens(const struct routing_state *rstate,
			u8 tokens, u32 prev_timestamp, u32 new_timestamp)
{
	u64 num_tokens = tokens;

	assert(new_timestamp >= prev_timestamp);

	num_tokens += ((new_timestamp - prev_timestamp)
		       / GOSSIP_TOKEN_TIME(rstate->daemon->dev_fast_gossip));
	if (num_tokens > TOKEN_MAX)
		num_tokens = TOKEN_MAX;
	return num_tokens;
}

static bool ratelimit(const struct routing_state *rstate,
		      u8 *tokens, u32 prev_timestamp, u32 new_timestamp)
{
	*tokens = update_tokens(rstate, *tokens, prev_timestamp, new_timestamp);

	/* Now, if we can afford it, pass this message. */
	if (*tokens >= TOKENS_PER_MSG) {
		*tokens -= TOKENS_PER_MSG;
		return true;
	}
	return false;
}

static const struct node_id *
pending_node_announce_keyof(const struct pending_node_announce *a)
{
	return &a->nodeid;
}

static bool pending_node_announce_eq(const struct pending_node_announce *pna,
				     const struct node_id *pc)
{
	return node_id_eq(&pna->nodeid, pc);
}

HTABLE_DEFINE_TYPE(struct pending_node_announce, pending_node_announce_keyof,
		   node_map_hash_key, pending_node_announce_eq,
		   pending_node_map);

/* We keep around announcements for channels until we have an
 * update for them (which gives us their timestamp) */
struct unupdated_channel {
	/* The channel_announcement message */
	const u8 *channel_announce;
	/* The short_channel_id */
	struct short_channel_id scid;
	/* The ids of the nodes */
	struct node_id id[2];
	/* When we added, so we can discard old ones */
	struct timeabs added;
	/* If we loaded from the store, this is where. */
	u32 index;
	/* Channel capacity */
	struct amount_sat sat;
	/* If non-NULL this is peer to credit it with */
	struct node_id *source_peer;
};

static struct unupdated_channel *
get_unupdated_channel(const struct routing_state *rstate,
		      const struct short_channel_id *scid)
{
	return uintmap_get(&rstate->unupdated_chanmap, scid->u64);
}

static void destroy_unupdated_channel(struct unupdated_channel *uc,
				      struct routing_state *rstate)
{
	uintmap_del(&rstate->unupdated_chanmap, uc->scid.u64);
}

static struct node_map *new_node_map(const tal_t *ctx)
{
	struct node_map *map = tal(ctx, struct node_map);
	node_map_init(map);
	return map;
}

/* We use a simple array (with NULL entries) until we have too many. */
static bool node_uses_chan_map(const struct node *node)
{
	return node->chan_map;
}

/* When simple array fills, use a htable. */
static void convert_node_to_chan_map(struct node *node)
{
	assert(!node_uses_chan_map(node));
	node->chan_map = tal(node, struct chan_map);
	chan_map_init_sized(node->chan_map, ARRAY_SIZE(node->chan_arr) + 1);
	assert(node_uses_chan_map(node));
	for (size_t i = 0; i < ARRAY_SIZE(node->chan_arr); i++) {
		chan_map_add(node->chan_map, node->chan_arr[i]);
		node->chan_arr[i] = NULL;
	}
}

static void add_chan(struct node *node, struct chan *chan)
{
	if (!node_uses_chan_map(node)) {
		for (size_t i = 0; i < ARRAY_SIZE(node->chan_arr); i++) {
			if (node->chan_arr[i] == NULL) {
				node->chan_arr[i] = chan;
				return;
			}
		}
		convert_node_to_chan_map(node);
	}

	chan_map_add(node->chan_map, chan);
}

static struct chan *next_chan_arr(const struct node *node,
				  struct chan_map_iter *i)
{
	while (i->i.off < ARRAY_SIZE(node->chan_arr)) {
		if (node->chan_arr[i->i.off])
			return node->chan_arr[i->i.off];
		i->i.off++;
	}
	return NULL;
}

struct chan *first_chan(const struct node *node, struct chan_map_iter *i)
{
	if (!node_uses_chan_map(node)) {
		i->i.off = 0;
		return next_chan_arr(node, i);
	}

	return chan_map_first(node->chan_map, i);
}

struct chan *next_chan(const struct node *node, struct chan_map_iter *i)
{
	if (!node_uses_chan_map(node)) {
		i->i.off++;
		return next_chan_arr(node, i);
	}

	return chan_map_next(node->chan_map, i);
}

static void destroy_routing_state(struct routing_state *rstate)
{
	/* Since we omitted destructors on these, clean up manually */
	u64 idx;
	for (struct chan *chan = uintmap_first(&rstate->chanmap, &idx);
	     chan;
	     chan = uintmap_after(&rstate->chanmap, &idx))
		free_chan(rstate, chan);
}

static void memleak_help_routing_tables(struct htable *memtable,
					struct routing_state *rstate)
{
	struct node *n;
	struct node_map_iter nit;

	memleak_scan_htable(memtable, &rstate->nodes->raw);
	memleak_scan_htable(memtable, &rstate->pending_node_map->raw);
	memleak_scan_htable(memtable, &rstate->pending_cannouncements->raw);
	memleak_scan_uintmap(memtable, &rstate->unupdated_chanmap);

	for (n = node_map_first(rstate->nodes, &nit);
	     n;
	     n = node_map_next(rstate->nodes, &nit)) {
		if (node_uses_chan_map(n))
			memleak_scan_htable(memtable, &n->chan_map->raw);
	}
}

struct routing_state *new_routing_state(const tal_t *ctx,
					struct daemon *daemon)
{
	struct routing_state *rstate = tal(ctx, struct routing_state);
	rstate->daemon = daemon;
	rstate->nodes = new_node_map(rstate);
	rstate->gs = gossip_store_new(daemon);
	rstate->dying_channels = tal_arr(rstate, struct dying_channel, 0);

	rstate->pending_cannouncements = tal(rstate, struct pending_cannouncement_map);
	pending_cannouncement_map_init(rstate->pending_cannouncements);

	uintmap_init(&rstate->chanmap);
	uintmap_init(&rstate->unupdated_chanmap);
	rstate->txf = txout_failures_new(rstate, rstate->daemon);
	rstate->pending_node_map = tal(ctx, struct pending_node_map);
	pending_node_map_init(rstate->pending_node_map);

	tal_add_destructor(rstate, destroy_routing_state);
	memleak_add_helper(rstate, memleak_help_routing_tables);

	return rstate;
}


const struct node_id *node_map_keyof_node(const struct node *n)
{
	return &n->id;
}

size_t node_map_hash_key(const struct node_id *pc)
{
	return siphash24(siphash_seed(), pc->k, sizeof(pc->k));
}

bool node_map_node_eq(const struct node *n, const struct node_id *pc)
{
	return node_id_eq(&n->id, pc);
}


static void destroy_node(struct node *node, struct routing_state *rstate)
{
	struct chan_map_iter i;
	struct chan *c;
	node_map_del(rstate->nodes, node);

	/* These remove themselves from chans[]. */
	while ((c = first_chan(node, &i)) != NULL)
		free_chan(rstate, c);
}

struct node *get_node(struct routing_state *rstate,
		      const struct node_id *id)
{
	return node_map_get(rstate->nodes, id);
}

static struct node *new_node(struct routing_state *rstate,
			     const struct node_id *id)
{
	struct node *n;

	assert(!get_node(rstate, id));

	n = tal(rstate, struct node);
	n->id = *id;
	memset(n->chan_arr, 0, sizeof(n->chan_arr));
	n->chan_map = NULL;
	broadcastable_init(&n->bcast);
	broadcastable_init(&n->rgraph);
	n->tokens = TOKEN_MAX;
	node_map_add(rstate->nodes, n);
	tal_add_destructor2(n, destroy_node, rstate);

	return n;
}

static bool is_chan_zombie(struct chan *chan)
{
	if (chan->half[0].zombie || chan->half[1].zombie)
		return true;
	return false;
}

static bool is_node_zombie(struct node* node)
{
	struct chan_map_iter i;
	struct chan *c;

	for (c = first_chan(node, &i); c; c = next_chan(node, &i)) {
		if (!is_chan_zombie(c))
			return false;
	}
	return true;
}

/* We can *send* a channel_announce for a channel attached to this node:
 * we only send once we have a channel_update. */
bool node_has_broadcastable_channels(const struct node *node)
{
	struct chan_map_iter i;
	struct chan *c;

	for (c = first_chan(node, &i); c; c = next_chan(node, &i)) {
		if (is_chan_zombie(c))
			continue;
		if (is_halfchan_defined(&c->half[0])
		    || is_halfchan_defined(&c->half[1]))
			return true;
	}
	return false;
}

static bool node_announce_predates_channels(const struct node *node)
{
	struct chan_map_iter i;
	struct chan *c;

	for (c = first_chan(node, &i); c; c = next_chan(node, &i)) {
		/* Zombies don't count! */
		if (is_chan_zombie(c))
			continue;

		if (c->bcast.index < node->bcast.index)
			return false;
	}
	return true;
}

/* Move this node's announcement to the tail of the gossip_store, to
 * make everyone send it again. */
static void force_node_announce_rexmit(struct routing_state *rstate,
				       struct node *node)
{
	const u8 *announce;
	announce = gossip_store_get(tmpctx, rstate->gs, node->bcast.index);

	u32 initial_bcast_index = node->bcast.index;
	gossip_store_delete(rstate->gs,
			    &node->bcast,
			    WIRE_NODE_ANNOUNCEMENT);
	node->bcast.index = gossip_store_add(rstate->gs,
					     announce,
					     node->bcast.timestamp,
					     false,
					     false,
					     false,
					     NULL);
	if (node->rgraph.index == initial_bcast_index){
		node->rgraph.index = node->bcast.index;
	} else {
		announce = gossip_store_get(tmpctx, rstate->gs, node->rgraph.index);
		gossip_store_delete(rstate->gs,
				    &node->rgraph,
				    WIRE_NODE_ANNOUNCEMENT);
		node->rgraph.index = gossip_store_add(rstate->gs,
						      announce,
						      node->rgraph.timestamp,
						      false,
						      true,
						      false,
						      NULL);
	}
}

static void remove_chan_from_node(struct routing_state *rstate,
				  struct node *node, const struct chan *chan)
{
	size_t num_chans;

	if (!node_uses_chan_map(node)) {
		num_chans = 0;
		for (size_t i = 0; i < ARRAY_SIZE(node->chan_arr); i++) {
			if (node->chan_arr[i] == chan)
				node->chan_arr[i] = NULL;
			else if (node->chan_arr[i] != NULL)
				num_chans++;
		}
	} else {
		if (!chan_map_del(node->chan_map, chan))
			abort();
		num_chans = chan_map_count(node->chan_map);
	}

	/* Last channel?  Simply delete node (and associated announce) */
	if (num_chans == 0) {
		if (node->rgraph.index != node->bcast.index)
			gossip_store_delete(rstate->gs,
					    &node->rgraph,
					    WIRE_NODE_ANNOUNCEMENT);
		gossip_store_delete(rstate->gs,
				    &node->bcast,
				    WIRE_NODE_ANNOUNCEMENT);
		tal_free(node);
		return;
	}

	/* Don't bother if there's no node_announcement */
	if (!node->bcast.index)
		return;

	/* Removed only public channel?  Remove node announcement. */
	if (!node_has_broadcastable_channels(node)) {
		if (node->rgraph.index != node->bcast.index)
			gossip_store_delete(rstate->gs,
					    &node->rgraph,
					    WIRE_NODE_ANNOUNCEMENT);
		gossip_store_delete(rstate->gs,
				    &node->bcast,
				    WIRE_NODE_ANNOUNCEMENT);
		node->rgraph.index = node->bcast.index = 0;
		node->rgraph.timestamp = node->bcast.timestamp = 0;
	} else if (node_announce_predates_channels(node)) {
		/* node announcement predates all channel announcements?
		 * Move to end (we could, in theory, move to just past next
		 * channel_announce, but we don't care that much about spurious
		 * retransmissions in this corner case */
		force_node_announce_rexmit(rstate, node);
	}
}

/* With --developer, we make sure that free_chan is called on this chan! */
static void destroy_chan_check(struct chan *chan)
{
	assert(chan->sat.satoshis == (unsigned long)chan); /* Raw: dev-hack */
}

static void free_chans_from_node(struct routing_state *rstate, struct chan *chan)
{
	remove_chan_from_node(rstate, chan->nodes[0], chan);
	remove_chan_from_node(rstate, chan->nodes[1], chan);

	if (rstate->daemon->developer)
		chan->sat.satoshis = (unsigned long)chan; /* Raw: dev-hack */
}

/* We used to make this a tal_add_destructor2, but that costs 40 bytes per
 * chan, and we only ever explicitly free it anyway. */
void free_chan(struct routing_state *rstate, struct chan *chan)
{
	free_chans_from_node(rstate, chan);
	uintmap_del(&rstate->chanmap, chan->scid.u64);

	tal_free(chan);
}

static void init_half_chan(struct routing_state *rstate,
				 struct chan *chan,
				 int channel_idx)
{
	struct half_chan *c = &chan->half[channel_idx];

	broadcastable_init(&c->bcast);
	broadcastable_init(&c->rgraph);
	c->tokens = TOKEN_MAX;
	c->zombie = false;
}

static void bad_gossip_order(const u8 *msg,
			     const struct node_id *source_peer,
			     const char *details)
{
	status_peer_debug(source_peer,
			  "Bad gossip order: %s before announcement %s from %s",
			  peer_wire_name(fromwire_peektype(msg)),
			  details,
			  source_peer ? type_to_string(tmpctx, struct node_id, source_peer) : "local");
}

struct chan *new_chan(struct routing_state *rstate,
		      const struct short_channel_id *scid,
		      const struct node_id *id1,
		      const struct node_id *id2,
		      struct amount_sat satoshis)
{
	struct chan *chan = tal(rstate, struct chan);
	int n1idx = node_id_idx(id1, id2);
	struct node *n1, *n2;

	if (rstate->daemon->developer)
		tal_add_destructor(chan, destroy_chan_check);

	/* We should never add a channel twice */
	assert(!uintmap_get(&rstate->chanmap, scid->u64));

	/* Create nodes on demand */
	n1 = get_node(rstate, id1);
	if (!n1)
		n1 = new_node(rstate, id1);
	n2 = get_node(rstate, id2);
	if (!n2)
		n2 = new_node(rstate, id2);

	chan->scid = *scid;
	chan->nodes[n1idx] = n1;
	chan->nodes[!n1idx] = n2;
	broadcastable_init(&chan->bcast);
	/* This is how we indicate it's not public yet. */
	chan->bcast.timestamp = 0;
	chan->sat = satoshis;

	add_chan(n2, chan);
	add_chan(n1, chan);

	/* Populate with (inactive) connections */
	init_half_chan(rstate, chan, n1idx);
	init_half_chan(rstate, chan, !n1idx);

	uintmap_add(&rstate->chanmap, scid->u64, chan);

	return chan;
}

/* We allow node announcements for this node if it doesn't otherwise exist, so
 * we can process them once it does exist (a channel_announce is being
 * validated right now).
 *
 * If we attach one, remove it on destruction of @ctx.
 */
static void del_pending_node_announcement(const tal_t *ctx UNUSED,
					  struct pending_node_announce *pna)
{
	if (--pna->refcount == 0) {
		pending_node_map_del(pna->rstate->pending_node_map, pna);
		tal_free(pna);
	}
}

static void catch_node_announcement(const tal_t *ctx,
				    struct routing_state *rstate,
				    struct node_id *nodeid)
{
	struct pending_node_announce *pna;
	struct node *node;

	/* No need if we already know about the node. */
	node = get_node(rstate, nodeid);
	if (node)
		return;

	/* We can have multiple channels announced at same time for nodes;
	 * but we can only have one of these in the map. */
	pna = pending_node_map_get(rstate->pending_node_map, nodeid);
	if (!pna) {
		pna = tal(rstate, struct pending_node_announce);
		pna->rstate = rstate;
		pna->nodeid = *nodeid;
		pna->node_announcement = NULL;
		pna->timestamp = 0;
		pna->index = 0;
		pna->refcount = 0;
		pna->source_peer = NULL;
		pna->spam.node_announcement = NULL;
		pna->spam.index = 0;
		pending_node_map_add(rstate->pending_node_map, pna);
	}
	pna->refcount++;
	tal_add_destructor2(ctx, del_pending_node_announcement, pna);
}

static void process_pending_node_announcement(struct routing_state *rstate,
					      struct node_id *nodeid)
{
	struct pending_node_announce *pna = pending_node_map_get(rstate->pending_node_map, nodeid);
	if (!pna)
		return;

	if (pna->node_announcement) {
		SUPERVERBOSE(
		    "Processing deferred node_announcement for node %s",
		    type_to_string(pna, struct node_id, nodeid));

		/* Can fail it timestamp is now too old */
		if (!routing_add_node_announcement(rstate,
						   pna->node_announcement,
						   pna->index,
						   pna->source_peer, NULL,
						   false))
			status_unusual("pending node_announcement %s too old?",
				       tal_hex(tmpctx, pna->node_announcement));
		/* Never send this again. */
		pna->node_announcement = tal_free(pna->node_announcement);
	}
	if (pna->spam.node_announcement) {
		SUPERVERBOSE(
		    "Processing deferred node_announcement for node %s",
		    type_to_string(pna, struct node_id, nodeid));

		/* Can fail it timestamp is now too old */
		if (!routing_add_node_announcement(rstate,
						   pna->spam.node_announcement,
						   pna->spam.index,
						   NULL, NULL,
						   true))
			status_unusual("pending node_announcement %s too old?",
				       tal_hex(tmpctx, pna->spam.node_announcement));
		/* Never send this again. */
		pna->spam.node_announcement = tal_free(pna->spam.node_announcement);
	}

	/* We don't need to catch any more node_announcements, since we've
	 * accepted the public channel now.  But other pending announcements
	 * may still hold a reference they use in
	 * del_pending_node_announcement, so simply delete it from the map. */
	pending_node_map_del(rstate->pending_node_map, notleak(pna));
}

static struct pending_cannouncement *
find_pending_cannouncement(struct routing_state *rstate,
			   const struct short_channel_id *scid)
{
	struct pending_cannouncement *pann;

	pann = pending_cannouncement_map_get(rstate->pending_cannouncements, scid);

	return pann;
}

static void destroy_pending_cannouncement(struct pending_cannouncement *pending,
					  struct routing_state *rstate)
{
	pending_cannouncement_map_del(rstate->pending_cannouncements, pending);
}

static void add_channel_announce_to_broadcast(struct routing_state *rstate,
					      struct chan *chan,
					      const u8 *channel_announce,
					      u32 timestamp,
					      u32 index)
{
	u8 *addendum = towire_gossip_store_channel_amount(tmpctx, chan->sat);

	chan->bcast.timestamp = timestamp;
	/* 0, unless we're loading from store */
	if (index)
		chan->bcast.index = index;
	else
		chan->bcast.index = gossip_store_add(rstate->gs,
						     channel_announce,
						     chan->bcast.timestamp,
						     false,
						     false,
						     false,
						     addendum);
}

static void delete_chan_messages_from_store(struct routing_state *rstate,
					    struct chan *chan)
{
	/* If these aren't in the store, these are noops. */
	gossip_store_delete(rstate->gs,
			    &chan->bcast, WIRE_CHANNEL_ANNOUNCEMENT);
	if (chan->half[0].rgraph.index != chan->half[0].bcast.index)
		gossip_store_delete(rstate->gs,
				    &chan->half[0].rgraph, WIRE_CHANNEL_UPDATE);
	gossip_store_delete(rstate->gs,
			    &chan->half[0].bcast, WIRE_CHANNEL_UPDATE);
	if (chan->half[1].rgraph.index != chan->half[1].bcast.index)
		gossip_store_delete(rstate->gs,
				    &chan->half[1].rgraph, WIRE_CHANNEL_UPDATE);
	gossip_store_delete(rstate->gs,
			    &chan->half[1].bcast, WIRE_CHANNEL_UPDATE);
}

static void remove_channel_from_store(struct routing_state *rstate,
				      struct chan *chan)
{
	/* Put in tombstone marker. Zombie channels will have one already. */
	if (!is_chan_zombie(chan))
		gossip_store_mark_channel_deleted(rstate->gs, &chan->scid);

	/* Now delete old entries. */
	delete_chan_messages_from_store(rstate, chan);
}

bool routing_add_channel_announcement(struct routing_state *rstate,
				      const u8 *msg TAKES,
				      struct amount_sat sat,
				      u32 index,
				      const struct node_id *source_peer)
{
	secp256k1_ecdsa_signature node_signature_1, node_signature_2;
	secp256k1_ecdsa_signature bitcoin_signature_1, bitcoin_signature_2;
	u8 *features;
	struct bitcoin_blkid chain_hash;
	struct short_channel_id scid;
	struct node_id node_id_1;
	struct node_id node_id_2;
	struct pubkey bitcoin_key_1;
	struct pubkey bitcoin_key_2;
	struct unupdated_channel *uc;

	/* Make sure we own msg, even if we don't save it. */
	if (taken(msg))
		tal_steal(tmpctx, msg);

	if (!fromwire_channel_announcement(
		    tmpctx, msg, &node_signature_1, &node_signature_2,
		    &bitcoin_signature_1, &bitcoin_signature_2, &features, &chain_hash,
		    &scid, &node_id_1, &node_id_2, &bitcoin_key_1, &bitcoin_key_2))
		return false;

	uc = tal(rstate, struct unupdated_channel);
	uc->channel_announce = tal_dup_talarr(uc, u8, msg);
	uc->added = gossip_time_now(rstate->daemon);
	uc->index = index;
	uc->sat = sat;
	uc->scid = scid;
	uc->id[0] = node_id_1;
	uc->id[1] = node_id_2;
	uc->source_peer = tal_dup_or_null(uc, struct node_id, source_peer);
	uintmap_add(&rstate->unupdated_chanmap, scid.u64, uc);
	tal_add_destructor2(uc, destroy_unupdated_channel, rstate);

	/* If a node_announcement comes along, save it for once we're updated */
	catch_node_announcement(uc, rstate, &node_id_1);
	catch_node_announcement(uc, rstate, &node_id_2);

	return true;
}

u8 *handle_channel_announcement(struct routing_state *rstate,
				const u8 *announce TAKES,
				u32 current_blockheight,
				const struct short_channel_id **scid,
				const struct node_id *source_peer TAKES)
{
	struct pending_cannouncement *pending;
	struct bitcoin_blkid chain_hash;
	u8 *features, *warn;
	secp256k1_ecdsa_signature node_signature_1, node_signature_2;
	secp256k1_ecdsa_signature bitcoin_signature_1, bitcoin_signature_2;
	struct chan *chan;
	const char *err;

	pending = tal(rstate, struct pending_cannouncement);
	pending->source_peer = tal_dup_or_null(pending, struct node_id, source_peer);
	pending->updates[0] = NULL;
	pending->updates[1] = NULL;
	pending->update_source_peer[0] = pending->update_source_peer[1] = NULL;
	pending->announce = tal_dup_talarr(pending, u8, announce);
	pending->update_timestamps[0] = pending->update_timestamps[1] = 0;

	if (!fromwire_channel_announcement(pending, pending->announce,
					   &node_signature_1,
					   &node_signature_2,
					   &bitcoin_signature_1,
					   &bitcoin_signature_2,
					   &features,
					   &chain_hash,
					   &pending->short_channel_id,
					   &pending->node_id_1,
					   &pending->node_id_2,
					   &pending->bitcoin_key_1,
					   &pending->bitcoin_key_2)) {
		warn = towire_warningfmt(rstate, NULL,
					"Malformed channel_announcement %s",
					tal_hex(pending, pending->announce));
		goto malformed;
	}

	/* We don't use features */
	tal_free(features);

	/* If we know the blockheight, and it's in the future, reject
	 * out-of-hand.  Remember, it should be 6 deep before they tell us
	 * anyway. */
	if (current_blockheight != 0
	    && short_channel_id_blocknum(&pending->short_channel_id) > current_blockheight) {
		status_peer_debug(pending->source_peer,
				  "Ignoring future channel_announcment for %s"
				  " (current block %u)",
				  type_to_string(tmpctx, struct short_channel_id,
						 &pending->short_channel_id),
				  current_blockheight);
		goto ignored;
	}

	/* If a prior txout lookup failed there is little point it trying
	 * again. Just drop the announcement and walk away whistling. */
	if (in_txout_failures(rstate->txf, pending->short_channel_id)) {
		SUPERVERBOSE(
		    "Ignoring channel_announcement of %s due to a prior txout "
		    "query failure. The channel was likely closed on-chain.",
		    type_to_string(tmpctx, struct short_channel_id,
				   &pending->short_channel_id));
		goto ignored;
	}

	/* Check if we know the channel already (no matter in what
	 * state, we stop here if yes). */
	chan = get_channel(rstate, &pending->short_channel_id);
	if (chan != NULL) {
		SUPERVERBOSE("%s: %s already has public channel",
			     __func__,
			     type_to_string(tmpctx, struct short_channel_id,
					    &pending->short_channel_id));
		goto ignored;
	}
	if (get_unupdated_channel(rstate, &pending->short_channel_id)) {
		SUPERVERBOSE("%s: %s already has unupdated channel",
			     __func__,
			     type_to_string(tmpctx, struct short_channel_id,
					    &pending->short_channel_id));
		goto ignored;
	}

	/* We don't replace previous ones, since we might validate that and
	 * think this one is OK! */
	if (find_pending_cannouncement(rstate, &pending->short_channel_id)) {
		SUPERVERBOSE("%s: %s already has pending cannouncement",
			     __func__,
			     type_to_string(tmpctx, struct short_channel_id,
					    &pending->short_channel_id));
		goto ignored;
	}

	/* FIXME: Handle duplicates as per BOLT #7 */

	/* BOLT #7:
	 * The receiving node:
	 *...
	 *  - if the specified `chain_hash` is unknown to the receiver:
	 *    - MUST ignore the message.
	 */
	if (!bitcoin_blkid_eq(&chain_hash, &chainparams->genesis_blockhash)) {
		status_peer_debug(pending->source_peer,
		    "Received channel_announcement %s for unknown chain %s",
		    type_to_string(pending, struct short_channel_id,
				   &pending->short_channel_id),
		    type_to_string(pending, struct bitcoin_blkid, &chain_hash));
		goto ignored;
	}

	/* Note that if node_id_1 or node_id_2 are malformed, it's caught here */
	err = sigcheck_channel_announcement(tmpctx,
					    &pending->node_id_1,
					    &pending->node_id_2,
					    &pending->bitcoin_key_1,
					    &pending->bitcoin_key_2,
					    &node_signature_1,
					    &node_signature_2,
					    &bitcoin_signature_1,
					    &bitcoin_signature_2,
					    pending->announce);
	if (err) {
		/* BOLT #7:
		 *
		 * - if `bitcoin_signature_1`, `bitcoin_signature_2`,
		 *   `node_signature_1` OR `node_signature_2` are invalid OR NOT
		 *    correct:
		 *   - SHOULD send a `warning`.
		 *   - MAY close the connection.
		 *   - MUST ignore the message.
		 */
		warn = towire_warningfmt(rstate, NULL, "%s", err);
		goto malformed;
	}

	/* Don't add an infinite number of pending announcements.  If we're
	 * catching up with the bitcoin chain, though, they can definitely
	 * pile up. */
	if (pending_cannouncement_map_count(rstate->pending_cannouncements)
	    > 100000) {
		static bool warned = false;
		if (!warned) {
			status_peer_unusual(pending->source_peer,
					    "Flooded by channel_announcements:"
					    " ignoring some");
			warned = true;
		}
		goto ignored;
	}

	status_peer_debug(pending->source_peer,
			  "Received channel_announcement for channel %s",
			  type_to_string(tmpctx, struct short_channel_id,
					 &pending->short_channel_id));

	/* Add both endpoints to the pending_node_map so we can stash
	 * node_announcements while we wait for the txout check */
	catch_node_announcement(pending, rstate, &pending->node_id_1);
	catch_node_announcement(pending, rstate, &pending->node_id_2);

	pending_cannouncement_map_add(rstate->pending_cannouncements, pending);
	tal_add_destructor2(pending, destroy_pending_cannouncement, rstate);

	/* Success */
	// MSC: Cppcheck 1.86 gets this false positive
	// cppcheck-suppress autoVariables
	*scid = &pending->short_channel_id;
	return NULL;

malformed:
	tal_free(pending);
	*scid = NULL;
	return warn;

ignored:
	tal_free(pending);
	*scid = NULL;
	return NULL;
}

static void process_pending_channel_update(struct daemon *daemon,
					   struct routing_state *rstate,
					   const struct short_channel_id *scid,
					   const u8 *cupdate,
					   const struct node_id *source_peer)
{
	u8 *err;

	if (!cupdate)
		return;

	err = handle_channel_update(rstate, cupdate, source_peer, NULL, false);
	if (err) {
		/* FIXME: We could send this error back to peer if != NULL */
		status_peer_debug(source_peer,
				  "Pending channel_update for %s: %s",
				  type_to_string(tmpctx, struct short_channel_id,
						 scid),
				  sanitize_error(tmpctx, err, NULL));
		tal_free(err);
	}
}

bool handle_pending_cannouncement(struct daemon *daemon,
				  struct routing_state *rstate,
				  const struct short_channel_id *scid,
				  struct amount_sat sat,
				  const u8 *outscript)
{
	const u8 *s;
	struct pending_cannouncement *pending;

	pending = find_pending_cannouncement(rstate, scid);
	if (!pending)
		return false;

	/* BOLT #7:
	 *
	 * The receiving node:
	 *...
	 *   - if the `short_channel_id`'s output... is spent:
	 *    - MUST ignore the message.
	 */
	if (tal_count(outscript) == 0) {
		status_peer_debug(pending->source_peer,
				  "channel_announcement: no unspent txout %s",
				  type_to_string(pending,
						 struct short_channel_id,
						 scid));
		tal_free(pending);
		txout_failures_add(rstate->txf, *scid);
		return false;
	}

	/* BOLT #7:
	 *
	 * The receiving node:
	 *...
	 *   - if the `short_channel_id`'s output does NOT correspond to a P2WSH
	 *     (using `bitcoin_key_1` and `bitcoin_key_2`, as specified in
	 *    [BOLT #3](03-transactions.md#funding-transaction-output)) ...
	 *    - MUST ignore the message.
	 */
	s = scriptpubkey_p2wsh(pending,
			       bitcoin_redeem_2of2(pending,
						   &pending->bitcoin_key_1,
						   &pending->bitcoin_key_2));

	if (!scripteq(s, outscript)) {
		status_peer_debug(pending->source_peer,
				  "channel_announcement: txout %s expected %s, got %s",
				  type_to_string(
					  pending, struct short_channel_id,
					  scid),
				  tal_hex(tmpctx, s),
				  tal_hex(tmpctx, outscript));
		tal_free(pending);
		return false;
	}

	/* Remove pending now, so below functions don't see it. */
	pending_cannouncement_map_del(rstate->pending_cannouncements, pending);
	tal_del_destructor2(pending, destroy_pending_cannouncement, rstate);

	/* Can fail if channel_announcement too old */
	if (!routing_add_channel_announcement(rstate, pending->announce, sat, 0,
					      pending->source_peer))
		status_peer_unusual(pending->source_peer,
				    "Could not add channel_announcement %s: too old?",
				    tal_hex(tmpctx, pending->announce));
	else {
		/* Did we have an update waiting?  If so, apply now. */
		process_pending_channel_update(daemon, rstate, scid, pending->updates[0],
					       pending->update_source_peer[0]);
		process_pending_channel_update(daemon, rstate, scid, pending->updates[1],
					       pending->update_source_peer[1]);
	}

	tal_free(pending);
	return true;
}

static void update_pending(struct pending_cannouncement *pending,
			   u32 timestamp, const u8 *update,
			   const u8 direction,
			   const struct node_id *source_peer TAKES)
{
	SUPERVERBOSE("Deferring update for pending channel %s/%d",
		     type_to_string(tmpctx, struct short_channel_id,
				    &pending->short_channel_id), direction);

	if (pending->update_timestamps[direction] < timestamp) {
		if (pending->updates[direction]) {
			status_peer_debug(source_peer,
					  "Replacing existing update");
			tal_free(pending->updates[direction]);
		}
		pending->updates[direction]
			= tal_dup_talarr(pending, u8, update);
		pending->update_timestamps[direction] = timestamp;
		tal_free(pending->update_source_peer[direction]);
		pending->update_source_peer[direction]
			= tal_dup_or_null(pending, struct node_id, source_peer);
	} else {
		/* Don't leak if we don't update! */
		if (taken(source_peer))
			tal_free(source_peer);
	}
}

static void delete_spam_update(struct routing_state *rstate,
			       struct half_chan *hc)
{
	/* Spam updates will have a unique rgraph index */
	if (hc->rgraph.index == hc->bcast.index)
		return;
	gossip_store_delete(rstate->gs, &hc->rgraph,
			    WIRE_CHANNEL_UPDATE);
	hc->rgraph.index = hc->bcast.index;
	hc->rgraph.timestamp = hc->bcast.timestamp;
}

static bool is_chan_dying(struct routing_state *rstate,
			  const struct short_channel_id *scid)
{
	for (size_t i = 0; i < tal_count(rstate->dying_channels); i++) {
		if (short_channel_id_eq(&rstate->dying_channels[i].scid, scid))
			return true;
	}
	return false;
}

/* Is this channel_update different from prev (not sigs and timestamps)? */
static bool cupdate_different(struct gossip_store *gs,
			      const struct half_chan *hc,
			      const u8 *cupdate)
{
	const u8 *oparts[2], *nparts[2];
	size_t osizes[2], nsizes[2];
	const u8 *orig;

	/* Get last one we have. */
	orig = gossip_store_get(tmpctx, gs, hc->bcast.index);
	get_cupdate_parts(orig, oparts, osizes);
	get_cupdate_parts(cupdate, nparts, nsizes);

	return !memeq(oparts[0], osizes[0], nparts[0], nsizes[0])
		|| !memeq(oparts[1], osizes[1], nparts[1], nsizes[1]);
}

bool routing_add_channel_update(struct routing_state *rstate,
				const u8 *update TAKES,
				u32 index,
				/* NULL if it's us */
				const struct node_id *source_peer,
				bool ignore_timestamp,
				bool force_spam_flag,
				bool force_zombie_flag)
{
	secp256k1_ecdsa_signature signature;
	struct short_channel_id short_channel_id;
	u32 timestamp;
	u8 message_flags, channel_flags;
	u16 expiry;
	struct amount_msat htlc_minimum, htlc_maximum;
	u32 fee_base_msat;
	u32 fee_proportional_millionths;
	struct bitcoin_blkid chain_hash;
	struct chan *chan;
	struct half_chan *hc;
	struct unupdated_channel *uc;
	u8 direction;
	struct amount_sat sat;
	bool spam;
	bool zombie;
	bool dying;

	/* Make sure we own msg, even if we don't save it. */
	if (taken(update))
		tal_steal(tmpctx, update);

	if (!fromwire_channel_update(
				update, &signature, &chain_hash,
				&short_channel_id, &timestamp,
				&message_flags, &channel_flags,
				&expiry, &htlc_minimum, &fee_base_msat,
				&fee_proportional_millionths,
				&htlc_maximum))
		return false;

	direction = channel_flags & 0x1;
	chan = get_channel(rstate, &short_channel_id);

	if (chan) {
		uc = NULL;
		sat = chan->sat;
		zombie = is_chan_zombie(chan);
		dying = is_chan_dying(rstate, &short_channel_id);
	} else {
		/* Maybe announcement was waiting for this update? */
		uc = get_unupdated_channel(rstate, &short_channel_id);
		if (!uc) {
			if (index)
				return false;
			/* Allow ld to process a private channel update */
			tell_lightningd_peer_update(rstate->daemon, source_peer,
						    short_channel_id, fee_base_msat,
						    fee_proportional_millionths,
						    expiry, htlc_minimum,
						    htlc_maximum);
			return false;
		}
		sat = uc->sat;
		/* When loading zombies from the store. */
		zombie = force_zombie_flag;
		dying = false;
	}

	/* Reject update if the `htlc_maximum_msat` is greater
	 * than the total available channel satoshis */
	if (amount_msat_greater_sat(htlc_maximum, sat))
		return false;

	/* Check timestamp is sane (unless from store). */
	if (!index && !timestamp_reasonable(rstate->daemon, timestamp)) {
		SUPERVERBOSE("Ignoring update timestamp %u for %s/%u",
			     timestamp,
			     type_to_string(tmpctx, struct short_channel_id,
					    &short_channel_id),
			     direction);
		return false;
	}

	/* OK, we're going to accept this, so create chan if doesn't exist */
	if (uc) {
		assert(!chan);
		chan = new_chan(rstate, &short_channel_id,
				&uc->id[0], &uc->id[1], sat);
		/* Assign zombie flag if loading zombie from store */
		if (force_zombie_flag)
			chan->half[direction].zombie = true;
	}

	/* Discard older updates */
	hc = &chan->half[direction];

	if (is_halfchan_defined(hc) && !ignore_timestamp) {
		/* The gossip_store should contain a single broadcastable entry
		 * and potentially one rate-limited entry. Any more is a bug */
		if (index){
			if (!force_spam_flag){
				status_broken("gossip_store broadcastable "
					      "channel_update %u replaces %u!",
					      index, hc->bcast.index);
				return false;
			} else if (hc->bcast.index != hc->rgraph.index){
				status_broken("gossip_store rate-limited "
					      "channel_update %u replaces %u!",
					      index, hc->rgraph.index);
				return false;
			}
		}

		if (timestamp <= hc->rgraph.timestamp) {
			SUPERVERBOSE("Ignoring outdated update.");
			/* Ignoring != failing */
			return true;
		}

		/* Allow redundant updates once every 7 days */
		if (timestamp < hc->bcast.timestamp + GOSSIP_PRUNE_INTERVAL(rstate->daemon->dev_fast_gossip_prune) / 2
		    && !cupdate_different(rstate->gs, hc, update)) {
			SUPERVERBOSE("Ignoring redundant update for %s/%u"
				     " (last %u, now %u)",
				     type_to_string(tmpctx,
						    struct short_channel_id,
						    &short_channel_id),
				     direction, hc->bcast.timestamp, timestamp);
			/* Ignoring != failing */
			return true;
		}

		/* Make sure it's not spamming us */
		if (!local_direction(rstate, chan, NULL)
		    && !ratelimit(rstate,
				  &hc->tokens, hc->bcast.timestamp, timestamp)) {
			status_peer_debug(source_peer,
					  "Spammy update for %s/%u flagged"
					  " (last %u, now %u)",
					  type_to_string(tmpctx,
							 struct short_channel_id,
							 &short_channel_id),
					  direction,
					  hc->bcast.timestamp, timestamp);
			spam = true;
		} else {
			spam = false;
		}
	} else {
		spam = false;
	}
	if (force_spam_flag)
		spam = true;

	/* Delete any prior entries (noop if they don't exist) */
	delete_spam_update(rstate, hc);
	if (!spam)
		gossip_store_delete(rstate->gs, &hc->bcast,
				    WIRE_CHANNEL_UPDATE);

	/* Update timestamp(s) */
	hc->rgraph.timestamp = timestamp;
	if (!spam)
		hc->bcast.timestamp = timestamp;

	/* If this is a peer's update to one of our local channels, tell lightningd. */
	if (node_id_eq(&chan->nodes[!direction]->id, &rstate->daemon->id)) {
		/* give lightningd the channel's inbound info to store to db */
		tell_lightningd_peer_update(rstate->daemon,
					    /* Note: we can get public
					     * channel_updates from other than
					     * direct peer!  So tell lightningd
					     * to trust us. */
					    NULL,
					    short_channel_id, fee_base_msat,
					    fee_proportional_millionths,
					    expiry, htlc_minimum,
					    htlc_maximum);
	}

	/* BOLT #7:
	 *   - MUST consider the `timestamp` of the `channel_announcement` to be
	 *     the `timestamp` of a corresponding `channel_update`.
	 *   - MUST consider whether to send the `channel_announcement` after
	 *     receiving the first corresponding `channel_update`.
	 */
	if (uc) {
		add_channel_announce_to_broadcast(rstate, chan,
						  uc->channel_announce,
						  timestamp,
						  uc->index);
	}

	/* Handle resurrection of zombie channels if the other side of the
	 * zombie channel has a recent timestamp. */
	if (zombie && timestamp_reasonable(rstate->daemon,
		chan->half[!direction].bcast.timestamp) &&
		chan->half[!direction].bcast.index && !index) {
		status_peer_debug(source_peer,
				  "Resurrecting zombie channel %s.",
				  type_to_string(tmpctx,
						 struct short_channel_id,
						 &chan->scid));
		const u8 *zombie_announcement = NULL;
		const u8 *zombie_addendum = NULL;
		const u8 *zombie_update[2] = {NULL, NULL};
		/* Resurrection is a careful process. First delete the zombie-
		 * flagged channel_announcement which has already been
		 * tombstoned, and re-add to the store without zombie flag. */
		zombie_announcement = gossip_store_get(tmpctx, rstate->gs,
						       chan->bcast.index);
		u32 offset = tal_count(zombie_announcement) +
			sizeof(struct gossip_hdr);
		/* The channel_announcement addendum reminds us of its size. */
		zombie_addendum = gossip_store_get(tmpctx, rstate->gs,
						   chan->bcast.index + offset);
		gossip_store_delete(rstate->gs, &chan->bcast,
				    WIRE_CHANNEL_ANNOUNCEMENT);
		chan->bcast.index =
			gossip_store_add(rstate->gs, zombie_announcement,
					 chan->bcast.timestamp,
					 false, false, false, zombie_addendum);
		/* Deletion of the old addendum is optional. */
		/* This opposing channel_update has been stashed away.  Now that
		 * there are two valid updates, this one gets restored. */
		/* FIXME: Handle spam case probably needs a helper f'n */
		zombie_update[0] = gossip_store_get(tmpctx, rstate->gs,
			chan->half[!direction].bcast.index);
		if (chan->half[!direction].bcast.index != chan->half[!direction].rgraph.index) {
			/* Don't forget the spam channel_update */
			zombie_update[1] = gossip_store_get(tmpctx, rstate->gs,
				chan->half[!direction].rgraph.index);
			gossip_store_delete(rstate->gs, &chan->half[!direction].rgraph,
					    WIRE_CHANNEL_UPDATE);
		}
		gossip_store_delete(rstate->gs, &chan->half[!direction].bcast,
				    WIRE_CHANNEL_UPDATE);
		chan->half[!direction].bcast.index =
			gossip_store_add(rstate->gs, zombie_update[0],
					 chan->half[!direction].bcast.timestamp,
					 false, false, false, NULL);
		if (zombie_update[1])
			chan->half[!direction].rgraph.index =
				gossip_store_add(rstate->gs, zombie_update[1],
						 chan->half[!direction].rgraph.timestamp,
						 false, true, false, NULL);
		else
			chan->half[!direction].rgraph.index = chan->half[!direction].bcast.index;

		/* It's a miracle! */
		chan->half[0].zombie = false;
		chan->half[1].zombie = false;
		zombie = false;
	}

	/* If we're loading from store, this means we don't re-add to store. */
	if (index) {
		if (!spam)
			hc->bcast.index = index;
		hc->rgraph.index = index;
	} else {
		hc->rgraph.index
			= gossip_store_add(rstate->gs, update, timestamp,
					   zombie, spam, dying, NULL);
		if (!spam)
			hc->bcast.index = hc->rgraph.index;

		peer_supplied_good_gossip(rstate->daemon, source_peer, 1);
	}

	if (uc) {
		/* If we were waiting for these nodes to appear (or gain a
		   public channel), process node_announcements now */
		process_pending_node_announcement(rstate, &chan->nodes[0]->id);
		process_pending_node_announcement(rstate, &chan->nodes[1]->id);
		tal_free(uc);
	}

	status_peer_debug(source_peer,
			  "Received %schannel_update for %schannel %s/%d now %s",
			  ignore_timestamp ? "(forced) " : "",
			  dying ? "dying ": "",
			  type_to_string(tmpctx, struct short_channel_id,
					 &short_channel_id),
			  channel_flags & 0x01,
			  channel_flags & ROUTING_FLAGS_DISABLED ? "DISABLED" : "ACTIVE");

	return true;
}

bool would_ratelimit_cupdate(struct routing_state *rstate,
			     const struct half_chan *hc,
			     u32 timestamp)
{
	return update_tokens(rstate, hc->tokens, hc->bcast.timestamp, timestamp)
		>= TOKENS_PER_MSG;
}

static const struct node_id *get_channel_owner(struct routing_state *rstate,
					       const struct short_channel_id *scid,
					       int direction)
{
	struct chan *chan = get_channel(rstate, scid);
	struct unupdated_channel *uc;

	if (chan)
		return &chan->nodes[direction]->id;

	/* Might be unupdated channel */
	uc = get_unupdated_channel(rstate, scid);
	if (uc)
		return &uc->id[direction];
	return NULL;
}

u8 *handle_channel_update(struct routing_state *rstate, const u8 *update TAKES,
			  const struct node_id *source_peer,
			  struct short_channel_id *unknown_scid,
			  bool force)
{
	u8 *serialized;
	const struct node_id *owner;
	secp256k1_ecdsa_signature signature;
	struct short_channel_id short_channel_id;
	u32 timestamp;
	u8 message_flags, channel_flags;
	u16 expiry;
	struct amount_msat htlc_minimum, htlc_maximum;
	u32 fee_base_msat;
	u32 fee_proportional_millionths;
	struct bitcoin_blkid chain_hash;
	u8 direction;
	struct pending_cannouncement *pending;
	const char *err;

	serialized = tal_dup_talarr(tmpctx, u8, update);
	if (!fromwire_channel_update(serialized, &signature,
				     &chain_hash, &short_channel_id,
				     &timestamp, &message_flags,
				     &channel_flags, &expiry,
				     &htlc_minimum, &fee_base_msat,
				     &fee_proportional_millionths,
				     &htlc_maximum)) {
		/* FIXME: We removed a warning about the
		 * channel_update being malformed since the warning
		 * could cause lnd to disconnect (seems they treat
		 * channel-unrelated warnings as fatal?). This was
		 * caused by lnd not enforcing the `htlc_maximum`,
		 * thus the parsing would fail. We can re-add the
		 * warning once our assumption that `htlc_maximum`
		 * being set is valid. */
		return NULL;
	}
	direction = channel_flags & 0x1;

	/* BOLT #7:
	 *
	 * The receiving node:
	 *...
	 *  - if the specified `chain_hash` value is unknown (meaning it isn't
	 *    active on the specified chain):
	 *    - MUST ignore the channel update.
	 */
	if (!bitcoin_blkid_eq(&chain_hash, &chainparams->genesis_blockhash)) {
		status_peer_debug(source_peer,
				  "Received channel_update for unknown chain %s",
				  type_to_string(tmpctx, struct bitcoin_blkid,
						 &chain_hash));
		return NULL;
	}

	/* If we dropped the matching announcement for this channel due to the
	 * txout query failing, don't report failure, it's just too noisy on
	 * mainnet */
	if (in_txout_failures(rstate->txf, short_channel_id))
		return NULL;

	/* If we have an unvalidated channel, just queue on that */
	pending = find_pending_cannouncement(rstate, &short_channel_id);
	if (pending) {
		status_peer_debug(source_peer,
				  "Updated pending announce with update %s/%u",
				  type_to_string(tmpctx,
						 struct short_channel_id,
						 &short_channel_id),
				  direction);
		update_pending(pending, timestamp, serialized, direction, source_peer);
		return NULL;
	}

	owner = get_channel_owner(rstate, &short_channel_id, direction);
	if (!owner) {
		/* This may be a local channel we don't know about.  If it's from a peer,
		 * check signature assuming it's from that peer, and if it's valid, hand to ld */
		if (source_peer
		    && sigcheck_channel_update(tmpctx, source_peer, &signature, serialized) == NULL) {
			tell_lightningd_peer_update(rstate->daemon, source_peer,
						    short_channel_id, fee_base_msat,
						    fee_proportional_millionths,
						    expiry, htlc_minimum,
						    htlc_maximum);
			return NULL;
		}

		if (unknown_scid)
			*unknown_scid = short_channel_id;
		bad_gossip_order(serialized,
				 source_peer,
				 tal_fmt(tmpctx, "%s/%u",
					 type_to_string(tmpctx,
							struct short_channel_id,
							&short_channel_id),
					 direction));
		return NULL;
	}

	err = sigcheck_channel_update(tmpctx, owner, &signature, serialized);
	if (err) {
		/* BOLT #7:
		 *
		 * - if `signature` is not a valid signature, using `node_id`
		 *  of the double-SHA256 of the entire message following the
		 *  `signature` field (including unknown fields following
		 *  `fee_proportional_millionths`):
		 *    - SHOULD send a `warning` and close the connection.
		 *    - MUST NOT process the message further.
		 */
		return towire_warningfmt(rstate, NULL, "%s", err);
	}

	routing_add_channel_update(rstate, take(serialized), 0, source_peer, force,
				   false, false);
	return NULL;
}

/* Get non-signature, non-timestamp parts of (valid!) node_announcement,
 * with TLV broken out separately  */
static void get_nannounce_parts(const u8 *node_announcement,
				const u8 *parts[3],
				size_t sizes[3])
{
	size_t len, ad_len;
	const u8 *flen, *ad_start;

	/* BOLT #7:
	 *
	 * 1. type: 257 (`node_announcement`)
	 * 2. data:
	 *    * [`signature`:`signature`]
	 *    * [`u16`:`flen`]
	 *    * [`flen*byte`:`features`]
	 *    * [`u32`:`timestamp`]
	 *...
	 */
	/* Note: 2 bytes for `type` field */
	/* We already checked it's valid before accepting */
	assert(tal_count(node_announcement) > 2 + 64);
	parts[0] = node_announcement + 2 + 64;

	/* Read flen to get size */
	flen = parts[0];
	len = tal_count(node_announcement) - (2 + 64);
	sizes[0] = 2 + fromwire_u16(&flen, &len);
	assert(flen != NULL && len >= 4);

	/* BOLT-0fe3485a5320efaa2be8cfa0e570ad4d0259cec3 #7:
	 *
	 *    * [`u32`:`timestamp`]
	 *    * [`point`:`node_id`]
	 *    * [`3*byte`:`rgb_color`]
	 *    * [`32*byte`:`alias`]
	 *    * [`u16`:`addrlen`]
	 *    * [`addrlen*byte`:`addresses`]
	 *    * [`node_ann_tlvs`:`tlvs`]
	*/
	parts[1] = node_announcement + 2 + 64 + sizes[0] + 4;

	/* Find the end of the addresses */
	ad_start = parts[1] + 33 + 3 + 32;
	len = tal_count(node_announcement)
		- (2 + 64 + sizes[0] + 4 + 33 + 3 + 32);
	ad_len = fromwire_u16(&ad_start, &len);
	assert(ad_start != NULL && len >= ad_len);

	sizes[1] = 33 + 3 + 32 + 2 + ad_len;

	/* Is there a TLV ? */
	sizes[2] = len - ad_len;
	if (sizes[2] != 0)
		parts[2] = parts[1] + sizes[1];
	else
		parts[2] = NULL;
}

/* Is this node_announcement different from prev (not sigs and timestamps)? */
static bool nannounce_different(struct gossip_store *gs,
				const struct node *node,
				const u8 *nannounce)
{
	const u8 *oparts[3], *nparts[3];
	size_t osizes[3], nsizes[3];
	const u8 *orig;

	/* Get last one we have. */
	orig = gossip_store_get(tmpctx, gs, node->bcast.index);
	get_nannounce_parts(orig, oparts, osizes);
	get_nannounce_parts(nannounce, nparts, nsizes);

	return !memeq(oparts[0], osizes[0], nparts[0], nsizes[0])
		|| !memeq(oparts[1], osizes[1], nparts[1], nsizes[1])
		|| !memeq(oparts[2], osizes[2], nparts[2], nsizes[2]);
}

bool routing_add_node_announcement(struct routing_state *rstate,
				   const u8 *msg TAKES,
				   u32 index,
				   const struct node_id *source_peer TAKES,
				   bool *was_unknown,
				   bool force_spam_flag)
{
	struct node *node;
	secp256k1_ecdsa_signature signature;
	u32 timestamp;
	struct node_id node_id;
	u8 rgb_color[3];
	u8 alias[32];
	u8 *features, *addresses;
	struct tlv_node_ann_tlvs *na_tlv;
	bool spam;

	if (was_unknown)
		*was_unknown = false;

	/* Make sure we own msg, even if we don't save it. */
	if (taken(msg))
		tal_steal(tmpctx, msg);

	/* Note: validity of node_id is already checked. */
	if (!fromwire_node_announcement(tmpctx, msg,
					&signature, &features, &timestamp,
					&node_id, rgb_color, alias,
					&addresses,
					&na_tlv)) {
		return false;
	}

	node = get_node(rstate, &node_id);

	if (node == NULL || !node_has_broadcastable_channels(node)) {
		struct pending_node_announce *pna;
		/* BOLT #7:
		 *
		 * - if `node_id` is NOT previously known from a
		 *   `channel_announcement` message, OR if `timestamp` is NOT
		 *   greater than the last-received `node_announcement` from
		 *   this `node_id`:
		 *    - SHOULD ignore the message.
		 */
		/* Check if we are currently verifying the txout for a
		 * matching channel */
		pna = pending_node_map_get(rstate->pending_node_map,
					   &node_id);
		if (!pna) {
			if (was_unknown)
				*was_unknown = true;
			/* Don't complain if it's a zombie node! */
			if (!node || !is_node_zombie(node)) {
				bad_gossip_order(msg, source_peer,
						 type_to_string(tmpctx, struct node_id,
								&node_id));
			}
			return false;
		} else if (timestamp <= pna->timestamp)
			/* Ignore old ones: they're OK (unless from store). */
			return index == 0;

		SUPERVERBOSE("Deferring node_announcement for node %s",
			     type_to_string(tmpctx, struct node_id, &node_id));
		/* a pending spam node announcement is possible when loading
		 * from the store */
		if (index && force_spam_flag) {
			tal_free(pna->spam.node_announcement);
			pna->spam.node_announcement = tal_dup_talarr(pna, u8, msg);
			pna->spam.index = index;
		} else {
			tal_free(pna->node_announcement);
			tal_free(pna->source_peer);
			pna->node_announcement = tal_dup_talarr(pna, u8, msg);
			pna->source_peer = tal_dup_or_null(pna, struct node_id, source_peer);
			pna->timestamp = timestamp;
			pna->index = index;
		}
		return true;
	}

	if (node->bcast.index) {
		u32 redundant_time;

		/* The gossip_store should contain a single broadcastable entry
		 * and potentially one rate-limited entry. Any more is a bug */
		if (index){
			if (!force_spam_flag){
				status_broken("gossip_store broadcastable "
					      "node_announcement %u replaces %u!",
					      index, node->bcast.index);
				return false;
			} else if (node->bcast.index != node->rgraph.index){
				status_broken("gossip_store rate-limited "
					      "node_announcement %u replaces %u!",
					      index, node->rgraph.index);
				return false;
			}
		}

		if (node->rgraph.timestamp >= timestamp) {
			SUPERVERBOSE("Ignoring node announcement, it's outdated.");
			/* OK unless we're loading from store */
			return index == 0;
		}

		/* Allow redundant updates once a day (faster in dev-fast-gossip-prune mode) */
		redundant_time = GOSSIP_PRUNE_INTERVAL(rstate->daemon->dev_fast_gossip_prune) / 14;
		if (timestamp < node->bcast.timestamp + redundant_time
		    && !nannounce_different(rstate->gs, node, msg)) {
			SUPERVERBOSE(
			    "Ignoring redundant nannounce for %s"
			    " (last %u, now %u)",
			    type_to_string(tmpctx, struct node_id, &node_id),
			    node->bcast.timestamp, timestamp);
			/* Ignoring != failing */
			return true;
		}

		/* Make sure it's not spamming us. */
		if (!ratelimit(rstate,
			       &node->tokens, node->bcast.timestamp, timestamp)) {
			status_peer_debug(source_peer,
					  "Spammy nannounce for %s flagged"
					  " (last %u, now %u)",
					  type_to_string(tmpctx,
							 struct node_id,
							 &node_id),
					  node->bcast.timestamp, timestamp);
			spam = true;
		} else {
			spam = false;
		}
	} else {
		spam = false;
	}
	if (force_spam_flag)
		spam = true;

	/* Routing graph always references the latest message. */
	node->rgraph.timestamp = timestamp;
	if (!spam) {
		node->bcast.timestamp = timestamp;
		/* remove prior spam update if one exists */
		if (node->rgraph.index != node->bcast.index) {
			gossip_store_delete(rstate->gs, &node->rgraph,
					    WIRE_NODE_ANNOUNCEMENT);
		}
		/* Harmless if it was never added */
		gossip_store_delete(rstate->gs, &node->bcast,
				    WIRE_NODE_ANNOUNCEMENT);
	/* Remove prior spam update. */
	} else if (node->rgraph.index != node->bcast.index) {
		gossip_store_delete(rstate->gs, &node->rgraph,
				    WIRE_NODE_ANNOUNCEMENT);
	}

	/* Don't add to the store if it was loaded from the store. */
	if (index) {
		node->rgraph.index = index;
		if (!spam)
			node->bcast.index = index;
	} else {
		node->rgraph.index
			= gossip_store_add(rstate->gs, msg, timestamp,
					   false, spam, false, NULL);
		if (!spam)
			node->bcast.index = node->rgraph.index;

		peer_supplied_good_gossip(rstate->daemon, source_peer, 1);
	}

	/* Only log this if *not* loading from store. */
	if (!index)
		status_peer_debug(source_peer,
				  "Received node_announcement for node %s",
				  type_to_string(tmpctx, struct node_id,
						 &node_id));

	return true;
}

u8 *handle_node_announcement(struct routing_state *rstate, const u8 *node_ann,
			     const struct node_id *source_peer TAKES,
			     bool *was_unknown)
{
	u8 *serialized;
	secp256k1_ecdsa_signature signature;
	u32 timestamp;
	struct node_id node_id;
	u8 rgb_color[3];
	u8 alias[32];
	u8 *features, *addresses;
	struct wireaddr *wireaddrs;
	size_t len = tal_count(node_ann);
	struct tlv_node_ann_tlvs *na_tlv;
	const char *err;

	if (was_unknown)
		*was_unknown = false;

	serialized = tal_dup_arr(tmpctx, u8, node_ann, len, 0);
	if (!fromwire_node_announcement(tmpctx, serialized,
					&signature, &features, &timestamp,
					&node_id, rgb_color, alias,
					&addresses,
					&na_tlv)) {
		/* BOLT #7:
		 *
		 *   - if `node_id` is NOT a valid compressed public key:
		 *    - SHOULD send a `warning`.
		 *    - MAY close the connection.
		 *    - MUST NOT process the message further.
		 */
		/* FIXME: We removed a warning about the
		 * node_announcement being malformed since the warning
		 * could cause lnd to disconnect (seems they treat
		 * channel-unrelated warnings as fatal?).
		 */
		return NULL;
	}

	err = sigcheck_node_announcement(tmpctx, &node_id, &signature,
					 serialized);
	if (err)
		return towire_warningfmt(rstate, NULL, "%s", err);

	wireaddrs = fromwire_wireaddr_array(tmpctx, addresses);
	if (!wireaddrs) {
		/* BOLT #7:
		 *
		 * - if `addrlen` is insufficient to hold the address
		 *  descriptors of the known types:
		 *    - SHOULD send a `warning`.
		 *    - MAY close the connection.
		 */
		return towire_warningfmt(rstate, NULL,
					 "Malformed wireaddrs %s in %s.",
					 tal_hex(tmpctx, wireaddrs),
					 tal_hex(tmpctx, node_ann));
	}

	/* May still fail, if we don't know the node. */
	routing_add_node_announcement(rstate, serialized, 0, source_peer, was_unknown, false);
	return NULL;
}

void route_prune(struct routing_state *rstate)
{
	u64 now = gossip_time_now(rstate->daemon).ts.tv_sec;
	/* Anything below this highwater mark ought to be pruned */
	const s64 highwater = now - GOSSIP_PRUNE_INTERVAL(rstate->daemon->dev_fast_gossip_prune);
	struct chan **pruned = tal_arr(tmpctx, struct chan *, 0);
	u64 idx;

	/* Now iterate through all channels and see if it is still alive */
	for (struct chan *chan = uintmap_first(&rstate->chanmap, &idx);
	     chan;
	     chan = uintmap_after(&rstate->chanmap, &idx)) {
		/* These have been pruned already */
		if (is_chan_zombie(chan))
			continue;

		/* BOLT #7:
		 * - if the `timestamp` of the latest `channel_update` in
		 *   either direction is older than two weeks (1209600 seconds):
		 *    - MAY prune the channel.
		 */
		/* This is a fancy way of saying "both ends must refresh!" */
		if (!is_halfchan_defined(&chan->half[0])
		    || chan->half[0].bcast.timestamp < highwater
		    || !is_halfchan_defined(&chan->half[1])
		    || chan->half[1].bcast.timestamp < highwater) {
			if (local_direction(rstate, chan, NULL))
				status_unusual("Pruning local channel %s from gossip_store: not refreshed in over two weeks",
					       type_to_string(tmpctx, struct short_channel_id,
							      &chan->scid));

			status_debug(
			    "Pruning channel %s from network view (ages %"PRIu64" and %"PRIu64"s)",
			    type_to_string(tmpctx, struct short_channel_id,
					   &chan->scid),
			    is_halfchan_defined(&chan->half[0])
			    ? now - chan->half[0].bcast.timestamp : 0,
			    is_halfchan_defined(&chan->half[1])
			    ? now - chan->half[1].bcast.timestamp : 0);

			/* This may perturb iteration so do outside loop. */
			tal_arr_expand(&pruned, chan);
		}
	}

	/* Look for channels we had an announcement for, but no update. */
	for (struct unupdated_channel *uc
		     = uintmap_first(&rstate->unupdated_chanmap, &idx);
	     uc;
	     uc = uintmap_after(&rstate->unupdated_chanmap, &idx)) {
		if (uc->added.ts.tv_sec < highwater) {
			tal_free(uc);
		}
	}

	/* Now free all the chans and maybe even nodes. */
	for (size_t i = 0; i < tal_count(pruned); i++) {
		remove_channel_from_store(rstate, pruned[i]);
		free_chan(rstate, pruned[i]);
	}
}

const char *unfinalized_entries(const tal_t *ctx, struct routing_state *rstate)
{
	struct unupdated_channel *uc;
	u64 index;
	struct pending_node_announce *pna;
	struct pending_node_map_iter it;

	uc = uintmap_first(&rstate->unupdated_chanmap, &index);
	if (uc)
		return tal_fmt(ctx, "Unupdated channel_announcement at %u",
			       uc->index);

	pna = pending_node_map_first(rstate->pending_node_map, &it);
	if (pna)
		return tal_fmt(ctx, "Waiting node_announcement at %u",
			       pna->index);

	return NULL;
}

/* Gossip store was corrupt, forget anything we loaded. */
void remove_all_gossip(struct routing_state *rstate)
{
	struct node *n;
	struct node_map_iter nit;
	struct chan *c;
	struct unupdated_channel *uc;
	u64 index;
	struct pending_cannouncement *pca;
	struct pending_cannouncement_map_iter pit;
	struct pending_node_map_iter pnait;

	/* We don't want them to try to delete from store, so do this
	 * manually. */
	while ((n = node_map_first(rstate->nodes, &nit)) != NULL) {
		tal_del_destructor2(n, destroy_node, rstate);
		node_map_del(rstate->nodes, n);
		tal_free(n);
	}

	/* Now free all the channels. */
	while ((c = uintmap_first(&rstate->chanmap, &index)) != NULL) {
		uintmap_del(&rstate->chanmap, index);
		if (rstate->daemon->developer)
			c->sat = amount_sat((unsigned long)c);
		tal_free(c);
	}

	while ((uc = uintmap_first(&rstate->unupdated_chanmap, &index)) != NULL)
		tal_free(uc);

	while ((pca = pending_cannouncement_map_first(rstate->pending_cannouncements, &pit)) != NULL)
		tal_free(pca);

	/* Freeing unupdated chanmaps should empty this */
	assert(pending_node_map_first(rstate->pending_node_map, &pnait) == NULL);
}

static void channel_spent(struct routing_state *rstate,
			  struct chan *chan STEALS)
{
	status_debug("Deleting channel %s due to the funding outpoint being "
		     "spent",
		     type_to_string(tmpctx, struct short_channel_id,
				    &chan->scid));
	/* Suppress any now-obsolete updates/announcements */
	txout_failures_add(rstate->txf, chan->scid);
	remove_channel_from_store(rstate, chan);
	/* Freeing is sufficient since everything else is allocated off
	 * of the channel and this takes care of unregistering
	 * the channel */
	free_chan(rstate, chan);
}

void routing_expire_channels(struct routing_state *rstate, u32 blockheight)
{
	struct chan *chan;

	for (size_t i = 0; i < tal_count(rstate->dying_channels); i++) {
		struct dying_channel *d = rstate->dying_channels + i;

		if (blockheight < d->deadline_blockheight)
			continue;
		chan = get_channel(rstate, &d->scid);
		if (chan)
			channel_spent(rstate, chan);
		/* Delete dying marker itself */
		gossip_store_delete(rstate->gs,
				    &d->marker, WIRE_GOSSIP_STORE_CHAN_DYING);
		tal_arr_remove(&rstate->dying_channels, i);
		i--;
	}
}

void remember_chan_dying(struct routing_state *rstate,
			 const struct short_channel_id *scid,
			 u32 deadline_blockheight,
			 u64 index)
{
	struct dying_channel d;
	d.scid = *scid;
	d.deadline_blockheight = deadline_blockheight;
	d.marker.index = index;
	tal_arr_expand(&rstate->dying_channels, d);
}

void routing_channel_spent(struct routing_state *rstate,
			   u32 current_blockheight,
			   struct chan *chan)
{
	u64 index;
	u32 deadline;
	u8 *msg;

	/* FIXME: We should note that delay is not necessary (or even
	 * sensible) for local channels! */
	if (local_direction(rstate, chan, NULL)) {
		channel_spent(rstate, chan);
		return;
	}

	/* BOLT #7:
	 * - once its funding output has been spent OR reorganized out:
	 *   - SHOULD forget a channel after a 12-block delay.
	 */
	deadline = current_blockheight + 12;

	/* Save to gossip_store in case we restart */
	msg = towire_gossip_store_chan_dying(tmpctx, &chan->scid, deadline);
	index = gossip_store_add(rstate->gs, msg, 0, false, false, false, NULL);

	/* Mark it dying, so we don't gossip it */
	gossip_store_mark_dying(rstate->gs, &chan->bcast,
				WIRE_CHANNEL_ANNOUNCEMENT);
	for (int dir = 0; dir < ARRAY_SIZE(chan->half); dir++) {
		if (is_halfchan_defined(&chan->half[dir])) {
			gossip_store_mark_dying(rstate->gs,
						&chan->half[dir].bcast,
						WIRE_CHANNEL_UPDATE);
		}
	}

	/* Remember locally so we can kill it in 12 blocks */
	status_debug("channel %s closing soon due"
		     " to the funding outpoint being spent",
		     type_to_string(msg, struct short_channel_id, &chan->scid));
	remember_chan_dying(rstate, &chan->scid, deadline, index);
}
