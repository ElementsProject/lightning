#include "routing.h"
#include <arpa/inet.h>
#include <bitcoin/block.h>
#include <bitcoin/script.h>
#include <ccan/array_size/array_size.h>
#include <ccan/endian/endian.h>
#include <ccan/mem/mem.h>
#include <ccan/tal/str/str.h>
#include <common/features.h>
#include <common/memleak.h>
#include <common/pseudorand.h>
#include <common/status.h>
#include <common/type_to_string.h>
#include <common/wire_error.h>
#include <common/wireaddr.h>
#include <gossipd/gen_gossip_peerd_wire.h>
#include <gossipd/gen_gossip_store.h>
#include <gossipd/gen_gossip_wire.h>
#include <inttypes.h>
#include <wire/gen_peer_wire.h>

#ifndef SUPERVERBOSE
#define SUPERVERBOSE(...)
#endif

/* 365.25 * 24 * 60 / 10 */
#define BLOCKS_PER_YEAR 52596

struct pending_node_announce {
	struct routing_state *rstate;
	struct node_id nodeid;
	size_t refcount;
	u8 *node_announcement;
	u32 timestamp;
	u32 index;
};

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
	tal_add_destructor(map, node_map_clear);
	return map;
}

/* We use a simple array (with NULL entries) until we have too many. */
static bool node_uses_chan_map(const struct node *node)
{
	/* This is a layering violation: last entry in htable is the table ptr,
	 * which is never NULL */
	return node->chans.arr[NUM_IMMEDIATE_CHANS] != NULL;
}

/* When simple array fills, use a htable. */
static void convert_node_to_chan_map(struct node *node)
{
	struct chan *chans[NUM_IMMEDIATE_CHANS];

	memcpy(chans, node->chans.arr, sizeof(chans));
	chan_map_init_sized(&node->chans.map, NUM_IMMEDIATE_CHANS + 1);
	assert(node_uses_chan_map(node));
	for (size_t i = 0; i < ARRAY_SIZE(chans); i++)
		chan_map_add(&node->chans.map, chans[i]);
}

static void add_chan(struct node *node, struct chan *chan)
{
	if (!node_uses_chan_map(node)) {
		for (size_t i = 0; i < NUM_IMMEDIATE_CHANS; i++) {
			if (node->chans.arr[i] == NULL) {
				node->chans.arr[i] = chan;
				return;
			}
		}
		convert_node_to_chan_map(node);
	}

	chan_map_add(&node->chans.map, chan);
}

static struct chan *next_chan_arr(const struct node *node,
				  struct chan_map_iter *i)
{
	while (i->i.off < NUM_IMMEDIATE_CHANS) {
		if (node->chans.arr[i->i.off])
			return node->chans.arr[i->i.off];
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

	return chan_map_first(&node->chans.map, i);
}

struct chan *next_chan(const struct node *node, struct chan_map_iter *i)
{
	if (!node_uses_chan_map(node)) {
		i->i.off++;
		return next_chan_arr(node, i);
	}

	return chan_map_next(&node->chans.map, i);
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

struct routing_state *new_routing_state(const tal_t *ctx,
					const struct chainparams *chainparams,
					const struct node_id *local_id,
					u32 prune_timeout,
					struct list_head *peers,
					const u32 *dev_gossip_time)
{
	struct routing_state *rstate = tal(ctx, struct routing_state);
	rstate->nodes = new_node_map(rstate);
	rstate->gs = gossip_store_new(rstate, peers);
	rstate->chainparams = chainparams;
	rstate->local_id = *local_id;
	rstate->prune_timeout = prune_timeout;
	rstate->local_channel_announced = false;

	pending_cannouncement_map_init(&rstate->pending_cannouncements);

	uintmap_init(&rstate->chanmap);
	uintmap_init(&rstate->unupdated_chanmap);
	chan_map_init(&rstate->local_disabled_map);
	uintmap_init(&rstate->txout_failures);

	rstate->pending_node_map = tal(ctx, struct pending_node_map);
	pending_node_map_init(rstate->pending_node_map);

#if DEVELOPER
	if (dev_gossip_time) {
		rstate->gossip_time = tal(rstate, struct timeabs);
		rstate->gossip_time->ts.tv_sec = *dev_gossip_time;
		rstate->gossip_time->ts.tv_nsec = 0;
	} else
		rstate->gossip_time = NULL;
#endif
	tal_add_destructor(rstate, destroy_routing_state);

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

	/* Free htable if we need. */
	if (node_uses_chan_map(node))
		chan_map_clear(&node->chans.map);
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
	memset(n->chans.arr, 0, sizeof(n->chans.arr));
	broadcastable_init(&n->bcast);
	node_map_add(rstate->nodes, n);
	tal_add_destructor2(n, destroy_node, rstate);

	return n;
}

/* We've received a channel_announce for a channel attached to this node:
 * otherwise it's in the map only because it's a peer, or us. */
static bool node_has_public_channels(struct node *node)
{
	struct chan_map_iter i;
	struct chan *c;

	for (c = first_chan(node, &i); c; c = next_chan(node, &i)) {
		if (is_chan_public(c))
			return true;
	}
	return false;
}

/* We can *send* a channel_announce for a channel attached to this node:
 * we only send once we have a channel_update. */
static bool node_has_broadcastable_channels(struct node *node)
{
	struct chan_map_iter i;
	struct chan *c;

	for (c = first_chan(node, &i); c; c = next_chan(node, &i)) {
		if (!is_chan_public(c))
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
		if (!is_chan_public(c))
			continue;

		if (c->bcast.index < node->bcast.index)
			return false;
	}
	return true;
}

static void remove_chan_from_node(struct routing_state *rstate,
				  struct node *node, const struct chan *chan)
{
	size_t num_chans;

	if (!node_uses_chan_map(node)) {
		num_chans = 0;
		for (size_t i = 0; i < NUM_IMMEDIATE_CHANS; i++) {
			if (node->chans.arr[i] == chan)
				node->chans.arr[i] = NULL;
			else if (node->chans.arr[i] != NULL)
				num_chans++;
		}
	} else {
		if (!chan_map_del(&node->chans.map, chan))
			abort();
		/* FIXME: Expose this in ccan/htable */
		num_chans = node->chans.map.raw.elems;
	}

	/* Last channel?  Simply delete node (and associated announce) */
	if (num_chans == 0) {
		gossip_store_delete(rstate->gs,
				    &node->bcast,
				    WIRE_NODE_ANNOUNCEMENT);
		tal_free(node);
		return;
	}

	if (!node->bcast.index)
		return;

	/* Removed only public channel?  Remove node announcement. */
	if (!node_has_broadcastable_channels(node)) {
		gossip_store_delete(rstate->gs,
				    &node->bcast,
				    WIRE_NODE_ANNOUNCEMENT);
	} else if (node_announce_predates_channels(node)) {
		const u8 *announce;

		announce = gossip_store_get(tmpctx, rstate->gs,
					    node->bcast.index);

		/* node announcement predates all channel announcements?
		 * Move to end (we could, in theory, move to just past next
		 * channel_announce, but we don't care that much about spurious
		 * retransmissions in this corner case */
		gossip_store_delete(rstate->gs,
				    &node->bcast,
				    WIRE_NODE_ANNOUNCEMENT);
		node->bcast.index = gossip_store_add(rstate->gs,
						     announce,
						     node->bcast.timestamp,
						     NULL);
	}
}

/* We used to make this a tal_add_destructor2, but that costs 40 bytes per
 * chan, and we only ever explicitly free it anyway. */
void free_chan(struct routing_state *rstate, struct chan *chan)
{
	remove_chan_from_node(rstate, chan->nodes[0], chan);
	remove_chan_from_node(rstate, chan->nodes[1], chan);

	uintmap_del(&rstate->chanmap, chan->scid.u64);

	/* Remove from local_disabled_map if it's there. */
	chan_map_del(&rstate->local_disabled_map, chan);
	tal_free(chan);
}

static void init_half_chan(struct routing_state *rstate,
				 struct chan *chan,
				 int channel_idx)
{
	struct half_chan *c = &chan->half[channel_idx];

	/* Set the channel direction */
	c->channel_flags = channel_idx;
	// TODO: wireup message_flags
	c->message_flags = 0;
	broadcastable_init(&c->bcast);
}

static void bad_gossip_order(const u8 *msg, const char *source,
			     const char *details)
{
	status_trace("Bad gossip order from %s: %s before announcement %s",
		     source, wire_type_name(fromwire_peektype(msg)),
		     details);
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

/* Too big to reach, but don't overflow if added. */
#define INFINITE AMOUNT_MSAT(0x3FFFFFFFFFFFFFFFULL)

/* We hack a multimap into a uintmap to implement a minheap by cost.
 * This is relatively inefficient, containing an array for each cost
 * value, assuming there aren't too many at same cost.
 *
 * We further optimize by never freeing or shrinking these entries,
 * but delete by replacing with NULL.  This means that we cache the
 * lowest index which actually contains something, since others may
 * contain empty arrays. */
struct unvisited {
	u64 min_index;
	UINTMAP(struct node **) map;
};


/* Risk of passing through this channel.
 *
 * There are two ways this function is used:
 *
 * 1. Normally, riskbias = 1.  A tiny bias here in order to prefer
 *    shorter routes, all things equal.
 * 2. Trying to find a shorter route, riskbias > 1.  By adding an extra
 *    cost to every hop, we're trying to bias against overlength routes.
 */
static WARN_UNUSED_RESULT bool risk_add_fee(struct amount_msat *risk,
					    struct amount_msat msat,
					    u32 delay, double riskfactor,
					    u64 riskbias)
{
	double r;

	/* Won't overflow on add, just lose precision */
	r = (double)riskbias + riskfactor * delay * msat.millisatoshis + risk->millisatoshis; /* Raw: to double */
	if (r > UINT64_MAX)
		return false;
	risk->millisatoshis = r; /* Raw: from double */
	return true;
}

/* Check that we can fit through this channel's indicated
 * maximum_ and minimum_msat requirements.
 */
static bool hc_can_carry(const struct half_chan *hc,
			 struct amount_msat requiredcap)
{
	return amount_msat_greater_eq(hc->htlc_maximum, requiredcap) &&
		amount_msat_less_eq(hc->htlc_minimum, requiredcap);
}

/* Theoretically, this could overflow. */
static bool fuzz_fee(u64 *fee,
		     const struct short_channel_id *scid,
		     double fuzz, const struct siphash_seed *base_seed)
{
	u64 fuzzed_fee, h;
 	double fee_scale;

	if (fuzz == 0.0)
		return true;

	h = siphash24(base_seed, scid, sizeof(*scid));

	/* Scale fees for this channel */
	/* rand = (h / UINT64_MAX)  random number between 0.0 -> 1.0
	 * 2*fuzz*rand              random number between 0.0 -> 2*fuzz
	 * 2*fuzz*rand - fuzz       random number between -fuzz -> +fuzz
	 */
	fee_scale = 1.0 + (2.0 * fuzz * h / UINT64_MAX) - fuzz;
	fuzzed_fee = *fee * fee_scale;
	if (fee_scale > 1.0 && fuzzed_fee < *fee)
		return false;
	*fee = fuzzed_fee;
	return true;
}

/* Can we carry this amount across the channel?  If so, returns true and
 * sets newtotal and newrisk */
static bool can_reach(const struct half_chan *c,
		      const struct short_channel_id *scid,
		      bool no_charge,
		      struct amount_msat total,
		      struct amount_msat risk,
		      double riskfactor,
		      u64 riskbias,
		      double fuzz, const struct siphash_seed *base_seed,
		      struct amount_msat *newtotal, struct amount_msat *newrisk)
{
	/* FIXME: Bias against smaller channels. */
	struct amount_msat fee;

	if (!amount_msat_fee(&fee, total, c->base_fee, c->proportional_fee))
		return false;

  	if (!fuzz_fee(&fee.millisatoshis, scid, fuzz, base_seed)) /* Raw: double manipulation */
		return false;

	if (no_charge) {
		*newtotal = total;

		/* We still want to consider the "charge", since it's indicative
		 * of a bias (we discounted one channel for a reason), but we
		 * don't pay it.  So we count it as additional risk. */
		if (!amount_msat_add(newrisk, risk, fee))
			return false;
	} else {
		*newrisk = risk;

		if (!amount_msat_add(newtotal, total, fee))
			return false;
	}

	/* Skip a channel if it indicated that it won't route the
	 * requested amount. */
	if (!hc_can_carry(c, *newtotal))
		return false;

	if (!risk_add_fee(newrisk, *newtotal, c->delay, riskfactor, riskbias))
		return false;

	return true;
}

/* Returns false on overflow (shouldn't happen!) */
typedef bool WARN_UNUSED_RESULT costfn_t(struct amount_msat *,
					 struct amount_msat,
					 struct amount_msat);

static WARN_UNUSED_RESULT bool
normal_cost_function(struct amount_msat *cost,
		     struct amount_msat total, struct amount_msat risk)
{
	if (amount_msat_add(cost, total, risk))
		return true;

	status_broken("Can't add cost of node %s + %s",
		      type_to_string(tmpctx, struct amount_msat, &total),
		      type_to_string(tmpctx, struct amount_msat, &risk));
	return false;
}

static WARN_UNUSED_RESULT bool
shortest_cost_function(struct amount_msat *cost,
		       struct amount_msat total, struct amount_msat risk)
{
	/* We add 1, so cost is never 0, for our hacky uintmap-as-minheap. */
	if (amount_msat_add(cost, risk, AMOUNT_MSAT(1)))
		return true;

	status_broken("Can't add 1 to risk of node %s",
		      type_to_string(tmpctx, struct amount_msat, &risk));
	return false;
}

/* Does totala+riska add up to less than totalb+riskb?
 * Saves sums if you want them.
 */
static bool costs_less(struct amount_msat totala,
		       struct amount_msat riska,
		       struct amount_msat *costa,
		       struct amount_msat totalb,
		       struct amount_msat riskb,
		       struct amount_msat *costb,
		       costfn_t *costfn)
{
	struct amount_msat suma, sumb;

	if (!costfn(&suma, totala, riska))
		return false;
	if (!costfn(&sumb, totalb, riskb))
		return false;

	if (costa)
		*costa = suma;
	if (costb)
		*costb = sumb;
	return amount_msat_less(suma, sumb);
}

/* Determine if the given half_chan is routable */
static bool hc_is_routable(struct routing_state *rstate,
			   const struct chan *chan, int idx)
{
	return is_halfchan_enabled(&chan->half[idx])
		&& !is_chan_local_disabled(rstate, chan);
}

static void unvisited_add(struct unvisited *unvisited, struct amount_msat cost,
			  struct node **arr)
{
	u64 idx = cost.millisatoshis; /* Raw: uintmap needs u64 index */
	if (idx < unvisited->min_index) {
		assert(idx); /* We don't allow sending 0 satoshis */
		unvisited->min_index = idx - 1;
	}
	uintmap_add(&unvisited->map, idx, arr);
}

static struct node **unvisited_get(const struct unvisited *unvisited,
				   struct amount_msat cost)
{
	return uintmap_get(&unvisited->map, cost.millisatoshis); /* Raw: uintmap */
}

static struct node **unvisited_del(struct unvisited *unvisited,
				   struct amount_msat cost)
{
	return uintmap_del(&unvisited->map, cost.millisatoshis); /* Raw: uintmap */
}

static bool is_unvisited(const struct node *node,
			 const struct unvisited *unvisited,
			 costfn_t *costfn)
{
	struct node **arr;
	struct amount_msat cost;

	/* If it's infinite, definitely unvisited */
	if (amount_msat_eq(node->dijkstra.total, INFINITE))
		return true;

	/* Shouldn't happen! */
	if (!costfn(&cost, node->dijkstra.total, node->dijkstra.risk))
		return false;

	arr = unvisited_get(unvisited, cost);
	for (size_t i = 0; i < tal_count(arr); i++) {
		if (arr[i] == node)
			return true;
	}
	return false;
}

static void unvisited_del_node(struct unvisited *unvisited,
			       struct amount_msat cost,
			       const struct node *node)
{
	struct node **arr;

	arr = unvisited_get(unvisited, cost);
	for (size_t i = 0; i < tal_count(arr); i++) {
		if (arr[i] == node) {
			arr[i] = NULL;
			return;
		}
	}
	abort();
}

static void adjust_unvisited(struct node *node,
			     struct unvisited *unvisited,
			     struct amount_msat cost_before,
			     struct amount_msat total,
			     struct amount_msat risk,
			     struct amount_msat cost_after)
{
	struct node **arr;

	/* If it was in unvisited map, remove it. */
	if (!amount_msat_eq(node->dijkstra.total, INFINITE))
		unvisited_del_node(unvisited, cost_before, node);

	/* Update node */
	node->dijkstra.total = total;
	node->dijkstra.risk = risk;

	SUPERVERBOSE("%s now cost %s",
		     type_to_string(tmpctx, struct node_id, &node->id),
		     type_to_string(tmpctx, struct amount_msat, &cost_after));

	/* Update map of unvisited nodes */
	arr = unvisited_get(unvisited, cost_after);
	if (arr) {
		struct node **old_arr;
		/* Try for empty slot */
		for (size_t i = 0; i < tal_count(arr); i++) {
			if (arr[i] == NULL) {
				arr[i] = node;
				return;
			}
		}
		/* Nope, expand */
		old_arr = arr;
		tal_arr_expand(&arr, node);
		if (arr == old_arr)
			return;

		/* Realloc moved it; del and add again. */
		unvisited_del(unvisited, cost_after);
	} else {
		arr = tal_arr(unvisited, struct node *, 1);
		arr[0] = node;
	}

	unvisited_add(unvisited, cost_after, arr);
}

static void remove_unvisited(struct node *node, struct unvisited *unvisited,
			     costfn_t *costfn)
{
	struct amount_msat cost;

	/* Shouldn't happen! */
	if (!costfn(&cost, node->dijkstra.total, node->dijkstra.risk))
		return;

	unvisited_del_node(unvisited, cost, node);
}

static void update_unvisited_neighbors(struct routing_state *rstate,
				       struct node *cur,
				       const struct node *me,
				       double riskfactor,
				       u64 riskbias,
				       double fuzz,
				       const struct siphash_seed *base_seed,
				       struct unvisited *unvisited,
				       costfn_t *costfn)
{
	struct chan_map_iter i;
	struct chan *chan;

	/* Consider all neighbors */
	for (chan = first_chan(cur, &i); chan; chan = next_chan(cur, &i)) {
		struct amount_msat total, risk, cost_before, cost_after;
		int idx = half_chan_to(cur, chan);
		struct node *peer = chan->nodes[idx];

		SUPERVERBOSE("CONSIDERING: %s -> %s (%s/%s)",
			     type_to_string(tmpctx, struct node_id,
					    &cur->id),
			     type_to_string(tmpctx, struct node_id,
					    &peer->id),
			     type_to_string(tmpctx, struct amount_msat,
					    &peer->dijkstra.total),
			     type_to_string(tmpctx, struct amount_msat,
					    &peer->dijkstra.risk));

		if (!hc_is_routable(rstate, chan, idx)) {
			SUPERVERBOSE("... not routable");
			continue;
		}

		if (!is_unvisited(peer, unvisited, costfn)) {
			SUPERVERBOSE("... already visited");
			continue;
		}

		/* We're looking at channels *backwards*, so peer == me
		 * is the right test here for whether we don't charge fees. */
		if (!can_reach(&chan->half[idx], &chan->scid, peer == me,
			       cur->dijkstra.total, cur->dijkstra.risk,
			       riskfactor, riskbias, fuzz, base_seed,
			       &total, &risk)) {
			SUPERVERBOSE("... can't reach");
			continue;
		}

		/* This effectively adds it to the map if it was infinite */
		if (costs_less(total, risk, &cost_after,
			       peer->dijkstra.total, peer->dijkstra.risk,
			       &cost_before,
			       costfn)) {
			SUPERVERBOSE("...%s can reach %s"
				     " total %s risk %s",
				     type_to_string(tmpctx, struct node_id,
						    &cur->id),
				     type_to_string(tmpctx, struct node_id,
						    &peer->id),
				     type_to_string(tmpctx, struct amount_msat,
						    &total),
				     type_to_string(tmpctx, struct amount_msat,
						    &risk));
			adjust_unvisited(peer, unvisited,
					 cost_before, total, risk, cost_after);
		}
	}
}

static struct node *first_unvisited(struct unvisited *unvisited)
{
	struct node **arr;

	while ((arr = uintmap_after(&unvisited->map, &unvisited->min_index))) {
		for (size_t i = 0; i < tal_count(arr); i++) {
			if (arr[i]) {
				unvisited->min_index--;
				return arr[i];
			}
		}
	}

	return NULL;
}

static void dijkstra(struct routing_state *rstate,
		     const struct node *dst,
		     const struct node *me,
		     double riskfactor,
		     u64 riskbias,
		     double fuzz, const struct siphash_seed *base_seed,
		     struct unvisited *unvisited,
		     costfn_t *costfn)
{
	struct node *cur;

	while ((cur = first_unvisited(unvisited)) != NULL) {
		update_unvisited_neighbors(rstate, cur, me,
					   riskfactor, riskbias,
					   fuzz, base_seed, unvisited, costfn);
		remove_unvisited(cur, unvisited, costfn);
		if (cur == dst)
			return;
	}
}

/* Note that we calculated route *backwards*, for fees.  So "from"
 * here has a high cost, "to" has a cost of exact amount sent. */
static struct chan **build_route(const tal_t *ctx,
				 struct routing_state *rstate,
				 const struct node *from,
				 const struct node *to,
				 const struct node *me,
				 double riskfactor,
				 u64 riskbias,
				 double fuzz,
				 const struct siphash_seed *base_seed,
				 struct amount_msat *fee)
{
	const struct node *i;
	struct chan **route, *chan;

	SUPERVERBOSE("Building route from %s (%s) -> %s (%s)",
		     type_to_string(tmpctx, struct node_id, &from->id),
		     type_to_string(tmpctx, struct amount_msat,
				    &from->dijkstra.total),
		     type_to_string(tmpctx, struct node_id, &to->id),
		     type_to_string(tmpctx, struct amount_msat,
				    &to->dijkstra.total));
	/* Never reached? */
	if (amount_msat_eq(from->dijkstra.total, INFINITE))
		return NULL;

	/* Walk to find which neighbors we used */
	route = tal_arr(ctx, struct chan *, 0);
	for (i = from; i != to; i = other_node(i, chan)) {
		struct chan_map_iter it;

		/* Consider all neighbors */
		for (chan = first_chan(i, &it); chan; chan = next_chan(i, &it)) {
			struct node *peer = other_node(i, chan);
			struct half_chan *hc = half_chan_from(i, chan);
			struct amount_msat total, risk;

			SUPERVERBOSE("CONSIDER: %s -> %s (%s/%s)",
				     type_to_string(tmpctx, struct node_id,
						    &i->id),
				     type_to_string(tmpctx, struct node_id,
						    &peer->id),
				     type_to_string(tmpctx, struct amount_msat,
						    &peer->dijkstra.total),
				     type_to_string(tmpctx, struct amount_msat,
						    &peer->dijkstra.risk));

			/* If traversing this wasn't possible, ignore */
			if (!hc_is_routable(rstate, chan, !half_chan_to(i, chan))) {
				continue;
			}

			if (!can_reach(hc, &chan->scid, i == me,
				       peer->dijkstra.total, peer->dijkstra.risk,
				       riskfactor,
				       riskbias,
				       fuzz, base_seed,
				       &total, &risk))
				continue;

			/* If this was the path we took, we're done (if there are
			 * two identical ones, it doesn't matter which) */
			if (amount_msat_eq(total, i->dijkstra.total)
			    && amount_msat_eq(risk, i->dijkstra.risk))
				break;
		}

		if (!chan) {
			status_broken("Could not find hop to %s",
				      type_to_string(tmpctx, struct node_id,
						     &i->id));
			return tal_free(route);
		}
		tal_arr_expand(&route, chan);
	}

	/* We don't charge ourselves fees, so skip first hop */
	if (!amount_msat_sub(fee,
			     other_node(from, route[0])->dijkstra.total,
			     to->dijkstra.total)) {
		status_broken("Could not subtract %s - %s for fee",
			      type_to_string(tmpctx, struct amount_msat,
					     &other_node(from, route[0])
					     ->dijkstra.total),
			      type_to_string(tmpctx, struct amount_msat,
					     &to->dijkstra.total));
		return tal_free(route);
	}

	return route;
}

static struct unvisited *dijkstra_prepare(const tal_t *ctx,
					  struct routing_state *rstate,
					  struct node *src,
					  struct amount_msat msat,
					  costfn_t *costfn)
{
	struct node_map_iter it;
	struct unvisited *unvisited;
	struct node *n;
	struct node **arr;
	struct amount_msat cost;

	unvisited = tal(tmpctx, struct unvisited);
	uintmap_init(&unvisited->map);
	unvisited->min_index = UINT64_MAX;

	/* Reset all the information. */
	for (n = node_map_first(rstate->nodes, &it);
	     n;
	     n = node_map_next(rstate->nodes, &it)) {
		if (n == src)
			continue;
		n->dijkstra.total = INFINITE;
		n->dijkstra.risk = INFINITE;
	}

	/* Mark start cost: place in unvisited map. */
	src->dijkstra.total = msat;
	src->dijkstra.risk = AMOUNT_MSAT(0);
	arr = tal_arr(unvisited, struct node *, 1);
	arr[0] = src;
	/* Adding 0 can never fail */
	if (!costfn(&cost, src->dijkstra.total, src->dijkstra.risk))
		abort();
	unvisited_add(unvisited, cost, arr);

	return unvisited;
}

static void dijkstra_cleanup(struct unvisited *unvisited)
{
	struct node **arr;
	u64 idx;

	/* uintmap uses malloc, so manual cleaning needed */
	while ((arr = uintmap_first(&unvisited->map, &idx)) != NULL) {
		tal_free(arr);
		uintmap_del(&unvisited->map, idx);
	}
	tal_free(unvisited);
}

/* We need to start biassing against long routes. */
static struct chan **
find_shorter_route(const tal_t *ctx, struct routing_state *rstate,
		   struct node *src, struct node *dst,
		   const struct node *me,
		   struct amount_msat msat,
		   size_t max_hops,
		   double fuzz, const struct siphash_seed *base_seed,
		   struct chan **long_route,
		   struct amount_msat *fee)
{
	struct unvisited *unvisited;
	struct chan **short_route = NULL;
	struct amount_msat long_cost, short_cost, cost_diff;
	u64 min_bias, max_bias;
	double riskfactor;

	/* We traverse backwards, so dst has largest total */
	if (!amount_msat_sub(&long_cost,
			     dst->dijkstra.total, src->dijkstra.total))
		goto bad_total;
	tal_free(long_route);

	/* FIXME: It's hard to juggle both the riskfactor and riskbias here,
	 * so we set our riskfactor to rougly equate to 1 millisatoshi
	 * per block delay, which is close enough to zero to not break
	 * this algorithm, but still provide some bias towards
	 * low-delay routes. */
	riskfactor = (double)1.0 / msat.millisatoshis; /* Raw: inversion */

	/* First, figure out if a short route is even possible.
	 * We set the cost function to ignore total, riskbias 1 and riskfactor
	 * ~0 so risk simply operates as a simple hop counter. */
	unvisited = dijkstra_prepare(tmpctx, rstate, src, msat,
				     shortest_cost_function);
	SUPERVERBOSE("Running shortest path from %s -> %s",
		     type_to_string(tmpctx, struct node_id, &dst->id),
		     type_to_string(tmpctx, struct node_id, &src->id));
	dijkstra(rstate, dst, NULL, riskfactor, 1, fuzz, base_seed,
		 unvisited, shortest_cost_function);
	dijkstra_cleanup(unvisited);

	/* This must succeed, since we found a route before */
	short_route = build_route(ctx, rstate, dst, src, me, riskfactor, 1,
				  fuzz, base_seed, fee);
	assert(short_route);
	if (!amount_msat_sub(&short_cost,
			     dst->dijkstra.total, src->dijkstra.total))
		goto bad_total;

	/* Still too long?  Oh well. */
	if (tal_count(short_route) > max_hops) {
		status_info("Minimal possible route %s->%s is %zu",
			    type_to_string(tmpctx, struct node_id, &dst->id),
			    type_to_string(tmpctx, struct node_id, &src->id),
			    tal_count(short_route));
		goto out;
	}

	/* OK, so it's possible, just more expensive. */
	min_bias = 0;

	if (!amount_msat_sub(&cost_diff, short_cost, long_cost)) {
		status_broken("Short cost %s < long cost %s?",
			      type_to_string(tmpctx, struct amount_msat,
					     &short_cost),
			      type_to_string(tmpctx, struct amount_msat,
					     &long_cost));
		goto out;
	}

	/* This is a gross overestimate, but it works. */
	max_bias = cost_diff.millisatoshis; /* Raw: bias calc */

	SUPERVERBOSE("maxbias %"PRIu64" gave rlen %zu",
		     max_bias, tal_count(short_route));

	/* Now, binary search */
	while (min_bias < max_bias) {
		struct chan **route;
		struct amount_msat this_fee;
		u64 riskbias = (min_bias + max_bias) / 2;

		unvisited = dijkstra_prepare(tmpctx, rstate, src, msat,
					     normal_cost_function);
		dijkstra(rstate, dst, me, riskfactor, riskbias, fuzz, base_seed,
			 unvisited, normal_cost_function);
		dijkstra_cleanup(unvisited);

		route = build_route(ctx, rstate, dst, src, me,
				    riskfactor, riskbias,
				    fuzz, base_seed, &this_fee);

		SUPERVERBOSE("riskbias %"PRIu64" rlen %zu",
			     riskbias, tal_count(route));
		/* Too long still?  This is our new min_bias */
		if (tal_count(route) > max_hops) {
			tal_free(route);
			min_bias = riskbias + 1;
		} else {
			/* This route is acceptable. */
			tal_free(short_route);
			short_route = route;
			/* Save this fee in case we exit loop */
			*fee = this_fee;
			max_bias = riskbias;
		}
	}

	return short_route;

bad_total:
	status_broken("dst total %s < src total %s?",
		      type_to_string(tmpctx, struct amount_msat,
				     &dst->dijkstra.total),
		      type_to_string(tmpctx, struct amount_msat,
				     &src->dijkstra.total));
out:
	tal_free(short_route);
	return NULL;
}

/* riskfactor is already scaled to per-block amount */
static struct chan **
find_route(const tal_t *ctx, struct routing_state *rstate,
	   const struct node_id *from, const struct node_id *to,
	   struct amount_msat msat,
	   double riskfactor,
	   double fuzz, const struct siphash_seed *base_seed,
	   size_t max_hops,
	   struct amount_msat *fee)
{
	struct node *src, *dst;
	const struct node *me;
	struct unvisited *unvisited;
	struct chan **route;

	/* Note: we map backwards, since we know the amount of satoshi we want
	 * at the end, and need to derive how much we need to send. */
	src = get_node(rstate, to);

	/* If from is NULL, that's means it's us. */
	if (!from)
		me = dst = get_node(rstate, &rstate->local_id);
	else {
		dst = get_node(rstate, from);
		me = NULL;
	}

	if (!src) {
		status_info("find_route: cannot find %s",
			    type_to_string(tmpctx, struct node_id, to));
		return NULL;
	} else if (!dst) {
		status_info("find_route: cannot find source (%s)",
			    type_to_string(tmpctx, struct node_id, to));
		return NULL;
	} else if (dst == src) {
		status_info("find_route: this is %s, refusing to create empty route",
			    type_to_string(tmpctx, struct node_id, to));
		return NULL;
	}

	unvisited = dijkstra_prepare(tmpctx, rstate, src, msat,
				     normal_cost_function);
	dijkstra(rstate, dst, me, riskfactor, 1, fuzz, base_seed,
		 unvisited, normal_cost_function);
	dijkstra_cleanup(unvisited);

	route = build_route(ctx, rstate, dst, src, me, riskfactor, 1,
			    fuzz, base_seed, fee);
	if (tal_count(route) <= max_hops)
		return route;

	/* This is the far more unlikely case */
	return find_shorter_route(ctx, rstate, src, dst, me, msat,
				  max_hops, fuzz, base_seed, route, fee);
}

/* Checks that key is valid, and signed this hash */
static bool check_signed_hash_nodeid(const struct sha256_double *hash,
				     const secp256k1_ecdsa_signature *signature,
				     const struct node_id *id)
{
	struct pubkey key;

	return pubkey_from_node_id(&key, id)
		&& check_signed_hash(hash, signature, &key);
}

/* Verify the signature of a channel_update message */
static u8 *check_channel_update(const tal_t *ctx,
				const struct node_id *node_id,
				const secp256k1_ecdsa_signature *node_sig,
				const u8 *update)
{
	/* 2 byte msg type + 64 byte signatures */
	int offset = 66;
	struct sha256_double hash;
	sha256_double(&hash, update + offset, tal_count(update) - offset);

	if (!check_signed_hash_nodeid(&hash, node_sig, node_id))
		return towire_errorfmt(ctx, NULL,
				       "Bad signature for %s hash %s"
				       " on channel_update %s",
				       type_to_string(ctx,
						      secp256k1_ecdsa_signature,
						      node_sig),
				       type_to_string(ctx,
						      struct sha256_double,
						      &hash),
				       tal_hex(ctx, update));
	return NULL;
}

static u8 *check_channel_announcement(const tal_t *ctx,
	const struct node_id *node1_id, const struct node_id *node2_id,
	const struct pubkey *bitcoin1_key, const struct pubkey *bitcoin2_key,
	const secp256k1_ecdsa_signature *node1_sig,
	const secp256k1_ecdsa_signature *node2_sig,
	const secp256k1_ecdsa_signature *bitcoin1_sig,
	const secp256k1_ecdsa_signature *bitcoin2_sig, const u8 *announcement)
{
	/* 2 byte msg type + 256 byte signatures */
	int offset = 258;
	struct sha256_double hash;
	sha256_double(&hash, announcement + offset,
		      tal_count(announcement) - offset);

	if (!check_signed_hash_nodeid(&hash, node1_sig, node1_id)) {
		return towire_errorfmt(ctx, NULL,
				       "Bad node_signature_1 %s hash %s"
				       " on node_announcement %s",
				       type_to_string(ctx,
						      secp256k1_ecdsa_signature,
						      node1_sig),
				       type_to_string(ctx,
						      struct sha256_double,
						      &hash),
				       tal_hex(ctx, announcement));
	}
	if (!check_signed_hash_nodeid(&hash, node2_sig, node2_id)) {
		return towire_errorfmt(ctx, NULL,
				       "Bad node_signature_2 %s hash %s"
				       " on node_announcement %s",
				       type_to_string(ctx,
						      secp256k1_ecdsa_signature,
						      node2_sig),
				       type_to_string(ctx,
						      struct sha256_double,
						      &hash),
				       tal_hex(ctx, announcement));
	}
	if (!check_signed_hash(&hash, bitcoin1_sig, bitcoin1_key)) {
		return towire_errorfmt(ctx, NULL,
				       "Bad bitcoin_signature_1 %s hash %s"
				       " on node_announcement %s",
				       type_to_string(ctx,
						      secp256k1_ecdsa_signature,
						      bitcoin1_sig),
				       type_to_string(ctx,
						      struct sha256_double,
						      &hash),
				       tal_hex(ctx, announcement));
	}
	if (!check_signed_hash(&hash, bitcoin2_sig, bitcoin2_key)) {
		return towire_errorfmt(ctx, NULL,
				       "Bad bitcoin_signature_2 %s hash %s"
				       " on node_announcement %s",
				       type_to_string(ctx,
						      secp256k1_ecdsa_signature,
						      bitcoin2_sig),
				       type_to_string(ctx,
						      struct sha256_double,
						      &hash),
				       tal_hex(ctx, announcement));
	}
	return NULL;
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

	/* No need if we already know about the node.  We might, however, only
	 * know about it because it's a peer (maybe with private or
	 * not-yet-announced channels), so check for that too. */
	node = get_node(rstate, nodeid);
	if (node && node_has_public_channels(node))
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

		/* Should not error, since we processed it before */
		if (!routing_add_node_announcement(rstate,
						   pna->node_announcement,
						   pna->index))
			status_failed(STATUS_FAIL_INTERNAL_ERROR,
				      "pending node_announcement %s malformed?",
				      tal_hex(tmpctx, pna->node_announcement));
		/* Never send this again. */
		pna->node_announcement = tal_free(pna->node_announcement);
	}

	/* We don't need to catch any more node_announcements, since we've
	 * accepted the public channel now.  But other pending announcements
	 * may still hold a reference they use in
	 * del_pending_node_announcement, so simply delete it from the map. */
	pending_node_map_del(rstate->pending_node_map, pna);
}

static struct pending_cannouncement *
find_pending_cannouncement(struct routing_state *rstate,
			   const struct short_channel_id *scid)
{
	struct pending_cannouncement *pann;

	pann = pending_cannouncement_map_get(&rstate->pending_cannouncements, scid);

	return pann;
}

static void destroy_pending_cannouncement(struct pending_cannouncement *pending,
					  struct routing_state *rstate)
{
	pending_cannouncement_map_del(&rstate->pending_cannouncements, pending);
}

static bool is_local_channel(const struct routing_state *rstate,
			     const struct chan *chan)
{
	return node_id_eq(&chan->nodes[0]->id, &rstate->local_id)
		|| node_id_eq(&chan->nodes[1]->id, &rstate->local_id);
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
						     addendum);
	rstate->local_channel_announced |= is_local_channel(rstate, chan);
}

bool routing_add_channel_announcement(struct routing_state *rstate,
				      const u8 *msg TAKES,
				      struct amount_sat sat,
				      u32 index)
{
	struct chan *chan;
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
	const u8 *private_updates[2] = { NULL, NULL };

	/* Make sure we own msg, even if we don't save it. */
	if (taken(msg))
		tal_steal(tmpctx, msg);

	if (!fromwire_channel_announcement(
		    tmpctx, msg, &node_signature_1, &node_signature_2,
		    &bitcoin_signature_1, &bitcoin_signature_2, &features, &chain_hash,
		    &scid, &node_id_1, &node_id_2, &bitcoin_key_1, &bitcoin_key_2))
		return false;

	/* The channel may already exist if it was non-public from
	 * local_add_channel(); normally we don't accept new
	 * channel_announcements.  See handle_channel_announcement. */
	chan = get_channel(rstate, &scid);

	/* private updates will exist in the store before the announce: we
	 * can't index those for broadcast since they would predate it, so we
	 * add fresh ones. */
	if (chan) {
		/* If this was in the gossip_store, gossip_store is bad! */
		if (index) {
			status_broken("gossip_store channel_announce"
				      " %u replaces %u!",
				      index, chan->bcast.index);
			return false;
		}

		/* Reload any private updates */
		if (chan->half[0].bcast.index)
			private_updates[0]
				= gossip_store_get_private_update(NULL,
						   rstate->gs,
						   chan->half[0].bcast.index);
		if (chan->half[1].bcast.index)
			private_updates[1]
				= gossip_store_get_private_update(NULL,
						   rstate->gs,
						   chan->half[1].bcast.index);

		remove_channel_from_store(rstate, chan);
		free_chan(rstate, chan);
	}

	uc = tal(rstate, struct unupdated_channel);
	uc->channel_announce = tal_dup_arr(uc, u8, msg, tal_count(msg), 0);
	uc->added = time_now();
	uc->index = index;
	uc->sat = sat;
	uc->scid = scid;
	uc->id[0] = node_id_1;
	uc->id[1] = node_id_2;
	uintmap_add(&rstate->unupdated_chanmap, scid.u64, uc);
	tal_add_destructor2(uc, destroy_unupdated_channel, rstate);

	/* If a node_announcement comes along, save it for once we're updated */
	catch_node_announcement(uc, rstate, &node_id_1);
	catch_node_announcement(uc, rstate, &node_id_2);

	/* If we had private updates, they'll immediately create the channel. */
	if (private_updates[0])
		routing_add_channel_update(rstate, take(private_updates[0]), 0);
	if (private_updates[1])
		routing_add_channel_update(rstate, take(private_updates[1]), 0);

	return true;
}

u8 *handle_channel_announcement(struct routing_state *rstate,
				const u8 *announce TAKES,
				const struct short_channel_id **scid)
{
	struct pending_cannouncement *pending;
	struct bitcoin_blkid chain_hash;
	u8 *features, *err;
	secp256k1_ecdsa_signature node_signature_1, node_signature_2;
	secp256k1_ecdsa_signature bitcoin_signature_1, bitcoin_signature_2;
	struct chan *chan;

	pending = tal(rstate, struct pending_cannouncement);
	pending->updates[0] = NULL;
	pending->updates[1] = NULL;
	pending->announce = tal_dup_arr(pending, u8,
					announce, tal_count(announce), 0);
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
		err = towire_errorfmt(rstate, NULL,
				      "Malformed channel_announcement %s",
				      tal_hex(pending, pending->announce));
		goto malformed;
	}

	/* If a prior txout lookup failed there is little point it trying
	 * again. Just drop the announcement and walk away whistling. Any non-0
	 * result means this failed before. */
	if (uintmap_get(&rstate->txout_failures, pending->short_channel_id.u64)) {
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
	if (chan != NULL && is_chan_public(chan)) {
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
	 *
	 *  - if `features` field contains _unknown even bits_:
	 *    - MUST NOT parse the remainder of the message.
	 *    - MAY discard the message altogether.
	 *    - SHOULD NOT connect to the node.
	 *  - MAY forward `node_announcement`s that contain an _unknown_
	 *   `features` _bit_, regardless of if it has parsed the announcement
	 *   or not.
	 */
	if (!features_supported(features, NULL)) {
		status_trace("Ignoring channel announcement, unsupported features %s.",
			     tal_hex(pending, features));
		goto ignored;
	}

	/* BOLT #7:
	 * The receiving node:
	 *...
	 *  - if the specified `chain_hash` is unknown to the receiver:
	 *    - MUST ignore the message.
	 */
	if (!bitcoin_blkid_eq(&chain_hash,
			      &rstate->chainparams->genesis_blockhash)) {
		status_trace(
		    "Received channel_announcement %s for unknown chain %s",
		    type_to_string(pending, struct short_channel_id,
				   &pending->short_channel_id),
		    type_to_string(pending, struct bitcoin_blkid, &chain_hash));
		goto ignored;
	}

	/* Note that if node_id_1 or node_id_2 are malformed, it's caught here */
	err = check_channel_announcement(rstate,
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
		 *    - SHOULD fail the connection.
		 */
		goto malformed;
	}

	status_trace("Received channel_announcement for channel %s",
		     type_to_string(tmpctx, struct short_channel_id,
				    &pending->short_channel_id));

	/* Add both endpoints to the pending_node_map so we can stash
	 * node_announcements while we wait for the txout check */
	catch_node_announcement(pending, rstate, &pending->node_id_1);
	catch_node_announcement(pending, rstate, &pending->node_id_2);

	pending_cannouncement_map_add(&rstate->pending_cannouncements, pending);
	tal_add_destructor2(pending, destroy_pending_cannouncement, rstate);

	/* Success */
	// MSC: Cppcheck 1.86 gets this false positive
	// cppcheck-suppress autoVariables
	*scid = &pending->short_channel_id;
	return NULL;

malformed:
	tal_free(pending);
	*scid = NULL;
	return err;

ignored:
	tal_free(pending);
	*scid = NULL;
	return NULL;
}

static void process_pending_channel_update(struct routing_state *rstate,
					   const struct short_channel_id *scid,
					   const u8 *cupdate)
{
	u8 *err;

	if (!cupdate)
		return;

	/* FIXME: We don't remember who sent us updates, so can't error them */
	err = handle_channel_update(rstate, cupdate, "pending update", NULL);
	if (err) {
		status_trace("Pending channel_update for %s: %s",
			     type_to_string(tmpctx, struct short_channel_id, scid),
			     sanitize_error(tmpctx, err, NULL));
		tal_free(err);
	}
}

bool handle_pending_cannouncement(struct routing_state *rstate,
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
		status_trace("channel_announcement: no unspent txout %s",
			     type_to_string(pending, struct short_channel_id,
					    scid));
		tal_free(pending);
		uintmap_add(&rstate->txout_failures, scid->u64, true);
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
		status_trace("channel_announcement: txout %s expectes %s, got %s",
			     type_to_string(pending, struct short_channel_id,
					    scid),
			     tal_hex(tmpctx, s), tal_hex(tmpctx, outscript));
		tal_free(pending);
		return false;
	}

	/* Remove pending now, so below functions don't see it. */
	pending_cannouncement_map_del(&rstate->pending_cannouncements, pending);
	tal_del_destructor2(pending, destroy_pending_cannouncement, rstate);

	if (!routing_add_channel_announcement(rstate, pending->announce, sat, 0))
		status_failed(STATUS_FAIL_INTERNAL_ERROR,
			      "Could not add channel_announcement");

	/* Did we have an update waiting?  If so, apply now. */
	process_pending_channel_update(rstate, scid, pending->updates[0]);
	process_pending_channel_update(rstate, scid, pending->updates[1]);

	tal_free(pending);
	return true;
}

static void update_pending(struct pending_cannouncement *pending,
			   u32 timestamp, const u8 *update,
			   const u8 direction)
{
	SUPERVERBOSE("Deferring update for pending channel %s/%d",
		     type_to_string(tmpctx, struct short_channel_id,
				    &pending->short_channel_id), direction);

	if (pending->update_timestamps[direction] < timestamp) {
		if (pending->updates[direction]) {
			status_trace("Replacing existing update");
			tal_free(pending->updates[direction]);
		}
		pending->updates[direction] = tal_dup_arr(pending, u8, update, tal_count(update), 0);
		pending->update_timestamps[direction] = timestamp;
	}
}

static void set_connection_values(struct chan *chan,
				  int idx,
				  u32 base_fee,
				  u32 proportional_fee,
				  u32 delay,
				  u8 message_flags,
				  u8 channel_flags,
				  u32 timestamp,
				  struct amount_msat htlc_minimum,
				  struct amount_msat htlc_maximum)
{
	struct half_chan *c = &chan->half[idx];

	c->delay = delay;
	c->htlc_minimum = htlc_minimum;
	c->htlc_maximum = htlc_maximum;
	c->base_fee = base_fee;
	c->proportional_fee = proportional_fee;
	c->message_flags = message_flags;
	c->channel_flags = channel_flags;
	c->bcast.timestamp = timestamp;
	assert((c->channel_flags & ROUTING_FLAGS_DIRECTION) == idx);

	SUPERVERBOSE("Channel %s/%d was updated.",
		     type_to_string(tmpctx, struct short_channel_id, &chan->scid),
		     idx);
}

bool routing_add_channel_update(struct routing_state *rstate,
				const u8 *update TAKES,
				u32 index)
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

	/* Make sure we own msg, even if we don't save it. */
	if (taken(update))
		tal_steal(tmpctx, update);

	if (!fromwire_channel_update(update, &signature, &chain_hash,
				     &short_channel_id, &timestamp,
				     &message_flags, &channel_flags,
				     &expiry, &htlc_minimum, &fee_base_msat,
				     &fee_proportional_millionths))
		return false;
	/* If it's flagged as containing the optional field, reparse for
	 * the optional field */
	if ((message_flags & ROUTING_OPT_HTLC_MAX_MSAT) &&
			!fromwire_channel_update_option_channel_htlc_max(
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
	} else {
		/* Maybe announcement was waiting for this update? */
		uc = get_unupdated_channel(rstate, &short_channel_id);
		if (!uc) {
			return false;
		}
		sat = uc->sat;
	}

	if (message_flags & ROUTING_OPT_HTLC_MAX_MSAT) {
		/* Reject update if the `htlc_maximum_msat` is greater
		 * than the total available channel satoshis */
		if (amount_msat_greater_sat(htlc_maximum, sat))
			return false;
	} else {
		/* If not indicated, set htlc_max_msat to channel capacity */
		if (!amount_sat_to_msat(&htlc_maximum, sat)) {
			status_broken("Channel capacity %s overflows!",
				      type_to_string(tmpctx, struct amount_sat,
						     &sat));
			return false;
		}
	}

	/* OK, we're going to accept this, so create chan if doesn't exist */
	if (uc) {
		assert(!chan);
		chan = new_chan(rstate, &short_channel_id,
				&uc->id[0], &uc->id[1], sat);
	}

	/* Discard older updates */
	hc = &chan->half[direction];

	/* If we're loading from store, duplicate entries are a bug. */
	if (is_halfchan_defined(hc) && index != 0) {
		status_broken("gossip_store channel_update %u replaces %u!",
			      index, hc->bcast.index);
		return false;
	}

	if (is_halfchan_defined(hc) && timestamp <= hc->bcast.timestamp) {
		SUPERVERBOSE("Ignoring outdated update.");
		/* Ignoring != failing */
		return true;
	}

	/* FIXME: https://github.com/lightningnetwork/lightning-rfc/pull/512
	 * says we MUST NOT exceed 2^32-1, but c-lightning did, so just trim
	 * rather than rejecting. */
	if (amount_msat_greater(htlc_maximum, rstate->chainparams->max_payment))
		htlc_maximum = rstate->chainparams->max_payment;

	set_connection_values(chan, direction, fee_base_msat,
			      fee_proportional_millionths, expiry,
			      message_flags, channel_flags,
			      timestamp, htlc_minimum, htlc_maximum);

	/* Safe even if was never added, but if it's a private channel it
	 * would be a WIRE_GOSSIP_STORE_PRIVATE_UPDATE. */
	gossip_store_delete(rstate->gs, &hc->bcast,
			    is_chan_public(chan)
			    ? WIRE_CHANNEL_UPDATE
			    : WIRE_GOSSIP_STORE_PRIVATE_UPDATE);

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
	} else if (!is_chan_public(chan)) {
		/* For private channels, we get updates without an announce: don't
		 * broadcast them!  But save local ones to store anyway. */
		assert(is_local_channel(rstate, chan));
		/* Don't save if we're loading from store */
		if (!index) {
			hc->bcast.index
				= gossip_store_add_private_update(rstate->gs,
								  update);
		} else
			hc->bcast.index = index;
		return true;
	}

	/* If we're loading from store, this means we don't re-add to store. */
	if (index)
		hc->bcast.index = index;
	else
		hc->bcast.index
			= gossip_store_add(rstate->gs, update,
					   hc->bcast.timestamp,
					   NULL);

	if (uc) {
		/* If we were waiting for these nodes to appear (or gain a
		   public channel), process node_announcements now */
		process_pending_node_announcement(rstate, &chan->nodes[0]->id);
		process_pending_node_announcement(rstate, &chan->nodes[1]->id);
		tal_free(uc);
	}
	return true;
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

void remove_channel_from_store(struct routing_state *rstate,
			       struct chan *chan)
{
	int update_type, announcment_type;

	if (is_chan_public(chan)) {
		update_type = WIRE_CHANNEL_UPDATE;
		announcment_type = WIRE_CHANNEL_ANNOUNCEMENT;
	} else {
		update_type = WIRE_GOSSIP_STORE_PRIVATE_UPDATE;
		announcment_type = WIRE_GOSSIPD_LOCAL_ADD_CHANNEL;
	}

	/* If these aren't in the store, these are noops. */
	gossip_store_delete(rstate->gs,
			    &chan->bcast, announcment_type);
	gossip_store_delete(rstate->gs,
			    &chan->half[0].bcast, update_type);
	gossip_store_delete(rstate->gs,
			    &chan->half[1].bcast, update_type);
}

u8 *handle_channel_update(struct routing_state *rstate, const u8 *update TAKES,
			  const char *source,
			  struct short_channel_id *unknown_scid)
{
	u8 *serialized;
	const struct node_id *owner;
	secp256k1_ecdsa_signature signature;
	struct short_channel_id short_channel_id;
	u32 timestamp;
	u8 message_flags, channel_flags;
	u16 expiry;
	struct amount_msat htlc_minimum;
	u32 fee_base_msat;
	u32 fee_proportional_millionths;
	struct bitcoin_blkid chain_hash;
	u8 direction;
	size_t len = tal_count(update);
	struct pending_cannouncement *pending;
	u8 *err;

	serialized = tal_dup_arr(tmpctx, u8, update, len, 0);
	if (!fromwire_channel_update(serialized, &signature,
				     &chain_hash, &short_channel_id,
				     &timestamp, &message_flags,
				     &channel_flags, &expiry,
				     &htlc_minimum, &fee_base_msat,
				     &fee_proportional_millionths)) {
		err = towire_errorfmt(rstate, NULL,
				      "Malformed channel_update %s",
				      tal_hex(tmpctx, serialized));
		return err;
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
	if (!bitcoin_blkid_eq(&chain_hash,
			      &rstate->chainparams->genesis_blockhash)) {
		status_trace("Received channel_update for unknown chain %s",
			     type_to_string(tmpctx, struct bitcoin_blkid,
					    &chain_hash));
		return NULL;
	}

	/* If we dropped the matching announcement for this channel due to the
	 * txout query failing, don't report failure, it's just too noisy on
	 * mainnet */
	if (uintmap_get(&rstate->txout_failures, short_channel_id.u64))
		return NULL;

	/* If we have an unvalidated channel, just queue on that */
	pending = find_pending_cannouncement(rstate, &short_channel_id);
	if (pending) {
		status_trace("Updated pending announce with update %s/%u",
			     type_to_string(tmpctx,
					    struct short_channel_id,
					    &short_channel_id),
			     direction);
		update_pending(pending, timestamp, serialized, direction);
		return NULL;
	}

	owner = get_channel_owner(rstate, &short_channel_id, direction);
	if (!owner) {
		if (unknown_scid)
			*unknown_scid = short_channel_id;
		bad_gossip_order(serialized,
				 source,
				 tal_fmt(tmpctx, "%s/%u",
					 type_to_string(tmpctx,
							struct short_channel_id,
							&short_channel_id),
					 direction));
		return NULL;
	}

	err = check_channel_update(rstate, owner, &signature, serialized);
	if (err) {
		/* BOLT #7:
		 *
		 * - if `signature` is not a valid signature, using `node_id`
		 *  of the double-SHA256 of the entire message following the
		 *  `signature` field (including unknown fields following
		 *  `fee_proportional_millionths`):
		 *    - MUST NOT process the message further.
		 *    - SHOULD fail the connection.
		 */
		return err;
	}

	status_trace("Received channel_update for channel %s/%d now %s (from %s)",
		     type_to_string(tmpctx, struct short_channel_id,
				    &short_channel_id),
		     channel_flags & 0x01,
		     channel_flags & ROUTING_FLAGS_DISABLED ? "DISABLED" : "ACTIVE",
		     source);

	if (!routing_add_channel_update(rstate, serialized, 0))
		status_failed(STATUS_FAIL_INTERNAL_ERROR,
			      "Failed adding channel_update");

	return NULL;
}

struct wireaddr *read_addresses(const tal_t *ctx, const u8 *ser)
{
	const u8 *cursor = ser;
	size_t len = tal_count(ser);
	struct wireaddr *wireaddrs = tal_arr(ctx, struct wireaddr, 0);

	while (cursor && len) {
		struct wireaddr wireaddr;

		/* BOLT #7:
		 *
		 * The receiving node:
		 *...
		 *   - SHOULD ignore the first `address descriptor` that does
		 *     NOT match the types defined above.
		 */
		if (!fromwire_wireaddr(&cursor, &len, &wireaddr)) {
			if (!cursor)
				/* Parsing address failed */
				return tal_free(wireaddrs);
			/* Unknown type, stop there. */
			status_trace("read_addresses: unknown address type %u",
				     cursor[0]);
			break;
		}

		tal_arr_expand(&wireaddrs, wireaddr);
	}
	return wireaddrs;
}

bool routing_add_node_announcement(struct routing_state *rstate,
				   const u8 *msg TAKES,
				   u32 index)
{
	struct node *node;
	secp256k1_ecdsa_signature signature;
	u32 timestamp;
	struct node_id node_id;
	u8 rgb_color[3];
	u8 alias[32];
	u8 *features, *addresses;

	/* Make sure we own msg, even if we don't save it. */
	if (taken(msg))
		tal_steal(tmpctx, msg);

	/* Note: validity of node_id is already checked. */
	if (!fromwire_node_announcement(tmpctx, msg,
					&signature, &features, &timestamp,
					&node_id, rgb_color, alias,
					&addresses)) {
		return false;
	}

	/* Only log this if *not* loading from store. */
	if (!index)
		status_trace("Received node_announcement for node %s",
			     type_to_string(tmpctx, struct node_id, &node_id));

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
			bad_gossip_order(msg, "node_announcement",
					 type_to_string(tmpctx, struct node_id,
							&node_id));
			return false;
		} else if (timestamp <= pna->timestamp)
			/* Ignore old ones: they're OK (unless from store). */
			return index == 0;

		SUPERVERBOSE("Deferring node_announcement for node %s",
			     type_to_string(tmpctx, struct node_id, &node_id));
		pna->timestamp = timestamp;
		pna->index = index;
		tal_free(pna->node_announcement);
		pna->node_announcement = tal_dup_arr(pna, u8, msg,
						     tal_count(msg),
						     0);
		return true;
	}

	if (node->bcast.index && index != 0) {
		status_broken("gossip_store node_announcement %u replaces %u!",
			      index, node->bcast.index);
		return false;
	}
	if (node->bcast.index && node->bcast.timestamp >= timestamp) {
		SUPERVERBOSE("Ignoring node announcement, it's outdated.");
		/* OK unless we're loading from store */
		return index == 0;
	}

	/* Harmless if it was never added */
	gossip_store_delete(rstate->gs,
			    &node->bcast,
			    WIRE_NODE_ANNOUNCEMENT);

	node->bcast.timestamp = timestamp;
	if (index)
		node->bcast.index = index;
	else
		node->bcast.index
			= gossip_store_add(rstate->gs, msg,
					   node->bcast.timestamp, NULL);
	return true;
}

u8 *handle_node_announcement(struct routing_state *rstate, const u8 *node_ann)
{
	u8 *serialized;
	struct sha256_double hash;
	secp256k1_ecdsa_signature signature;
	u32 timestamp;
	struct node_id node_id;
	u8 rgb_color[3];
	u8 alias[32];
	u8 *features, *addresses;
	struct wireaddr *wireaddrs;
	size_t len = tal_count(node_ann);

	serialized = tal_dup_arr(tmpctx, u8, node_ann, len, 0);
	if (!fromwire_node_announcement(tmpctx, serialized,
					&signature, &features, &timestamp,
					&node_id, rgb_color, alias,
					&addresses)) {
		/* BOLT #7:
		 *
		 *   - if `node_id` is NOT a valid compressed public key:
		 *    - SHOULD fail the connection.
		 *    - MUST NOT process the message further.
		 */
		u8 *err = towire_errorfmt(rstate, NULL,
					  "Malformed node_announcement %s",
					  tal_hex(tmpctx, node_ann));
		return err;
	}

	/* BOLT #7:
	 *
	 * The receiving node:
	 *...
	 *  - if `features` field contains _unknown even bits_:
	 *    - MUST NOT parse the remainder of the message.
	 *    - MAY discard the message altogether.
	 *    - SHOULD NOT connect to the node.
	 */
	if (!features_supported(features, NULL)) {
		status_trace("Ignoring node announcement for node %s, unsupported features %s.",
			     type_to_string(tmpctx, struct node_id, &node_id),
			     tal_hex(tmpctx, features));
		return NULL;
	}

	sha256_double(&hash, serialized + 66, tal_count(serialized) - 66);
	/* If node_id is invalid, it fails here */
	if (!check_signed_hash_nodeid(&hash, &signature, &node_id)) {
		/* BOLT #7:
		 *
		 * - if `signature` is not a valid signature, using
                 *   `node_id` of the double-SHA256 of the entire
                 *   message following the `signature` field
                 *   (including unknown fields following
                 *   `fee_proportional_millionths`):
		 *    - MUST NOT process the message further.
		 *    - SHOULD fail the connection.
		 */
		u8 *err = towire_errorfmt(rstate, NULL,
					  "Bad signature for %s hash %s"
					  " on node_announcement %s",
					  type_to_string(tmpctx,
							 secp256k1_ecdsa_signature,
							 &signature),
					  type_to_string(tmpctx,
							 struct sha256_double,
							 &hash),
					  tal_hex(tmpctx, node_ann));
		return err;
	}

	wireaddrs = read_addresses(tmpctx, addresses);
	if (!wireaddrs) {
		/* BOLT #7:
		 *
		 * - if `addrlen` is insufficient to hold the address
		 *  descriptors of the known types:
		 *    - SHOULD fail the connection.
		 */
		u8 *err = towire_errorfmt(rstate, NULL,
					  "Malformed wireaddrs %s in %s.",
					  tal_hex(tmpctx, wireaddrs),
					  tal_hex(tmpctx, node_ann));
		return err;
	}

	/* May still fail, if we don't know the node. */
	routing_add_node_announcement(rstate, serialized, 0);
	return NULL;
}

struct route_hop *get_route(const tal_t *ctx, struct routing_state *rstate,
			    const struct node_id *source,
			    const struct node_id *destination,
			    struct amount_msat msat, double riskfactor,
			    u32 final_cltv,
			    double fuzz, u64 seed,
			    const struct short_channel_id_dir *excluded,
			    size_t max_hops)
{
	struct chan **route;
	struct amount_msat fee;
	struct route_hop *hops;
	struct node *n;
	struct exclusion_memento *exes;
	struct siphash_seed base_seed;
	char *err;

	base_seed.u.u64[0] = base_seed.u.u64[1] = seed;

	if (amount_msat_eq(msat, AMOUNT_MSAT(0)))
		return NULL;

	/* Apply eclusions.  */
	exes = exclude_channels(rstate, excluded);

	route = find_route(ctx, rstate, source, destination, msat,
			   riskfactor / BLOCKS_PER_YEAR / 100,
			   fuzz, &base_seed, max_hops, &fee);

	/* Remove applied exclusions.  */
	restore_excluded_channels(exes);

	if (!route) {
		return NULL;
	}

	/* Generate the route.  */
	err = generate_route_hops(ctx,
				  &hops, &n,
				  route, get_node(rstate, destination),
				  msat, final_cltv);
	if (err) {
		status_broken("%s", err);
		return NULL;
	}
	assert(node_id_eq(&n->id, source ? source : &rstate->local_id));

	return hops;
}

char *generate_route_hops(const tal_t *ctx,
			  /* outputs.  */
			  struct route_hop **hops,
			  struct node **source,
			  /* inputs.  */
			  struct chan **chans,
			  struct node *destination,
			  struct amount_msat final_msat,
			  u32 final_cltv)
{
	struct amount_msat total_amount;
	u32 total_delay;
	struct node *n;

	*hops = tal_arr(ctx, struct route_hop, tal_count(chans));
	total_amount = final_msat;
	total_delay = final_cltv;

	/* Start at destination node. */
	n = destination;
	for (int i = tal_count(chans) - 1; i >= 0; --i) {
		const struct half_chan *c;

		int idx = half_chan_to(n, chans[i]);
		c = &chans[i]->half[idx];
		(*hops)[i].channel_id = chans[i]->scid;
		(*hops)[i].nodeid = n->id;
		(*hops)[i].amount = total_amount;
		(*hops)[i].delay = total_delay;
		(*hops)[i].direction = idx;

		/* Since we calculated this route, it should not overflow! */
		if (!amount_msat_add_fee(&total_amount,
					 c->base_fee, c->proportional_fee)) {
			/* Clear outputs.  */
			*hops = tal_free(*hops);
			*source = NULL;
			/* Return error message.  */
			return tal_fmt(ctx,
				       "Route overflow step %i: %s + %u/%u!?",
				       i, type_to_string(tmpctx, struct amount_msat,
							 &total_amount),
				       c->base_fee, c->proportional_fee);
		}

		/* FIXME: Handle overflow of total delay. */
		total_delay += c->delay;
		n = other_node(n, chans[i]);
	}
	/* Update. */
	*source = n;

	/* Succeeded.  */
	return NULL;
}

void routing_failure(struct routing_state *rstate,
		     const struct node_id *erring_node_id,
		     const struct short_channel_id *scid,
		     int erring_direction,
		     enum onion_type failcode,
		     const u8 *channel_update)
{
	struct chan **pruned = tal_arr(tmpctx, struct chan *, 0);

	status_trace("Received routing failure 0x%04x (%s), "
		     "erring node %s, "
		     "channel %s/%u",
		     (int) failcode, onion_type_name(failcode),
		     type_to_string(tmpctx, struct node_id, erring_node_id),
		     type_to_string(tmpctx, struct short_channel_id, scid),
		     erring_direction);

	/* lightningd will only extract this if UPDATE is set. */
	if (channel_update) {
		u8 *err = handle_channel_update(rstate, channel_update, "error",
						NULL);
		if (err) {
			status_unusual("routing_failure: "
				       "bad channel_update %s",
				       sanitize_error(err, err, NULL));
			tal_free(err);
		}
	} else if (failcode & UPDATE) {
		status_unusual("routing_failure: "
			       "UPDATE bit set, no channel_update. "
			       "failcode: 0x%04x",
			       (int) failcode);
	}

	/* We respond to permanent errors, ignore the rest: they're
	 * for the pay command to worry about.  */
	if (!(failcode & PERM))
		return;

	if (failcode & NODE) {
		struct node *node = get_node(rstate, erring_node_id);
		if (!node) {
			status_unusual("routing_failure: Erring node %s not in map",
				       type_to_string(tmpctx, struct node_id,
						      erring_node_id));
		} else {
			struct chan_map_iter i;
			struct chan *c;

			status_trace("Deleting node %s",
				     type_to_string(tmpctx,
						    struct node_id,
						    &node->id));
			for (c = first_chan(node, &i); c; c = next_chan(node, &i)) {
				/* Set it up to be pruned. */
				tal_arr_expand(&pruned, c);
			}
		}
	} else {
		struct chan *chan = get_channel(rstate, scid);

		if (!chan)
			status_unusual("routing_failure: "
				       "Channel %s unknown",
				       type_to_string(tmpctx,
						      struct short_channel_id,
						      scid));
		else {
			/* This error can be triggered by sendpay if caller
			 * uses the wrong key for dest. */
			if (failcode == WIRE_INVALID_ONION_HMAC
			    && !node_id_eq(&chan->nodes[!erring_direction]->id,
					   erring_node_id))
				return;

			status_trace("Deleting channel %s",
				     type_to_string(tmpctx,
						    struct short_channel_id,
						    scid));
			/* Set it up to be deleted. */
			tal_arr_expand(&pruned, chan);
		}
	}

	/* Now free all the chans and maybe even nodes. */
	for (size_t i = 0; i < tal_count(pruned); i++)
		free_chan(rstate, pruned[i]);
}


void route_prune(struct routing_state *rstate)
{
	u64 now = gossip_time_now(rstate).ts.tv_sec;
	/* Anything below this highwater mark ought to be pruned */
	const s64 highwater = now - rstate->prune_timeout;
	struct chan **pruned = tal_arr(tmpctx, struct chan *, 0);
	u64 idx;

	/* Now iterate through all channels and see if it is still alive */
	for (struct chan *chan = uintmap_first(&rstate->chanmap, &idx);
	     chan;
	     chan = uintmap_after(&rstate->chanmap, &idx)) {
		/* Local-only?  Don't prune. */
		if (!is_chan_public(chan))
			continue;

		if ((!is_halfchan_defined(&chan->half[0])
		     || chan->half[0].bcast.timestamp < highwater)
		    && (!is_halfchan_defined(&chan->half[1])
			|| chan->half[1].bcast.timestamp < highwater)) {
			status_trace(
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

#if DEVELOPER
void memleak_remove_routing_tables(struct htable *memtable,
				   const struct routing_state *rstate)
{
	struct node *n;
	struct node_map_iter nit;

	memleak_remove_htable(memtable, &rstate->nodes->raw);
	memleak_remove_htable(memtable, &rstate->pending_node_map->raw);
	memleak_remove_htable(memtable, &rstate->pending_cannouncements.raw);

	for (n = node_map_first(rstate->nodes, &nit);
	     n;
	     n = node_map_next(rstate->nodes, &nit)) {
		if (node_uses_chan_map(n))
			memleak_remove_htable(memtable, &n->chans.map.raw);
	}
}
#endif /* DEVELOPER */

bool handle_local_add_channel(struct routing_state *rstate,
			      const u8 *msg, u64 index)
{
	struct short_channel_id scid;
	struct node_id remote_node_id;
	struct amount_sat sat;
	struct chan *chan;

	if (!fromwire_gossipd_local_add_channel(msg, &scid, &remote_node_id,
						&sat)) {
		status_broken("Unable to parse local_add_channel message: %s",
			      tal_hex(msg, msg));
		return false;
	}

	/* Can happen on channeld restart. */
	if (get_channel(rstate, &scid)) {
		status_trace("Attempted to local_add_channel a known channel");
		return true;
	}

	status_trace("local_add_channel %s",
		     type_to_string(tmpctx, struct short_channel_id, &scid));

	/* Create new (unannounced) channel */
	chan = new_chan(rstate, &scid, &rstate->local_id, &remote_node_id, sat);
	if (!index)
		index = gossip_store_add(rstate->gs, msg, 0, NULL);
	chan->bcast.index = index;
	return true;
}

struct timeabs gossip_time_now(const struct routing_state *rstate)
{
#if DEVELOPER
	if (rstate->gossip_time)
		return *rstate->gossip_time;
#endif
	return time_now();
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
		if (node_uses_chan_map(n))
			chan_map_clear(&n->chans.map);
		node_map_del(rstate->nodes, n);
		tal_free(n);
	}

	/* Now free all the channels. */
	while ((c = uintmap_first(&rstate->chanmap, &index)) != NULL) {
		uintmap_del(&rstate->chanmap, index);

		/* Remove from local_disabled_map if it's there. */
		chan_map_del(&rstate->local_disabled_map, c);
		tal_free(c);
	}

	while ((uc = uintmap_first(&rstate->unupdated_chanmap, &index)) != NULL)
		tal_free(uc);

	while ((pca = pending_cannouncement_map_first(&rstate->pending_cannouncements, &pit)) != NULL)
		tal_free(pca);

	/* Freeing unupdated chanmaps should empty this */
	assert(pending_node_map_first(rstate->pending_node_map, &pnait) == NULL);
}

struct exclusion_memento {
	struct routing_state *rstate;
	const struct short_channel_id_dir *excluded;
	struct amount_msat *saved_capacity;
};

struct exclusion_memento *
exclude_channels(struct routing_state *rstate,
		 const struct short_channel_id_dir *excluded TAKES)
{
	struct exclusion_memento *memento;
	struct amount_msat *saved_capacity;

	u32 len = tal_count(excluded);

	/* Construct the memento object. */
	memento = tal(rstate, struct exclusion_memento);
	memento->rstate = rstate;
	memento->excluded = tal_dup_arr(memento,
					const struct short_channel_id_dir,
					excluded,
					len, 0);
	memento->saved_capacity = tal_arr(memento,
					  struct amount_msat, len);

	/* Temporarily set excluded channels' capacity to zero.
	 * Save the capacity to the array in the memento. */
	saved_capacity = memento->saved_capacity;
	for (size_t i = 0; i < len; i++) {
		struct chan *chan = get_channel(rstate, &excluded[i].scid);
		if (!chan)
			continue;
		saved_capacity[i] = chan->half[excluded[i].dir].htlc_maximum;
		chan->half[excluded[i].dir].htlc_maximum = AMOUNT_MSAT(0);
	}

	return memento;
}

void restore_excluded_channels(struct exclusion_memento *memento)
{
	struct routing_state *rstate = memento->rstate;
	const struct short_channel_id_dir *excluded = memento->excluded;
	struct amount_msat *saved_capacity = memento->saved_capacity;

	/* Now restore the capacity. */
	/* Restoring is done in reverse order, in order to properly
	 * handle the case where a channel is indicated twice in
	 * our input.
	 * Entries in `saved_capacity` of that channel beyond the
	 * first entry will be 0, only the first entry of that
	 * channel will be the correct capacity.
	 * By restoring in reverse order we ensure we can restore
	 * the correct capacity.
	 */
	for (ssize_t i = tal_count(excluded) - 1; i >= 0; i--) {
		struct chan *chan = get_channel(rstate, &excluded[i].scid);
		if (!chan)
			continue;
		chan->half[excluded[i].dir].htlc_maximum = saved_capacity[i];
	}

	/* Destroy the memento. */
	tal_free(memento);
}
