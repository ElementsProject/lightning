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
#include <gossipd/gen_gossip_wire.h>
#include <inttypes.h>
#include <wire/gen_peer_wire.h>

#ifndef SUPERVERBOSE
#define SUPERVERBOSE(...)
#endif

/* 365.25 * 24 * 60 / 10 */
#define BLOCKS_PER_YEAR 52596

/* We've unpacked and checked its signatures, now we wait for master to tell
 * us the txout to check */
struct pending_cannouncement {
	/* Off routing_state->pending_cannouncement */
	struct list_node list;

	/* Unpacked fields here */
	struct short_channel_id short_channel_id;
	struct pubkey node_id_1;
	struct pubkey node_id_2;
	struct pubkey bitcoin_key_1;
	struct pubkey bitcoin_key_2;

	/* The raw bits */
	const u8 *announce;

	/* Deferred updates, if we received them while waiting for
	 * this (one for each direction) */
	const u8 *updates[2];

	/* Only ever replace with newer updates */
	u32 update_timestamps[2];
};

struct pending_node_announce {
	struct pubkey nodeid;
	u8 *node_announcement;
	u32 timestamp;
};

static const struct pubkey *
pending_node_announce_keyof(const struct pending_node_announce *a)
{
	return &a->nodeid;
}

static bool pending_node_announce_eq(const struct pending_node_announce *pna,
				     const struct pubkey *key)
{
	return pubkey_eq(&pna->nodeid, key);
}

HTABLE_DEFINE_TYPE(struct pending_node_announce, pending_node_announce_keyof,
		   node_map_hash_key, pending_node_announce_eq,
		   pending_node_map);

static struct node_map *empty_node_map(const tal_t *ctx)
{
	struct node_map *map = tal(ctx, struct node_map);
	node_map_init(map);
	tal_add_destructor(map, node_map_clear);
	return map;
}

struct routing_state *new_routing_state(const tal_t *ctx,
					const struct chainparams *chainparams,
					const struct pubkey *local_id,
					u32 prune_timeout)
{
	struct routing_state *rstate = tal(ctx, struct routing_state);
	rstate->nodes = empty_node_map(rstate);
	rstate->broadcasts = new_broadcast_state(rstate);
	rstate->chainparams = chainparams;
	rstate->local_id = *local_id;
	rstate->prune_timeout = prune_timeout;
	rstate->store = gossip_store_new(rstate, rstate, rstate->broadcasts);
	rstate->local_channel_announced = false;
	list_head_init(&rstate->pending_cannouncement);
	uintmap_init(&rstate->chanmap);

	rstate->pending_node_map = tal(ctx, struct pending_node_map);
	pending_node_map_init(rstate->pending_node_map);

	return rstate;
}


const struct pubkey *node_map_keyof_node(const struct node *n)
{
	return &n->id;
}

size_t node_map_hash_key(const struct pubkey *key)
{
	return siphash24(siphash_seed(), key, sizeof(*key));
}

bool node_map_node_eq(const struct node *n, const struct pubkey *key)
{
	return pubkey_eq(&n->id, key);
}

static void destroy_node(struct node *node, struct routing_state *rstate)
{
	node_map_del(rstate->nodes, node);

	/* These remove themselves from the array. */
	while (tal_count(node->chans))
		tal_free(node->chans[0]);
}

struct node *get_node(struct routing_state *rstate, const struct pubkey *id)
{
	return node_map_get(rstate->nodes, id);
}

static struct node *new_node(struct routing_state *rstate,
			     const struct pubkey *id)
{
	struct node *n;

	assert(!get_node(rstate, id));

	n = tal(rstate, struct node);
	n->id = *id;
	n->chans = tal_arr(n, struct chan *, 0);
	n->globalfeatures = NULL;
	n->node_announcement = NULL;
	n->node_announcement_index = 0;
	n->last_timestamp = -1;
	n->addresses = tal_arr(n, struct wireaddr, 0);
	node_map_add(rstate->nodes, n);
	tal_add_destructor2(n, destroy_node, rstate);

	return n;
}

/* We've received a channel_announce for a channel attached to this node */
static bool node_has_public_channels(struct node *node)
{
	for (size_t i = 0; i < tal_count(node->chans); i++)
		if (is_chan_public(node->chans[i]))
			return true;
	return false;
}

/* We can *send* a channel_announce for a channel attached to this node:
 * we only send once we have a channel_update. */
static bool node_has_broadcastable_channels(struct node *node)
{
	for (size_t i = 0; i < tal_count(node->chans); i++) {
		if (!is_chan_public(node->chans[i]))
			continue;
		if (is_halfchan_defined(&node->chans[i]->half[0])
		    || is_halfchan_defined(&node->chans[i]->half[1]))
			return true;
	}
	return false;
}

static bool remove_channel_from_array(struct chan ***chans, const struct chan *c)
{
	size_t i, n;

	n = tal_count(*chans);
	for (i = 0; i < n; i++) {
		if ((*chans)[i] != c)
			continue;
		n--;
		memmove(*chans + i, *chans + i + 1, sizeof(**chans) * (n - i));
		tal_resize(chans, n);
		return true;
	}
	return false;
}

static bool node_announce_predates_channels(const struct node *node)
{
	for (size_t i = 0; i < tal_count(node->chans); i++) {
		if (!is_chan_announced(node->chans[i]))
			continue;

		if (node->chans[i]->channel_announcement_index
		    < node->node_announcement_index)
			return false;
	}
	return true;
}

static u64 persistent_broadcast(struct routing_state *rstate, const u8 *msg, u32 timestamp)
{
	u64 index = insert_broadcast(rstate->broadcasts, msg, timestamp);
	if (index)
		gossip_store_add(rstate->store, msg);
	return index;
}

static void remove_chan_from_node(struct routing_state *rstate,
				  struct node *node, const struct chan *chan)
{
	if (!remove_channel_from_array(&node->chans, chan))
		abort();

	/* Last channel?  Simply delete node (and associated announce) */
	if (tal_count(node->chans) == 0) {
		tal_free(node);
		return;
	}

	if (!node->node_announcement_index)
		return;

	/* Removed only public channel?  Remove node announcement. */
	if (!node_has_broadcastable_channels(node)) {
		broadcast_del(rstate->broadcasts, node->node_announcement_index,
			      node->node_announcement);
		node->node_announcement_index = 0;
	} else if (node_announce_predates_channels(node)) {
		/* node announcement predates all channel announcements?
		 * Move to end (we could, in theory, move to just past next
		 * channel_announce, but we don't care that much about spurious
		 * retransmissions in this corner case */
		broadcast_del(rstate->broadcasts, node->node_announcement_index,
			      node->node_announcement);
		node->node_announcement_index = persistent_broadcast(
		    rstate, node->node_announcement, node->last_timestamp);
	}
}

static void destroy_chan(struct chan *chan, struct routing_state *rstate)
{
	remove_chan_from_node(rstate, chan->nodes[0], chan);
	remove_chan_from_node(rstate, chan->nodes[1], chan);

	uintmap_del(&rstate->chanmap, chan->scid.u64);
}

static void init_half_chan(struct routing_state *rstate,
				 struct chan *chan,
				 int channel_idx)
{
	struct half_chan *c = &chan->half[channel_idx];

	c->channel_update = NULL;

	/* Set the channel direction */
	c->channel_flags = channel_idx;
	// TODO: wireup message_flags
	c->message_flags = 0;
	/* We haven't seen channel_update: make it halfway to prune time,
	 * which should be older than any update we'd see. */
	c->last_timestamp = time_now().ts.tv_sec - rstate->prune_timeout/2;
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
		      const struct pubkey *id1,
		      const struct pubkey *id2,
		      struct amount_sat satoshis)
{
	struct chan *chan = tal(rstate, struct chan);
	int n1idx = pubkey_idx(id1, id2);
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
	chan->txout_script = NULL;
	chan->channel_announce = NULL;
	chan->channel_announcement_index = 0;
	chan->sat = satoshis;
	chan->local_disabled = false;

	tal_arr_expand(&n2->chans, chan);
	tal_arr_expand(&n1->chans, chan);

	/* Populate with (inactive) connections */
	init_half_chan(rstate, chan, n1idx);
	init_half_chan(rstate, chan, !n1idx);

	uintmap_add(&rstate->chanmap, scid->u64, chan);

	tal_add_destructor2(chan, destroy_chan, rstate);
	return chan;
}

/* Too big to reach, but don't overflow if added. */
#define INFINITE AMOUNT_MSAT(0x3FFFFFFFFFFFFFFFULL)

static void clear_bfg(struct node_map *nodes)
{
	struct node *n;
	struct node_map_iter it;

	for (n = node_map_first(nodes, &it); n; n = node_map_next(nodes, &it)) {
		size_t i;
		for (i = 0; i < ARRAY_SIZE(n->bfg); i++) {
			n->bfg[i].total = INFINITE;
			n->bfg[i].risk = AMOUNT_MSAT(0);
		}
	}
}

/* Risk of passing through this channel.  We insert a tiny constant here
 * in order to prefer shorter routes, all things equal. */
static WARN_UNUSED_RESULT bool risk_add_fee(struct amount_msat *risk,
					    struct amount_msat msat,
					    u32 delay, double riskfactor)
{
	double r;

	/* Won't overflow on add, just lose precision */
	r = 1.0 + riskfactor * delay * msat.millisatoshis + risk->millisatoshis; /* Raw: to double */
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
static bool fuzz_fee(u64 *fee, double fee_scale)
{
	u64 fuzzed_fee = *fee * fee_scale;
	if (fee_scale > 1.0 && fuzzed_fee < *fee)
		return false;
	*fee = fuzzed_fee;
	return true;
}

/* We track totals, rather than costs.  That's because the fee depends
 * on the current amount passing through. */
static void bfg_one_edge(struct node *node,
			 struct chan *chan, int idx,
			 double riskfactor,
			 double fuzz, const struct siphash_seed *base_seed,
			 size_t max_hops)
{
	size_t h;
	double fee_scale = 1.0;
	const struct half_chan *c = &chan->half[idx];

	if (fuzz != 0.0) {
		u64 h =	siphash24(base_seed, &chan->scid, sizeof(chan->scid));

		/* Scale fees for this channel */
		/* rand = (h / UINT64_MAX)  random number between 0.0 -> 1.0
		 * 2*fuzz*rand              random number between 0.0 -> 2*fuzz
		 * 2*fuzz*rand - fuzz       random number between -fuzz -> +fuzz
		 */
		fee_scale = 1.0 + (2.0 * fuzz * h / UINT64_MAX) - fuzz;
	}

	for (h = 0; h < max_hops; h++) {
		struct node *src;
		/* FIXME: Bias against smaller channels. */
		struct amount_msat fee, risk, requiredcap,
			this_total, curr_total;

		if (!amount_msat_fee(&fee, node->bfg[h].total,
				     c->base_fee, c->proportional_fee))
			continue;

		if (!fuzz_fee(&fee.millisatoshis, fee_scale)) /* Raw: double manipulation */
			continue;

		if (!amount_msat_add(&requiredcap, node->bfg[h].total, fee))
			continue;

		risk = node->bfg[h].risk;
		if (!risk_add_fee(&risk, requiredcap, c->delay, riskfactor))
			continue;

		if (!hc_can_carry(c, requiredcap)) {
			/* Skip a channel if it indicated that it won't route
			 * the requested amount. */
			continue;
		}

		if (!amount_msat_add(&this_total, requiredcap, risk))
			continue;

		/* nodes[0] is src for connections[0] */
		src = chan->nodes[idx];

		if (!amount_msat_add(&curr_total,
				     src->bfg[h + 1].total,
				     src->bfg[h + 1].risk)) {
			/* We just calculated this: shouldn't happen! */
			status_broken("Overflow: total %s + risk %s",
				      type_to_string(tmpctx, struct amount_msat,
						     &src->bfg[h + 1].total),
				      type_to_string(tmpctx, struct amount_msat,
						     &src->bfg[h + 1].risk));
			continue;
		}

		if (amount_msat_less(this_total, curr_total)) {
			SUPERVERBOSE("...%s can reach here hoplen %zu"
				     " total %s risk %s",
				     type_to_string(tmpctx, struct pubkey,
						    &src->id),
				     h,
				     type_to_string(tmpctx, struct amount_msat,
						    &requiredcap),
				     type_to_string(tmpctx, struct amount_msat,
						    &risk));
			src->bfg[h+1].total = requiredcap;
			src->bfg[h+1].risk = risk;
			src->bfg[h+1].prev = chan;
		}
	}
}

/* Determine if the given half_chan is routable */
static bool hc_is_routable(const struct chan *chan, int idx)
{
	return !chan->local_disabled
		&& is_halfchan_enabled(&chan->half[idx]);
}

/* riskfactor is already scaled to per-block amount */
static struct chan **
find_route(const tal_t *ctx, struct routing_state *rstate,
	   const struct pubkey *from, const struct pubkey *to,
	   struct amount_msat msat,
	   double riskfactor,
	   double fuzz, const struct siphash_seed *base_seed,
	   size_t max_hops,
	   struct amount_msat *fee)
{
	struct chan **route;
	struct node *n, *src, *dst;
	struct node_map_iter it;
	struct amount_msat best_total;
	int runs, i, best;

	/* Note: we map backwards, since we know the amount of satoshi we want
	 * at the end, and need to derive how much we need to send. */
	dst = get_node(rstate, from);
	src = get_node(rstate, to);

	if (!src) {
		status_info("find_route: cannot find %s",
			    type_to_string(tmpctx, struct pubkey, to));
		return NULL;
	} else if (!dst) {
		status_info("find_route: cannot find myself (%s)",
			    type_to_string(tmpctx, struct pubkey, to));
		return NULL;
	} else if (dst == src) {
		status_info("find_route: this is %s, refusing to create empty route",
			    type_to_string(tmpctx, struct pubkey, to));
		return NULL;
	}

	if (max_hops > ROUTING_MAX_HOPS) {
		status_info("find_route: max_hops huge amount %zu > %u",
			    max_hops, ROUTING_MAX_HOPS);
		return NULL;
	}

	/* Reset all the information. */
	clear_bfg(rstate->nodes);

	/* Bellman-Ford-Gibson: like Bellman-Ford, but keep values for
	 * every path length. */
	src->bfg[0].total = msat;
	src->bfg[0].risk = AMOUNT_MSAT(0);

	for (runs = 0; runs < max_hops; runs++) {
		SUPERVERBOSE("Run %i", runs);
		/* Run through every edge. */
		for (n = node_map_first(rstate->nodes, &it);
		     n;
		     n = node_map_next(rstate->nodes, &it)) {
			size_t num_edges = tal_count(n->chans);
			for (i = 0; i < num_edges; i++) {
				struct chan *chan = n->chans[i];
				int idx = half_chan_to(n, chan);

				SUPERVERBOSE("Node %s edge %i/%zu",
					     type_to_string(tmpctx, struct pubkey,
							    &n->id),
					     i, num_edges);

				if (!hc_is_routable(chan, idx)) {
					SUPERVERBOSE("...unroutable (local_disabled = %i, is_halfchan_enabled = %i, unroutable_until = %i",
						     chan->local_disabled,
						     is_halfchan_enabled(&chan->half[idx]),
						     chan->half[idx].unroutable_until >= now);
					continue;
				}
				bfg_one_edge(n, chan, idx,
					     riskfactor, fuzz, base_seed,
					     max_hops);
				SUPERVERBOSE("...done");
			}
		}
	}

	best = 0;
	best_total = INFINITE;
	for (i = 0; i <= max_hops; i++) {
		struct amount_msat total;
		status_trace("%i hop solution: %s + %s",
			     i,
			     type_to_string(tmpctx, struct amount_msat,
					    &dst->bfg[i].total),
			     type_to_string(tmpctx, struct amount_msat,
					    &dst->bfg[i].risk));
		if (!amount_msat_add(&total,
				     dst->bfg[i].total, dst->bfg[i].risk))
			continue;
		if (amount_msat_less(total, best_total)) {
			best = i;
			best_total = total;
		}
	}
	status_trace("=> chose %i hop solution", best);

	/* No route? */
	if (amount_msat_greater_eq(best_total, INFINITE)) {
		status_trace("find_route: No route to %s",
			     type_to_string(tmpctx, struct pubkey, to));
		return NULL;
	}

	/* We (dst) don't charge ourselves fees, so skip first hop */
	n = other_node(dst, dst->bfg[best].prev);
	if (!amount_msat_sub(fee, n->bfg[best-1].total, msat)) {
		status_broken("Could not subtract %s - %s for fee",
			      type_to_string(tmpctx, struct amount_msat,
					     &n->bfg[best-1].total),
			      type_to_string(tmpctx, struct amount_msat, &msat));
		return NULL;
	}

	/* Lay out route */
	route = tal_arr(ctx, struct chan *, best);
	for (i = 0, n = dst;
	     i < best;
	     n = other_node(n, n->bfg[best-i].prev), i++) {
		route[i] = n->bfg[best-i].prev;
	}
	assert(n == src);

	return route;
}

/* Verify the signature of a channel_update message */
static u8 *check_channel_update(const tal_t *ctx,
				const struct pubkey *node_key,
				const secp256k1_ecdsa_signature *node_sig,
				const u8 *update)
{
	/* 2 byte msg type + 64 byte signatures */
	int offset = 66;
	struct sha256_double hash;
	sha256_double(&hash, update + offset, tal_count(update) - offset);

	if (!check_signed_hash(&hash, node_sig, node_key))
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
	const struct pubkey *node1_key, const struct pubkey *node2_key,
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

	if (!check_signed_hash(&hash, node1_sig, node1_key)) {
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
	if (!check_signed_hash(&hash, node2_sig, node2_key)) {
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

static void add_pending_node_announcement(struct routing_state *rstate, struct pubkey *nodeid)
{
	struct pending_node_announce *pna = tal(rstate, struct pending_node_announce);
	pna->nodeid = *nodeid;
	pna->node_announcement = NULL;
	pna->timestamp = 0;
	pending_node_map_add(rstate->pending_node_map, pna);
}

static void process_pending_node_announcement(struct routing_state *rstate,
					      struct pubkey *nodeid)
{
	struct pending_node_announce *pna = pending_node_map_get(rstate->pending_node_map, nodeid);
	if (!pna)
		return;

	if (pna->node_announcement) {
		u8 *err;
		SUPERVERBOSE(
		    "Processing deferred node_announcement for node %s",
		    type_to_string(pna, struct pubkey, nodeid));

		/* Should not error, since we processed it before */
		err = handle_node_announcement(rstate, pna->node_announcement);
		if (err)
			status_failed(STATUS_FAIL_INTERNAL_ERROR,
				      "pending node_announcement %s malformed %s?",
				      tal_hex(tmpctx, pna->node_announcement),
				      sanitize_error(tmpctx, err, NULL));
	}
	pending_node_map_del(rstate->pending_node_map, pna);
	tal_free(pna);
}

static struct pending_cannouncement *
find_pending_cannouncement(struct routing_state *rstate,
			   const struct short_channel_id *scid)
{
	struct pending_cannouncement *i;

	list_for_each(&rstate->pending_cannouncement, i, list) {
		if (short_channel_id_eq(scid, &i->short_channel_id))
			return i;
	}
	return NULL;
}

static void destroy_pending_cannouncement(struct pending_cannouncement *pending,
					  struct routing_state *rstate)
{
	list_del_from(&rstate->pending_cannouncement, &pending->list);
}

static bool is_local_channel(const struct routing_state *rstate,
			     const struct chan *chan)
{
	return pubkey_eq(&chan->nodes[0]->id, &rstate->local_id)
		|| pubkey_eq(&chan->nodes[1]->id, &rstate->local_id);
}

static void add_channel_announce_to_broadcast(struct routing_state *rstate,
					      struct chan *chan,
					      u32 timestamp)
{
	chan->channel_announcement_index =
	    persistent_broadcast(rstate, chan->channel_announce, timestamp);
	rstate->local_channel_announced |= is_local_channel(rstate, chan);

	/* If we've been waiting for this, now we can announce node */
	for (size_t i = 0; i < ARRAY_SIZE(chan->nodes); i++) {
		struct node *node = chan->nodes[i];
		if (!node->node_announcement)
			continue;
		if (!node->node_announcement_index) {
			node->node_announcement_index = persistent_broadcast(
			    rstate, node->node_announcement,
			    node->last_timestamp);
		}
	}
}

bool routing_add_channel_announcement(struct routing_state *rstate,
				      const u8 *msg TAKES,
				      struct amount_sat sat)
{
	struct chan *chan;
	secp256k1_ecdsa_signature node_signature_1, node_signature_2;
	secp256k1_ecdsa_signature bitcoin_signature_1, bitcoin_signature_2;
	u8 *features;
	struct bitcoin_blkid chain_hash;
	struct short_channel_id scid;
	struct pubkey node_id_1;
	struct pubkey node_id_2;
	struct pubkey bitcoin_key_1;
	struct pubkey bitcoin_key_2;

	if (!fromwire_channel_announcement(
		    tmpctx, msg, &node_signature_1, &node_signature_2,
		    &bitcoin_signature_1, &bitcoin_signature_2, &features, &chain_hash,
		    &scid, &node_id_1, &node_id_2, &bitcoin_key_1, &bitcoin_key_2))
		return false;

	/* The channel may already exist if it was non-public from
	 * local_add_channel(); normally we don't accept new
	 * channel_announcements.  See handle_channel_announcement. */
	chan = get_channel(rstate, &scid);
	if (!chan)
		chan = new_chan(rstate, &scid, &node_id_1, &node_id_2, sat);

	/* Channel is now public. */
	chan->channel_announce = tal_dup_arr(chan, u8, msg, tal_count(msg), 0);

	/* Apply any private updates. */
	for (size_t i = 0; i < ARRAY_SIZE(chan->half); i++) {
		const u8 *update = chan->half[i].channel_update;
		if (!update)
			continue;

		/* Remove from channel, otherwise it will be freed! */
		chan->half[i].channel_update = NULL;
		routing_add_channel_update(rstate, take(update));
	}

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
	add_pending_node_announcement(rstate, &pending->node_id_1);
	add_pending_node_announcement(rstate, &pending->node_id_2);

	list_add_tail(&rstate->pending_cannouncement, &pending->list);
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
	err = handle_channel_update(rstate, cupdate, "pending update");
	if (err) {
		status_trace("Pending channel_update for %s: %s",
			     type_to_string(tmpctx, struct short_channel_id, scid),
			     sanitize_error(tmpctx, err, NULL));
		tal_free(err);
	}
}

void handle_pending_cannouncement(struct routing_state *rstate,
				  const struct short_channel_id *scid,
				  struct amount_sat sat,
				  const u8 *outscript)
{
	const u8 *s;
	struct pending_cannouncement *pending;

	pending = find_pending_cannouncement(rstate, scid);
	if (!pending)
		return;

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
		return;
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
		return;
	}

	if (!routing_add_channel_announcement(rstate, pending->announce, sat))
		status_failed(STATUS_FAIL_INTERNAL_ERROR,
			      "Could not add channel_announcement");

	/* Did we have an update waiting?  If so, apply now. */
	process_pending_channel_update(rstate, scid, pending->updates[0]);
	process_pending_channel_update(rstate, scid, pending->updates[1]);

	process_pending_node_announcement(rstate, &pending->node_id_1);
	process_pending_node_announcement(rstate, &pending->node_id_2);

	tal_free(pending);
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
				  u64 timestamp,
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
	c->last_timestamp = timestamp;
	assert((c->channel_flags & ROUTING_FLAGS_DIRECTION) == idx);

	SUPERVERBOSE("Channel %s/%d was updated.",
		     type_to_string(tmpctx, struct short_channel_id, &chan->scid),
		     idx);
}

bool routing_add_channel_update(struct routing_state *rstate,
				const u8 *update TAKES)
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
	u8 direction;

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
	chan = get_channel(rstate, &short_channel_id);
	if (!chan)
		return false;

	if (message_flags & ROUTING_OPT_HTLC_MAX_MSAT) {
		/* Reject update if the `htlc_maximum_msat` is greater
		 * than the total available channel satoshis */
		if (amount_msat_greater_sat(htlc_maximum, chan->sat))
			return false;
	} else {
		/* If not indicated, set htlc_max_msat to channel capacity */
		if (!amount_sat_to_msat(&htlc_maximum, chan->sat)) {
			status_broken("Channel capacity %s overflows!",
				      type_to_string(tmpctx, struct amount_sat,
						     &chan->sat));
			return false;
		}
	}

	/* FIXME: https://github.com/lightningnetwork/lightning-rfc/pull/512
	 * says we MUST NOT exceed 2^32-1, but c-lightning did, so just trim
	 * rather than rejecting. */
	if (amount_msat_greater(htlc_maximum, rstate->chainparams->max_payment))
		htlc_maximum = rstate->chainparams->max_payment;

	direction = channel_flags & 0x1;
	set_connection_values(chan, direction, fee_base_msat,
			      fee_proportional_millionths, expiry,
			      message_flags, channel_flags,
			      timestamp, htlc_minimum, htlc_maximum);

	/* Replace any old one. */
	tal_free(chan->half[direction].channel_update);
	chan->half[direction].channel_update
		= tal_dup_arr(chan, u8, update, tal_count(update), 0);

	/* For private channels, we get updates without an announce: don't
	 * broadcast them! */
	if (!chan->channel_announce)
		return true;

	/* BOLT #7:
	 *   - MUST consider the `timestamp` of the `channel_announcement` to be
	 *     the `timestamp` of a corresponding `channel_update`.
	 *   - MUST consider whether to send the `channel_announcement` after
	 *     receiving the first corresponding `channel_update`.
	 */
	if (chan->channel_announcement_index == 0)
		add_channel_announce_to_broadcast(rstate, chan, timestamp);

	persistent_broadcast(rstate, chan->half[direction].channel_update,
			     timestamp);
	return true;
}

u8 *handle_channel_update(struct routing_state *rstate, const u8 *update TAKES,
			  const char *source)
{
	u8 *serialized;
	struct half_chan *c;
	secp256k1_ecdsa_signature signature;
	struct short_channel_id short_channel_id;
	u32 timestamp;
	u8 message_flags, channel_flags;
	u16 expiry;
	struct amount_msat htlc_minimum;
	u32 fee_base_msat;
	u32 fee_proportional_millionths;
	struct bitcoin_blkid chain_hash;
	struct chan *chan;
	u8 direction;
	size_t len = tal_count(update);
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

	chan = get_channel(rstate, &short_channel_id);

	/* Optimization: only check for pending if not public */
	if (!chan || !is_chan_public(chan)) {
		struct pending_cannouncement *pending;

		pending = find_pending_cannouncement(rstate, &short_channel_id);
		if (pending) {
			update_pending(pending,
				       timestamp, serialized, direction);
			return NULL;
		}

		if (!chan) {
			bad_gossip_order(serialized,
					 source,
					 tal_fmt(tmpctx, "%s(%u)",
						 type_to_string(tmpctx,
							struct short_channel_id,
							&short_channel_id),
						 channel_flags));
			return NULL;
		}
	}

	/* BOLT #7:
	 *
	 *  - if the `timestamp` is unreasonably far in the future:
	 *    - MAY discard the `channel_update`.
	 */
	if (timestamp > time_now().ts.tv_sec + rstate->prune_timeout) {
		status_debug("Received channel_update for %s with far time %u",
			     type_to_string(tmpctx, struct short_channel_id,
					    &short_channel_id),
			     timestamp);
		return NULL;
	}

	/* Note: we can consider old timestamps a case of "instant prune" too */
	if (timestamp < time_now().ts.tv_sec - rstate->prune_timeout) {
		status_debug("Received channel_update for %s with old time %u",
			     type_to_string(tmpctx, struct short_channel_id,
					    &short_channel_id),
			     timestamp);
		return NULL;
	}

	c = &chan->half[direction];

	if (is_halfchan_defined(c) && timestamp <= c->last_timestamp) {
		/* They're not supposed to do this! */
		if (timestamp == c->last_timestamp
		    && !memeq(c->channel_update, tal_count(c->channel_update),
			      serialized, tal_count(serialized))) {
			status_unusual("Bad gossip repeated timestamp for %s(%u): %s then %s",
				       type_to_string(tmpctx,
						      struct short_channel_id,
						      &short_channel_id),
				       channel_flags,
				       tal_hex(tmpctx, c->channel_update),
				       tal_hex(tmpctx, serialized));
		}
		SUPERVERBOSE("Ignoring outdated update.");
		return NULL;
	}

	err = check_channel_update(rstate, &chan->nodes[direction]->id,
				   &signature, serialized);
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

	status_trace("Received channel_update for channel %s/%d now %s was %s (from %s)",
		     type_to_string(tmpctx, struct short_channel_id,
				    &short_channel_id),
		     channel_flags & 0x01,
		     channel_flags & ROUTING_FLAGS_DISABLED ? "DISABLED" : "ACTIVE",
		     is_halfchan_defined(c)
		     ? (c->channel_flags & ROUTING_FLAGS_DISABLED ? "DISABLED" : "ACTIVE")
		     : "UNDEFINED",
		     source);

	if (!routing_add_channel_update(rstate, serialized))
		status_failed(STATUS_FAIL_INTERNAL_ERROR,
			      "Failed adding channel_update");

	return NULL;
}

static struct wireaddr *read_addresses(const tal_t *ctx, const u8 *ser)
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

bool routing_add_node_announcement(struct routing_state *rstate, const u8 *msg TAKES)
{
	struct node *node;
	secp256k1_ecdsa_signature signature;
	u32 timestamp;
	struct pubkey node_id;
	u8 rgb_color[3];
	u8 alias[32];
	u8 *features, *addresses;
	struct wireaddr *wireaddrs;

	if (!fromwire_node_announcement(tmpctx, msg,
					&signature, &features, &timestamp,
					&node_id, rgb_color, alias,
					&addresses))
		return false;

	node = get_node(rstate, &node_id);

	/* May happen if we accepted the node_announcement due to a local
	* channel, for which we didn't have the announcement yet. */
	if (node == NULL)
		return false;

	wireaddrs = read_addresses(tmpctx, addresses);
	tal_free(node->addresses);
	node->addresses = tal_steal(node, wireaddrs);

	node->last_timestamp = timestamp;
	memcpy(node->rgb_color, rgb_color, ARRAY_SIZE(node->rgb_color));
	memcpy(node->alias, alias, ARRAY_SIZE(node->alias));
	tal_free(node->globalfeatures);
	node->globalfeatures = tal_steal(node, features);

	tal_free(node->node_announcement);
	node->node_announcement = tal_dup_arr(node, u8, msg, tal_count(msg), 0);

	/* We might be waiting for channel_announce to be released. */
	if (node_has_broadcastable_channels(node)) {
		node->node_announcement_index = persistent_broadcast(
		    rstate, node->node_announcement, timestamp);
	}
	return true;
}

u8 *handle_node_announcement(struct routing_state *rstate, const u8 *node_ann)
{
	u8 *serialized;
	struct sha256_double hash;
	struct node *node;
	secp256k1_ecdsa_signature signature;
	u32 timestamp;
	struct pubkey node_id;
	u8 rgb_color[3];
	u8 alias[32];
	u8 *features, *addresses;
	struct wireaddr *wireaddrs;
	struct pending_node_announce *pna;
	size_t len = tal_count(node_ann);
	bool applied;

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
			     type_to_string(tmpctx, struct pubkey, &node_id),
			     tal_hex(tmpctx, features));
		return NULL;
	}

	sha256_double(&hash, serialized + 66, tal_count(serialized) - 66);
	if (!check_signed_hash(&hash, &signature, &node_id)) {
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

	/* Beyond this point it's not malformed, so safe if we make it
	 * pending and requeue later. */
	node = get_node(rstate, &node_id);

	/* BOLT #7:
	 *
	 * - if `node_id` is NOT previously known from a `channel_announcement`
	 *   message, OR if `timestamp` is NOT greater than the last-received
	 *   `node_announcement` from this `node_id`:
	 *    - SHOULD ignore the message.
	 */
	if (!node || !node_has_public_channels(node)) {
		/* Check if we are currently verifying the txout for a
		 * matching channel */
		pna = pending_node_map_get(rstate->pending_node_map,
					   &node_id);
		if (!pna) {
			bad_gossip_order(serialized, "node_announcement",
					 type_to_string(tmpctx, struct pubkey,
							&node_id));
		} else if (pna->timestamp < timestamp) {
			SUPERVERBOSE(
			    "Deferring node_announcement for node %s",
			    type_to_string(tmpctx, struct pubkey, &node_id));
			pna->timestamp = timestamp;
			tal_free(pna->node_announcement);
			pna->node_announcement = tal_dup_arr(pna, u8, node_ann,
							     tal_count(node_ann),
							     0);
		}
		return NULL;
	}

	if (node->last_timestamp >= timestamp) {
		SUPERVERBOSE("Ignoring node announcement, it's outdated.");
		return NULL;
	}

	status_trace("Received node_announcement for node %s",
		     type_to_string(tmpctx, struct pubkey, &node_id));

	applied = routing_add_node_announcement(rstate, serialized);
	assert(applied);
	return NULL;
}

struct route_hop *get_route(const tal_t *ctx, struct routing_state *rstate,
			    const struct pubkey *source,
			    const struct pubkey *destination,
			    struct amount_msat msat, double riskfactor,
			    u32 final_cltv,
			    double fuzz, u64 seed,
			    const struct short_channel_id_dir *excluded,
			    size_t max_hops)
{
	struct chan **route;
	struct amount_msat total_amount;
	unsigned int total_delay;
	struct amount_msat fee;
	struct route_hop *hops;
	struct node *n;
	struct amount_msat *saved_capacity;
	struct siphash_seed base_seed;

	saved_capacity = tal_arr(tmpctx, struct amount_msat, tal_count(excluded));

	base_seed.u.u64[0] = base_seed.u.u64[1] = seed;

	/* Temporarily set excluded channels' capacity to zero. */
	for (size_t i = 0; i < tal_count(excluded); i++) {
		struct chan *chan = get_channel(rstate, &excluded[i].scid);
		if (!chan)
			continue;
		saved_capacity[i] = chan->half[excluded[i].dir].htlc_maximum;
		chan->half[excluded[i].dir].htlc_maximum = AMOUNT_MSAT(0);
	}

	route = find_route(ctx, rstate, source, destination, msat,
			   riskfactor / BLOCKS_PER_YEAR / 100,
			   fuzz, &base_seed, max_hops, &fee);

	/* Now restore the capacity. */
	for (size_t i = 0; i < tal_count(excluded); i++) {
		struct chan *chan = get_channel(rstate, &excluded[i].scid);
		if (!chan)
			continue;
		chan->half[excluded[i].dir].htlc_maximum = saved_capacity[i];
	}

	if (!route) {
		return NULL;
	}

	/* Fees, delays need to be calculated backwards along route. */
	hops = tal_arr(ctx, struct route_hop, tal_count(route));
	total_amount = msat;
	total_delay = final_cltv;

	/* Start at destination node. */
	n = get_node(rstate, destination);
	for (int i = tal_count(route) - 1; i >= 0; i--) {
		const struct half_chan *c;

		int idx = half_chan_to(n, route[i]);
		c = &route[i]->half[idx];
		hops[i].channel_id = route[i]->scid;
		hops[i].nodeid = n->id;
		hops[i].amount = total_amount;
		hops[i].delay = total_delay;
		hops[i].direction = idx;

		/* Since we calculated this route, it should not overflow! */
		if (!amount_msat_add_fee(&total_amount,
					 c->base_fee, c->proportional_fee)) {
			status_broken("Route overflow step %i: %s + %u/%u!?",
				      i, type_to_string(tmpctx, struct amount_msat,
							&total_amount),
				      c->base_fee, c->proportional_fee);
			return tal_free(hops);
		}
		total_delay += c->delay;
		n = other_node(n, route[i]);
	}
	assert(pubkey_eq(&n->id, source));

	return hops;
}

void routing_failure(struct routing_state *rstate,
		     const struct pubkey *erring_node_pubkey,
		     const struct short_channel_id *scid,
		     int erring_direction,
		     enum onion_type failcode,
		     const u8 *channel_update)
{
	status_trace("Received routing failure 0x%04x (%s), "
		     "erring node %s, "
		     "channel %s/%u",
		     (int) failcode, onion_type_name(failcode),
		     type_to_string(tmpctx, struct pubkey, erring_node_pubkey),
		     type_to_string(tmpctx, struct short_channel_id, scid),
		     erring_direction);

	/* lightningd will only extract this if UPDATE is set. */
	if (channel_update) {
		u8 *err = handle_channel_update(rstate, channel_update, "error");
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
		struct node *node = get_node(rstate, erring_node_pubkey);
		if (!node) {
			status_unusual("routing_failure: Erring node %s not in map",
				       type_to_string(tmpctx, struct pubkey,
						      erring_node_pubkey));
		} else {
			status_trace("Deleting node %s",
				     type_to_string(tmpctx,
						    struct pubkey,
						    &node->id));
			for (size_t i = 0; i < tal_count(node->chans); ++i) {
				/* Set it up to be pruned. */
				tal_steal(tmpctx, node->chans[i]);
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
			    && !pubkey_eq(&chan->nodes[!erring_direction]->id,
					  erring_node_pubkey))
				return;

			status_trace("Deleting channel %s",
				     type_to_string(tmpctx,
						    struct short_channel_id,
						    scid));
			/* Set it up to be deleted. */
			tal_steal(tmpctx, chan);
		}
	}
}


void route_prune(struct routing_state *rstate)
{
	u64 now = time_now().ts.tv_sec;
	/* Anything below this highwater mark ought to be pruned */
	const s64 highwater = now - rstate->prune_timeout;
	const tal_t *pruned = tal(NULL, char);
	struct chan *chan;
	u64 idx;

	/* Now iterate through all channels and see if it is still alive */
	for (chan = uintmap_first(&rstate->chanmap, &idx);
	     chan;
	     chan = uintmap_after(&rstate->chanmap, &idx)) {
		/* Local-only?  Don't prune. */
		if (!is_chan_public(chan))
			continue;

		if (chan->half[0].last_timestamp < highwater
		    && chan->half[1].last_timestamp < highwater) {
			status_trace(
			    "Pruning channel %s from network view (ages %"PRIu64" and %"PRIu64"s)",
			    type_to_string(tmpctx, struct short_channel_id,
					   &chan->scid),
			    now - chan->half[0].last_timestamp,
			    now - chan->half[1].last_timestamp);

			/* This may perturb iteration so do outside loop. */
			tal_steal(pruned, chan);
		}
	}

	/* This frees all the chans and maybe even nodes. */
	tal_free(pruned);
}

#if DEVELOPER
void memleak_remove_routing_tables(struct htable *memtable,
				   const struct routing_state *rstate)
{
	memleak_remove_htable(memtable, &rstate->nodes->raw);
	memleak_remove_htable(memtable, &rstate->pending_node_map->raw);
	memleak_remove_uintmap(memtable, &rstate->broadcasts->broadcasts);
}
#endif /* DEVELOPER */

bool handle_local_add_channel(struct routing_state *rstate, const u8 *msg)
{
	struct short_channel_id scid;
	struct pubkey remote_node_id;
	struct amount_sat sat;

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
	new_chan(rstate, &scid, &rstate->local_id, &remote_node_id, sat);
	return true;
}
