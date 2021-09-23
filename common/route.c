#include "config.h"
#include <assert.h>
#include <common/dijkstra.h>
#include <common/features.h>
#include <common/gossmap.h>
#include <common/route.h>

bool route_can_carry_even_disabled(const struct gossmap *map,
				   const struct gossmap_chan *c,
				   int dir,
				   struct amount_msat amount,
				   void *unused)
{
	if (!gossmap_chan_set(c, dir))
		return false;
	if (!gossmap_chan_capacity(c, dir, amount))
		return false;
	return true;
}

/* Generally only one side gets marked disabled, but it's disabled. */
bool route_can_carry(const struct gossmap *map,
		       const struct gossmap_chan *c,
		       int dir,
		       struct amount_msat amount,
		       void *arg)
{
	if (!c->half[dir].enabled || !c->half[!dir].enabled)
		return false;
	return route_can_carry_even_disabled(map, c, dir, amount, arg);
}

/* Squeeze total costs into a u32 */
static u32 costs_to_score(struct amount_msat cost,
			  struct amount_msat risk)
{
	u64 costs = cost.millisatoshis + risk.millisatoshis; /* Raw: score */
	if (costs > 0xFFFFFFFF)
		costs = 0xFFFFFFFF;
	return costs;
}

/* Prioritize distance over costs */
u64 route_score_shorter(u32 distance,
			struct amount_msat cost,
			struct amount_msat risk,
			int dir UNUSED,
			const struct gossmap_chan *c UNUSED)
{
	return costs_to_score(cost, risk) + ((u64)distance << 32);
}

/* Prioritize costs over distance */
u64 route_score_cheaper(u32 distance,
			struct amount_msat cost,
			struct amount_msat risk,
			int dir UNUSED,
			const struct gossmap_chan *c UNUSED)
{
	return ((u64)costs_to_score(cost, risk) << 32) + distance;
}

/* Recursive version: return false if we can't get there.
 *
 * amount and cltv are updated, and reflect the amount we
 * and delay would have to put into the first channel (usually
 * ignored, since we don't pay for our own channels!).
 */
static bool dijkstra_to_hops(struct route_hop **hops,
			     const struct gossmap *gossmap,
			     const struct dijkstra *dij,
			     const struct gossmap_node *cur,
			     struct amount_msat *amount,
			     u32 *cltv)
{
	u32 curidx = gossmap_node_idx(gossmap, cur);
	u32 dist = dijkstra_distance(dij, curidx);
	struct gossmap_chan *c;
	const struct gossmap_node *next;
	size_t num_hops = tal_count(*hops);
	const struct half_chan *h;

	if (dist == 0)
		return true;

	if (dist == UINT_MAX)
		return false;

	tal_resize(hops, num_hops + 1);

	/* OK, populate other fields. */
	c = dijkstra_best_chan(dij, curidx);
	if (c->half[0].nodeidx == curidx) {
		(*hops)[num_hops].direction = 0;
	} else {
		assert(c->half[1].nodeidx == curidx);
		(*hops)[num_hops].direction = 1;
	}
	(*hops)[num_hops].scid = gossmap_chan_scid(gossmap, c);

	/* Find other end of channel. */
	next = gossmap_nth_node(gossmap, c, !(*hops)[num_hops].direction);
	gossmap_node_get_id(gossmap, next, &(*hops)[num_hops].node_id);
	/* If we don't have a node_announcement, we *assume* modern */
	if (next->nann_off == 0
	    || gossmap_node_get_feature(gossmap, next, OPT_VAR_ONION) != -1)
		(*hops)[num_hops].style = ROUTE_HOP_TLV;
	else
		(*hops)[num_hops].style = ROUTE_HOP_LEGACY;

	/* These are (ab)used by others. */
	(*hops)[num_hops].blinding = NULL;
	(*hops)[num_hops].enctlv = NULL;

	if (!dijkstra_to_hops(hops, gossmap, dij, next, amount, cltv))
		return false;

	(*hops)[num_hops].amount = *amount;
	(*hops)[num_hops].delay = *cltv;

	h = &c->half[(*hops)[num_hops].direction];
	if (!amount_msat_add_fee(amount, h->base_fee, h->proportional_fee))
		/* Shouldn't happen, since we said it would route,
		 * amounts must be sane. */
		abort();
	*cltv += h->delay;
	return true;
}

struct route_hop *route_from_dijkstra(const tal_t *ctx,
				      const struct gossmap *map,
				      const struct dijkstra *dij,
				      const struct gossmap_node *src,
				      struct amount_msat final_amount,
				      u32 final_cltv)
{
	struct route_hop *hops = tal_arr(ctx, struct route_hop, 0);

	if (!dijkstra_to_hops(&hops, map, dij, src, &final_amount, &final_cltv))
		return tal_free(hops);

	return hops;
}
