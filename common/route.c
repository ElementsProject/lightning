#include "config.h"
#include <assert.h>
#include <ccan/err/err.h>
#include <ccan/tal/str/str.h>
#include <ccan/time/time.h>
#include <common/dijkstra.h>
#include <common/gossmap.h>
#include <common/node_id.h>
#include <common/pseudorand.h>
#include <common/random_select.h>
#include <common/route.h>
#include <common/type_to_string.h>
#include <inttypes.h>
#include <stdio.h>

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
			struct amount_msat risk)
{
	return costs_to_score(cost, risk) + ((u64)distance << 32);
}

/* Prioritize costs over distance */
u64 route_score_cheaper(u32 distance,
			struct amount_msat cost,
			struct amount_msat risk)
{
	return ((u64)costs_to_score(cost, risk) << 32) + distance;
}

struct route **route_from_dijkstra(const tal_t *ctx,
				   const struct gossmap *map,
				   const struct dijkstra *dij,
				   const struct gossmap_node *cur)
{
	struct route **path = tal_arr(ctx, struct route *, 0);
	u32 curidx = gossmap_node_idx(map, cur);

	while (dijkstra_distance(dij, curidx) != 0) {
		struct route *r;

		if (dijkstra_distance(dij, curidx) == UINT_MAX)
			return tal_free(path);

		r = tal(path, struct route);
		r->c = dijkstra_best_chan(dij, curidx);
		if (r->c->half[0].nodeidx == curidx) {
			r->dir = 0;
		} else {
			assert(r->c->half[1].nodeidx == curidx);
			r->dir = 1;
		}
		tal_arr_expand(&path, r);
		cur = gossmap_nth_node(map, r->c, !r->dir);
		curidx = gossmap_node_idx(map, cur);
	}
	return path;
}
