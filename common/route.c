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

bool route_path_shorter(u32 old_distance, u32 new_distance,
			struct amount_msat old_cost,
			struct amount_msat new_cost,
			struct amount_msat old_risk,
			struct amount_msat new_risk,
			void *unused)
{
	if (new_distance > old_distance)
		return false;
	if (new_distance < old_distance)
		return true;

	/* Tiebreak by cost */
	if (!amount_msat_add(&old_cost, old_cost, old_risk)
	    || !amount_msat_add(&new_cost, new_cost, new_risk))
		return false;
	return amount_msat_less(new_cost, old_cost);
}

bool route_path_cheaper(u32 old_distance, u32 new_distance,
			struct amount_msat old_cost,
			struct amount_msat new_cost,
			struct amount_msat old_risk,
			struct amount_msat new_risk,
			void *unused)
{
	if (!amount_msat_add(&old_cost, old_cost, old_risk)
	    || !amount_msat_add(&new_cost, new_cost, new_risk))
		return false;

	if (amount_msat_greater(new_cost, old_cost))
		return false;
	if (amount_msat_less(new_cost, old_cost))
		return true;

	/* Tiebreak by distance */
	return new_distance < old_distance;
}

struct route **route_from_dijkstra(const struct gossmap *map,
				   const struct dijkstra *dij,
				   const struct gossmap_node *cur)
{
	struct route **path = tal_arr(map, struct route *, 0);
	u32 curidx = gossmap_node_idx(map, cur);

	while (dijkstra_distance(dij, curidx) != 0) {
		struct route *r;

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
