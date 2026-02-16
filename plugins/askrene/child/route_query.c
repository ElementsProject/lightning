#include "config.h"
#include <common/gossmap.h>
#include <plugins/askrene/child/additional_costs.h>
#include <plugins/askrene/child/route_query.h>
#include <plugins/askrene/layer.h>
#include <plugins/askrene/reserve.h>

struct amount_msat get_additional_per_htlc_cost(const struct route_query *rq,
						const struct short_channel_id_dir *scidd)
{
	const struct per_htlc_cost *phc;
	phc = additional_cost_htable_get(rq->additional_costs, scidd);
	if (phc)
		return phc->per_htlc_cost;
	else
		return AMOUNT_MSAT(0);
}

void get_constraints(const struct route_query *rq,
		     const struct gossmap_chan *chan,
		     int dir,
		     struct amount_msat *min,
		     struct amount_msat *max)
{
	struct short_channel_id_dir scidd;
	size_t idx = gossmap_chan_idx(rq->gossmap, chan);

	*min = AMOUNT_MSAT(0);

	/* Fast path: no information known, no reserve. */
	if (idx < tal_count(rq->capacities) && rq->capacities[idx] != 0) {
		*max = amount_msat(fp16_to_u64(rq->capacities[idx]) * 1000);
		return;
	}

	/* Naive implementation! */
	scidd.scid = gossmap_chan_scid(rq->gossmap, chan);
	scidd.dir = dir;
	*max = AMOUNT_MSAT(-1ULL);

	/* Look through layers for any constraints (might be dummy
	 * ones, for created channels!) */
	for (size_t i = 0; i < tal_count(rq->layers); i++)
		layer_apply_constraints(rq->layers[i], &scidd, min, max);

	/* Might be here because it's reserved, but capacity is normal. */
	if (amount_msat_eq(*max, AMOUNT_MSAT(-1ULL)))
		*max = gossmap_chan_get_capacity(rq->gossmap, chan);

	/* Finally, if any is in use, subtract that! */
	reserve_sub(rq->reserved, &scidd, rq->layers, min);
	reserve_sub(rq->reserved, &scidd, rq->layers, max);
}
