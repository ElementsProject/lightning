#include "config.h"
#include <ccan/asort/asort.h>
#include <common/gossmap.h>
#include <math.h>
#include <plugins/askrene/child/additional_costs.h>
#include <plugins/askrene/child/mcf.h>
#include <plugins/askrene/child/route_query.h>
#include <plugins/askrene/layer.h>
#include <plugins/askrene/reserve.h>

/* Lifetime of liquidity bounds is one day. "Lifetime" in the sense of the
 * exponential time decay: the time it takes for the liquidity lower bound to be
 * reduced by half is "lifetime" times ln(2) ~ 16 hours. */
#define ASKRENE_RELAX_TIME_SECS 86400

/* It could be any number between 0 and 1. It represents the fraction of lower
 * liquidity bound that we adjust when we find a failure. The smaller it is the
 * more we trust previous knowledge. Similar to a "learning velocity" for AI. */
#define ASKRENE_FAILURE_RELAX_FRACTION 0.5

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

static int constraint_cmp(const struct constraint *a,
			  const struct constraint *b, void *unused)
{
	if (a->timestamp < b->timestamp)
		return -1;
	if (a->timestamp > b->timestamp)
		return 1;
	return 0;
}

/* Like a capacitor discharging, this is the physical process of information
 * getting older and entropy increasing. It satisfies the semigroup property so
 * it is a well defined Markovian time evolution operation. Same for the
 * "charge" operation.
 * 	Dicharge(x, t) = x * exp(-t/lifetime)
 * 	Charge(x, t) = C - (C -x) * exp(-t/lifetime)
 *
 * 	Discharge(x, t1+t2) = Discharge(Discharge(x, t1), t2),
 * 	Charge(x, t1+t2) = Charge(Charge(x, t1), t2),
 *
 * @min: apply discharge to it,
 * @max: apply charge to it,
 * @capacity: "capacitor"'s capacity,
 * @time_delta: time interval in seconds, 0-> nothing changes, infinity->full
 * charge/discharge
 * @lifetime: characteristic time of the system in seconds, ie. min is reduced
 * by half after ln(2)*lifetime seconds.
 */
// FIXME: unit test
static void exponential_time_charge_discharge(struct amount_msat *min,
					      struct amount_msat *max,
					      const struct amount_msat capacity,
					      const u64 time_delta,
					      const u64 lifetime)
{
	double factor = exp((-1.0 * time_delta) / lifetime);
	struct amount_msat residual;

	if (!amount_msat_scale(min, *min, factor))
		goto fail;

	if (!amount_msat_sub(&residual, capacity, *max))
		goto fail;
	if (!amount_msat_scale(&residual, residual, factor))
		goto fail;
	if (!amount_msat_sub(max, capacity, residual))
		goto fail;

fail:
	/* It should not fail, but if it does, we default to 0 knowledge. */
	*min = AMOUNT_MSAT(0);
	*max = capacity;
}

/* Computes min/max bounds based on known constraints. It self-adjusts for
 * contradictory information giving precedence to more recent constraints. Time
 * decay is considered.
 * FIXME: this approach was completey cooked by hand because it is better than
 * simply trusting all constraints as we have seen during tests (see CLN #9282).
 * However it would be nice to have a theoretically sound adjustment, eg.
 * Maximum Likelyhood, if applicable. */
// FIXME: unit test
static void constraints_get_bounds_selfadjust(struct constraint *constraints,
					      const struct amount_msat capacity,
					      struct amount_msat *min,
					      struct amount_msat *max,
					      const u64 current_unixtime)
{
	assert(ASKRENE_FAILURE_RELAX_FRACTION >= 0.0 &&
	       ASKRENE_FAILURE_RELAX_FRACTION <= 1.0);
	u64 last_timestamp = 0, delta;
	double prob_fail;
	struct amount_msat x, amount, high;

	*min = AMOUNT_MSAT(0);
	*max = capacity;
	asort(constraints, tal_count(constraints), constraint_cmp, NULL);
	for (size_t i = 0; i < tal_count(constraints); i++) {
		assert(constraints[i].timestamp >= last_timestamp);
		delta = constraints[i].timestamp - last_timestamp;
		last_timestamp = constraints[i].timestamp;

		/* time relax the bound we carry */
		exponential_time_charge_discharge(min, max, capacity, delta,
						  ASKRENE_RELAX_TIME_SECS);

		if (amount_msat_greater_eq(constraints[i].max,
					   AMOUNT_MSAT(UINT64_MAX))) {
			/* this is an "unconstrained" event, a min value bound
			 */
			x = constraints[i].min;
			*min = amount_msat_max(*min, x);
			*max = amount_msat_max(*max, x);
		} else {
			/* this is a "constrained" event, a max value bound */
			x = constraints[i].max;
			if (amount_msat_greater(x, *max)) {
				/* Trivial case, we were expecting x to fail. */
			} else if (amount_msat_less(x, *min)) {
				/* This should have succeeded 100% of the times,
				 * our knowledge was wrong. */
				*min = amount_msat_min(*min, x);
				*max = amount_msat_min(*max, x);
				if (!amount_msat_scale(
					min, *min,
					1.0 - ASKRENE_FAILURE_RELAX_FRACTION)) {
					*min = AMOUNT_MSAT(0);
				}
			} else {
				/* We got failure for a quantity between min and
				 * max bounds. We relax a little the lower bound
				 * in relation to the probability of this event
				 * taking place. If p~1 this was expected,
				 * min/max reflected reality. On the other hand
				 * if p~0, we were either unlucky or more likely
				 * our lower bound was too high. */

				/* off-by-one because the high bound in MCF
				 * means "we know the liquidity is below this
				 * value", which makes some equations take a
				 * simpler form. */
				if (!amount_msat_add(&high, *max,
						     AMOUNT_MSAT(1)))
					high = capacity;
				/* off-by-one because
				 * json_askrene_inform_channel already
				 * substracted 1msat here, meaning we tried x+1
				 * and it failed. */
				if (!amount_msat_add(&amount, x,
						     AMOUNT_MSAT(1)))
					amount = capacity;
				prob_fail = 1.0 - pickhardt_richter_probability(
						      *min, high, amount);
				assert(prob_fail >= 0 && prob_fail <= 1.0);

				*max = amount_msat_min(*max, x);
				if (!amount_msat_scale(
					min, *min,
					1.0 + ASKRENE_FAILURE_RELAX_FRACTION *
						  (prob_fail - 1.0))) {
					*min = AMOUNT_MSAT(0);
				}
			}
		}
	}
	/* Finally time relax the bound we carry to the current time. */
	if(current_unixtime > last_timestamp)
		exponential_time_charge_discharge(
		    min, max, capacity, current_unixtime - last_timestamp,
		    ASKRENE_RELAX_TIME_SECS);
}

/* Constraints produced bounds this way since askrene was first written. We keep
 * it around momentarily. */
// static void constraints_get_bounds_legacy(const struct constraint *constraints,
// 					  const struct amount_msat capacity,
// 					  struct amount_msat *min,
// 					  struct amount_msat *max)
// {
// 	*min = AMOUNT_MSAT(0);
// 	*max = capacity;
// 	for (size_t i = 0; i < tal_count(constraints); i++) {
// 		*min = amount_msat_max(*min, constraints[i].min);
// 		*max = amount_msat_min(*max, constraints[i].max);
// 	}
// 	if(amount_msat_greater(*min, *max))
// 		*min = *max;
// }

void get_constraints(const struct route_query *rq,
		     const struct gossmap_chan *chan,
		     int dir,
		     struct amount_msat *min,
		     struct amount_msat *max)
{
	struct short_channel_id_dir scidd;
	size_t idx = gossmap_chan_idx(rq->gossmap, chan);
	struct constraint *constraints = tal_arr(rq, struct constraint, 0);

	/* Fast path: no information known, no reserve. */
	if (idx < tal_count(rq->capacities) && rq->capacities[idx] != 0) {
		*min = AMOUNT_MSAT(0);
		*max = amount_msat(fp16_to_u64(rq->capacities[idx]) * 1000);
		return;
	}

	const struct amount_msat capacity =
	    gossmap_chan_get_capacity(rq->gossmap, chan);

	/* Naive implementation! */
	scidd.scid = gossmap_chan_scid(rq->gossmap, chan);
	scidd.dir = dir;

	/* Look through layers for any constraints (might be dummy
	 * ones, for created channels!) */
	for (size_t i = 0; i < tal_count(rq->layers); i++)
		constraints = layer_get_constraints(rq, rq->layers[i], &scidd,
						    take(constraints));

	constraints_get_bounds_selfadjust(constraints, capacity, min, max,
					  rq->current_unixtime);

	/* Finally, if any is in use, subtract that! */
	reserve_sub(rq->reserved, &scidd, rq->layers, min);
	reserve_sub(rq->reserved, &scidd, rq->layers, max);
}
