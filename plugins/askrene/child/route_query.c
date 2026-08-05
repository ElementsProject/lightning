#include "config.h"
#include <ccan/asort/asort.h>
#include <common/gossmap.h>
#include <common/utils.h>
#include <math.h>
#include <plugins/askrene/child/additional_costs.h>
#include <plugins/askrene/child/mcf.h>
#include <plugins/askrene/child/route_query.h>
#include <plugins/askrene/layer.h>
#include <plugins/askrene/reserve.h>

/* It could be any number between 0 and 1. It represents the fraction of lower
 * liquidity bound that we adjust when we find a failure. The smaller it is the
 * more we trust previous knowledge. Similar to a "learning velocity" for AI. */
#define ASKRENE_FAILURE_RELAX_FRACTION 0.5

/* Lifetime of liquidity bounds is one day. "Lifetime" in the sense of the
 * exponential time decay: the time it takes for the liquidity lower bound to be
 * reduced by half is "lifetime" times ln(2) ~ 16 hours. */
#define ASKRENE_RELAX_TIME_SECS 86400

/* Like a capacitor discharging, this is the physical process of information
 * getting older and entropy increasing. It satisfies the semigroup property so
 * it is a well defined Markovian time evolution operation. Same for the
 * "charge" operation.
 *
 * Definition:
 * 	Dicharge(x, t) = x * exp(-t/lifetime)
 * 	Charge(x, t) = C - (C -x) * exp(-t/lifetime)
 *
 * Semigroup composition rule:
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

	return;
fail:
	/* It should not fail, but if it does, we default to 0 knowledge. */
	*min = AMOUNT_MSAT(0);
	*max = capacity;
}

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

static int intel_cmp(const struct channel_intel *a,
		     const struct channel_intel *b, void *unused)
{
	const u64 a_time = channel_intel_timestamp(a);
	const u64 b_time = channel_intel_timestamp(b);
	if (a_time < b_time)
		return -1;
	if (a_time > b_time)
		return 1;
	return 0;
}

/* Bounds in one direction determine the bounds on the other direction. */
static void reverse_bounds(struct amount_msat *rev_min,
			   struct amount_msat *rev_max,
			   struct amount_msat capacity,
			   struct amount_msat min,
			   struct amount_msat max)
{
	if (!amount_msat_sub(rev_min, capacity, max)) {
		assert(0);
	}
	if (!amount_msat_sub(rev_max, capacity, min)) {
		assert(0);
	}
}

/* When we have been informed of an "unconstrained" flow event. */
static void bounds_by_unconstrained(struct amount_msat x,
				    struct amount_msat capacity,
				    struct amount_msat *min,
				    struct amount_msat *max,
				    bool reverse)
{
	if(reverse){
		struct amount_msat rev_min, rev_max;
		reverse_bounds(&rev_min, &rev_max, capacity, *min, *max);
		bounds_by_unconstrained(x, capacity, &rev_min, &rev_max, false);
		reverse_bounds(min, max, capacity, rev_min, rev_max);
		return;
	}
	*min = amount_msat_max(*min, x);
	*max = amount_msat_max(*max, x);
}

/* When we have been informed of a "constrained" flow event. */
static void bounds_by_constrained(struct amount_msat x,
				  struct amount_msat capacity,
				  struct amount_msat *min,
				  struct amount_msat *max,
				  bool reverse,
				  bool is_internal)
{
	if(reverse){
		struct amount_msat rev_min, rev_max;
		reverse_bounds(&rev_min, &rev_max, capacity, *min, *max);
		bounds_by_constrained(x, capacity, &rev_min, &rev_max, false, is_internal);
		reverse_bounds(min, max, capacity, rev_min, rev_max);
		return;
	}

	if (is_internal) {
		/* an internal constraint is a hard bound, not an observed event
		 */
		*min = amount_msat_min(*min, x);
		*max = amount_msat_min(*max, x);
		return;
	}

	double prob_fail;
	struct amount_msat high, amount;
	if (amount_msat_greater(x, *max)) {
		/* Trivial case, we were expecting x to fail. */
	} else if (amount_msat_less(x, *min)) {
		/* This should have succeeded 100% of the times,
		 * our knowledge was wrong. */
		*min = amount_msat_min(*min, x);
		*max = amount_msat_min(*max, x);
		if (!amount_msat_scale(min, *min,
				       1.0 - ASKRENE_FAILURE_RELAX_FRACTION)) {
			*min = AMOUNT_MSAT(0);
		}
	} else {
		/* We got failure for a quantity between min and
		 * max bounds. We relax a little the lower bound
		 * in relation to the probability of this event
		 * taking place. If p~1, this was expected,
		 * min/max reflected reality. On the other hand
		 * if p~0, we were either unlucky or more likely
		 * our lower bound was too high. */

		/* off-by-one because the high bound in MCF
		 * means "we know the liquidity is below this
		 * value", which makes some equations take a
		 * simpler form. */
		if (!amount_msat_add(&high, *max, AMOUNT_MSAT(1)))
			high = capacity;
		/* off-by-one because
		 * json_askrene_inform_channel already
		 * substracted 1msat here, meaning we tried x+1
		 * and it failed. */
		if (!amount_msat_add(&amount, x, AMOUNT_MSAT(1)))
			amount = capacity;
		prob_fail =
		    1.0 - pickhardt_richter_probability(*min, high, amount);
		assert(prob_fail >= 0 && prob_fail <= 1.0);

		*max = amount_msat_min(*max, x);
		if (!amount_msat_scale(min, *min,
				       1.0 + ASKRENE_FAILURE_RELAX_FRACTION *
						 (prob_fail - 1.0))) {
			*min = AMOUNT_MSAT(0);
		}
	}
}

/* When we have been informed of a "succeeded" flow event. */
static void bounds_by_impression(struct amount_msat x,
				 struct amount_msat capacity,
				 struct amount_msat *min,
				 struct amount_msat *max,
				 bool reverse)
{
	if(reverse){
		struct amount_msat rev_min, rev_max;
		reverse_bounds(&rev_min, &rev_max, capacity, *min, *max);
		bounds_by_impression(x, capacity, &rev_min, &rev_max, false);
		reverse_bounds(min, max, capacity, rev_min, rev_max);
		return;
	}
	if(!amount_msat_deduct(max, x))
		*max = AMOUNT_MSAT(0);
	if(!amount_msat_deduct(min, x))
		*min = AMOUNT_MSAT(0);
}

/* Computes min/max bounds based on known constraints. It self-adjusts for
 * contradictory information giving precedence to more recent constraints.
 * FIXME: add time decay
 * FIXME: this approach was completey cooked by hand because it is better than
 * simply trusting all constraints as we have seen during tests (see CLN #9282).
 * However it would be nice to have a theoretically sound adjustment, eg.
 * Maximum Likelyhood, if applicable.
 * FIXME: unit test it */
static void get_bounds_adaptively(struct channel_intel *intelarr,
				  const struct amount_msat capacity,
				  struct amount_msat *min,
				  struct amount_msat *max,
				  int dir,
				  const u64 current_unixtime)
{
	u64 last_timestamp = 0, delta, this_timestamp;
	const struct constraint *constraint;
	const struct impression *impression;

	*min = AMOUNT_MSAT(0);
	*max = capacity;
	asort(intelarr, tal_count(intelarr), intel_cmp, NULL);
	for (size_t i = 0; i < tal_count(intelarr); i++) {
		if (intelarr[i].constraint) {
			/* a constraint */
			assert(!intelarr[i].impression);
			constraint = intelarr[i].constraint;

			/* Constraints created internally have UINT64_MAX in the
			 * timestamp, we should treat them as if they belong to
			 * the present. */
			this_timestamp = constraint->timestamp == UINT64_MAX
					     ? current_unixtime
					     : constraint->timestamp;
			assert(this_timestamp >= last_timestamp);
			delta = this_timestamp - last_timestamp;
			last_timestamp = this_timestamp;

			/* time relax the bounds we carry */
			if (delta > 0)
				exponential_time_charge_discharge(
				    min, max, capacity, delta,
				    ASKRENE_RELAX_TIME_SECS);

			if (amount_msat_greater(constraint->min,
						AMOUNT_MSAT(0))) {
				/* this is an "unconstrained" event, a min value
				 * bound */
				bounds_by_unconstrained(
				    constraint->min, capacity, min, max,
				    dir != constraint->scidd.dir);
			}
			if (amount_msat_less(constraint->max,
					     AMOUNT_MSAT(UINT64_MAX))) {
				/* this is a "constrained" event, a max value
				 * bound */
				bounds_by_constrained(
				    constraint->max, capacity, min, max,
				    dir != constraint->scidd.dir,
				    constraint->timestamp == UINT64_MAX);
			}
		} else {
			/* an impression */
			assert(intelarr[i].impression);
			impression = intelarr[i].impression;

			/* we don't have impressions created internally */
			assert(impression->timestamp < UINT64_MAX);

			assert(impression->timestamp >= last_timestamp);
			delta = impression->timestamp - last_timestamp;
			last_timestamp = impression->timestamp;

			/* time relax the bounds we carry */
			exponential_time_charge_discharge(
			    min, max, capacity, delta, ASKRENE_RELAX_TIME_SECS);

			bounds_by_impression(impression->amount, capacity, min,
					     max, dir != impression->scidd.dir);
		}
	}

	/* Finally time relax the bounds we carry to the current time. */
	if (current_unixtime > last_timestamp)
		exponential_time_charge_discharge(
		    min, max, capacity, current_unixtime - last_timestamp,
		    ASKRENE_RELAX_TIME_SECS);
}

void get_constraints(const struct route_query *rq,
		     const struct gossmap_chan *chan,
		     int dir,
		     struct amount_msat *min,
		     struct amount_msat *max)
{
	struct short_channel_id_dir scidd;
	size_t idx = gossmap_chan_idx(rq->gossmap, chan);
	struct channel_intel *intelarr;
	struct amount_msat capacity;

	*min = AMOUNT_MSAT(0);

	/* Fast path: no information known, no reserve. */
	if (idx < tal_count(rq->capacities) && rq->capacities[idx] != 0) {
		*max = amount_msat(fp16_to_u64(rq->capacities[idx]) * 1000);
		return;
	}

	/* Might be here because it's reserved, but capacity is normal. */
	*max = capacity = gossmap_chan_get_capacity(rq->gossmap, chan);
	intelarr = tal_arr(tmpctx, struct channel_intel, 0);

	/* Naive implementation! */
	scidd.scid = gossmap_chan_scid(rq->gossmap, chan);
	scidd.dir = dir;

	/* Look through layers for any constraints (might be dummy
	 * ones, for created channels!) */
	for (size_t i = 0; i < tal_count(rq->layers); i++)
		intelarr = layer_collect_channel_intels(tmpctx, rq->layers[i],
							&scidd, take(intelarr));

	get_bounds_adaptively(intelarr, capacity, min, max, dir,
			      rq->current_unixtime);
	tal_free(intelarr);
	/* Finally, if any is in use, subtract that! */
	reserve_sub(rq->reserved, &scidd, rq->layers, min);
	reserve_sub(rq->reserved, &scidd, rq->layers, max);
}
