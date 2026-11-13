#include "config.h"
#include <bitcoin/short_channel_id.h>
#include <ccan/asort/asort.h>
#include <ccan/tal/str/str.h>
#include <common/gossmap.h>
#include <common/memleak.h>
#include <plugins/askrene/child/additional_costs.h>
#include <plugins/askrene/child/mcf.h>
#include <plugins/askrene/child/route_query.h>
#include <plugins/askrene/layer.h>
#include <plugins/askrene/reserve.h>

/* It could be any number between 0 and 1. It represents the fraction of lower
 * liquidity bound that we adjust when we find a failure. The smaller it is the
 * more we trust previous knowledge. Similar to a "learning velocity" for AI. */
#define ASKRENE_FAILURE_RELAX_FRACTION 0.5

/* This is what MCF needs and it is obtained by combining user constraints,
 * observations and reservations. */
struct channel_bounds {
	/* which channel */
	struct short_channel_id scid;
	struct amount_msat capacity;

	struct {
		/* bounds values, liquidity is at least 'min' and at most 'max'
		 */
		struct amount_msat min, max;

		/* which layer to blame */
		const struct layer *layer;
	} half[2];
};

static const struct short_channel_id channel_bounds_scid(const struct channel_bounds *c)
{
	return c->scid;
}

static inline bool channel_bounds_eq(const struct channel_bounds *c,
				     const struct short_channel_id scid)
{
	return short_channel_id_eq(scid, channel_bounds_scid(c));
}

HTABLE_DEFINE_NODUPS_TYPE(struct channel_bounds, channel_bounds_scid, hash_scid,
			  channel_bounds_eq, channel_bounds_htable);

static int cmp_u64(const u64 a, const u64 b)
{
	if (a < b)
		return -1;
	if (a > b)
		return 1;
	return 0;
}

static int cmp_channel_intel(const struct channel_intel_out *A,
			     const struct channel_intel_out *B, void *unused)
{
	int ret;

	ret = cmp_u64(A->scidd.scid.u64, B->scidd.scid.u64);
	if (ret)
		return ret;

	/* short_channel_ids are equal */
	ret = cmp_u64(A->timestamp, B->timestamp);
	if (ret)
		return ret;

	/* also timestamps are equal */
	return cmp_u64(A->index, B->index);
}

static int cmp_channel_observation(const struct channel_observation_out *A,
				   const struct channel_observation_out *B,
				   void *unused)
{
	int ret;

	ret = cmp_u64(A->scidd.scid.u64, B->scidd.scid.u64);
	if (ret)
		return ret;

	/* short_channel_ids are equal */
	ret = cmp_u64(A->timestamp, B->timestamp);
	if (ret)
		return ret;

	/* also timestamps are equal */
	return cmp_u64(A->index, B->index);
}

/* Get an existing bound entry or create a new one. */
static struct channel_bounds *fetch_bounds(const tal_t *ctx,
					   struct channel_bounds_htable *htable,
					   const struct gossmap *gossmap,
					   struct short_channel_id scid)
{
	const struct gossmap_chan *chan;
	struct channel_bounds *bounds;
	bounds = channel_bounds_htable_get(htable, scid);
	if (!bounds) {
		chan = gossmap_find_chan(gossmap, &scid);
		if (!chan)
			/* We might have intel about a channel
			 * that we no longer have in gossmap, we
			 * skip those. */
			return NULL;

		bounds = tal(ctx, struct channel_bounds);
		bounds->scid = scid;
		bounds->capacity = gossmap_chan_get_capacity(gossmap, chan);

		bounds->half[0].layer = NULL;
		bounds->half[0].min = AMOUNT_MSAT(0);
		bounds->half[0].max = bounds->capacity;

		bounds->half[1].layer = NULL;
		bounds->half[1].min = AMOUNT_MSAT(0);
		bounds->half[1].max = bounds->capacity;

		channel_bounds_htable_add(htable, bounds);
	}
	return bounds;
}

static void update_bound_from_intel(struct channel_bounds *bounds,
				    const struct channel_intel_out *intel)
{
	struct amount_msat current_imp;
	int dir;

	dir = intel->scidd.dir;

	/* Naive implementation! */
	if (intel->is_impression) {
		return;
	} else {
		bounds->half[dir].min = amount_msat_max(
		    bounds->half[dir].min, intel->value.min_max.min);

		if (amount_msat_greater(bounds->half[dir].max,
					intel->value.min_max.max)) {
			bounds->half[dir].max = intel->value.min_max.max;
			bounds->half[dir].layer = intel->layer;
		}
	}
}

static void update_bounds_htlc_forwarded(struct channel_bounds *bounds,
					 int dir,
					 struct amount_msat amount)
{
	// FIXME: was this an expected event?
	struct amount_msat reserves;

	/* same dir */
	if(!amount_msat_deduct(&bounds->half[dir].max, amount))
		bounds->half[dir].max = AMOUNT_MSAT(0);
	if(!amount_msat_deduct(&bounds->half[dir].min, amount))
		bounds->half[dir].min = AMOUNT_MSAT(0);

	/* opposite dir, be a bit more pessimistic because the amount could have
	 * gone into reserves */
	/* skin-in-the-game reserves, assumed at 1% of the capacity */
	if(!amount_msat_scale(&reserves, bounds->capacity, 0.01))
		reserves = AMOUNT_MSAT(0);
	if (!amount_msat_deduct(&amount, reserves))
		return;

	if (!amount_msat_accumulate(&bounds->half[!dir].max, amount))
		bounds->half[!dir].max = bounds->capacity;
	if (!amount_msat_accumulate(&bounds->half[!dir].min, amount))
		bounds->half[!dir].min = bounds->capacity;
}

static void update_bounds_htlc_failed(struct channel_bounds *bounds,
				      int dir,
				      struct amount_msat amount)
{
	double prob_fail;
	struct amount_msat high, amount_minus_1;

	if (!amount_msat_sub(&amount_minus_1, amount, AMOUNT_MSAT(1)))
		amount_minus_1 = AMOUNT_MSAT(0);

	/* same dir */

	/* was this an expected event? */
	if(amount_msat_greater(amount, bounds->half[dir].max)) {
		/* Trivial case, we were expecting it to fail. */
	} else if(amount_msat_less(amount, bounds->half[dir].min)){
		/* This should have succeeded 100% of the times,
		 * our knowledge was plain wrong. */
		bounds->half[dir].min =
		    amount_msat_min(amount_minus_1, bounds->half[dir].min);
		bounds->half[dir].max =
		    amount_msat_min(amount_minus_1, bounds->half[dir].max);
		if (!amount_msat_scale(&bounds->half[dir].min,
				       bounds->half[dir].min,
				       1.0 - ASKRENE_FAILURE_RELAX_FRACTION))
			bounds->half[dir].min = AMOUNT_MSAT(0);
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
		if (!amount_msat_add(&high, bounds->half[dir].max,
				     AMOUNT_MSAT(1)))
			high = bounds->capacity;
		prob_fail = 1.0 - pickhardt_richter_probability(
				      bounds->half[dir].min, high, amount);
		assert(prob_fail >= 0 && prob_fail <= 1.0);

		bounds->half[dir].max =
		    amount_msat_min(bounds->half[dir].max, amount_minus_1);
		if (!amount_msat_scale(&bounds->half[dir].min,
					bounds->half[dir].min,
				       1.0 + ASKRENE_FAILURE_RELAX_FRACTION *
						 (prob_fail - 1.0)))
			bounds->half[dir].min = AMOUNT_MSAT(0);
	}

	/* skip the opposite dir, be pessimistic, the forward direction refusing
	 * to send the payment doesn't necessarily mean that the funds are on
	 * the other side */

}

static void update_bounds_htlc_accepted(struct channel_bounds *bounds,
					int dir,
					struct amount_msat amount)
{
	// FIXME: was this an expected event?

	/* same dir */
	bounds->half[dir].min = amount_msat_max(amount, bounds->half[dir].min);
	bounds->half[dir].max = amount_msat_max(amount, bounds->half[dir].max);

	/* opposite dir */
	if(!amount_msat_sub(&amount, bounds->capacity, amount))
		amount = AMOUNT_MSAT(0);

	bounds->half[!dir].min = amount_msat_min(amount, bounds->half[!dir].min);
	bounds->half[!dir].max = amount_msat_min(amount, bounds->half[!dir].max);
}

static void update_bound_from_observation(struct channel_bounds *bounds,
					  const struct channel_observation_out *observation)
{
	struct amount_msat current_amt;
	int dir;

	dir = observation->scidd.dir;
	current_amt = observation->amount;

	switch (observation->result) {
	case OBSERVATION_HTLC_FAILED:
		update_bounds_htlc_failed(bounds, dir, current_amt);
		break;

	case OBSERVATION_HTLC_ACCEPTED:
		update_bounds_htlc_accepted(bounds, dir, current_amt);
		break;

	case OBSERVATION_HTLC_FORWARDED:
		update_bounds_htlc_forwarded(bounds, dir, current_amt);
		break;
	}
}

/* Compute the bounds that apply to every channel for which we have some
 * knowledge. */
static void precompute_bounds(struct route_query *rq)
{
	struct channel_intel_out *all_intels =
	    tal_arr(rq, struct channel_intel_out, 0);
	struct channel_observation_out *all_observations =
	    tal_arr(rq, struct channel_observation_out, 0);

	const struct channel_intel_out *intel;
	const struct channel_observation_out *observation;
	struct short_channel_id scid;
	struct channel_bounds *bounds = NULL;

	for (size_t i = 0; i < tal_count(rq->layers); i++) {
		layer_get_intels(rq->layers[i], &all_intels);
		layer_get_observations(rq->layers[i], &all_observations);
	}

	for (size_t i = 0; i < tal_count(all_intels); i++) {
		all_intels[i].index = i;
		all_observations[i].index = i;
	}

	asort(all_intels, tal_count(all_intels), cmp_channel_intel, NULL);
	asort(all_observations, tal_count(all_observations),
	      cmp_channel_observation, NULL);

	/* Update bounds from observations. These are flexible. */
	for (size_t i = 0; i < tal_count(all_observations); i++) {
		observation = &all_observations[i];
		scid = observation->scidd.scid;

		/* instead of fetching everytime from the hash table, we keep a
		 * copy of the pointer */
		if (bounds == NULL || !channel_bounds_eq(bounds, scid)) {
			/* we need to pull it out of the table or create a fresh
			 * one */
			bounds = fetch_bounds(rq, rq->bounds_htable,
					      rq->gossmap, scid);
		}

		if (bounds == NULL)
			continue;

		update_bound_from_observation(bounds, observation);
	}

	/* After observations we enforce hard bounds from constraints. */
	for (size_t i = 0; i < tal_count(all_intels); i++) {
		intel = &all_intels[i];
		scid = intel->scidd.scid;

		/* instead of fetching everytime from the hash table, we keep a
		 * copy of the pointer */
		if (bounds == NULL || !channel_bounds_eq(bounds, scid)) {
			/* we need to pull it out of the table or create a fresh
			 * one */
			bounds = fetch_bounds(rq, rq->bounds_htable,
					      rq->gossmap, scid);
		}

		if (bounds == NULL)
			continue;

		update_bound_from_intel(bounds, intel);
	}

	tal_free(all_intels);
	tal_free(all_observations);
}

struct route_query *new_route_query(const tal_t *ctx,
				    const struct gossmap *gossmap,
				    const char *cmd_id,
				    const struct layer **layers,
				    const s8 *biases,
				    const struct additional_cost_htable *additional_costs,
				    struct reserve_htable *reserved,
				    fp16_t *capacities TAKES)
{
	struct route_query *rq = tal(ctx, struct route_query);

	rq->gossmap = gossmap;
	rq->cmd_id = tal_strdup(rq, cmd_id);
	rq->layers = layers;
	rq->biases = biases;
	rq->additional_costs = additional_costs;
	rq->reserved = reserved;
	rq->capacities = tal_dup_talarr(rq, fp16_t, capacities);
	rq->disabled_chans =
	    tal_arrz(rq, bitmap,
		     2 * BITMAP_NWORDS(gossmap_max_chan_idx(gossmap)));
	rq->bounds_htable = new_htable(rq, channel_bounds_htable);

	precompute_bounds(rq);
	return rq;
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

bool get_layer_bounds(const struct route_query *rq,
		      const struct short_channel_id_dir *scidd,
		      struct amount_msat *min,
		      struct amount_msat *max,
		      const struct layer **layer)
{
	const struct channel_bounds *bounds;

	bounds = channel_bounds_htable_get(rq->bounds_htable, scidd->scid);
	if (!bounds)
		return false;

	*min = bounds->half[scidd->dir].min;
	*max = bounds->half[scidd->dir].max;
	*layer = bounds->half[scidd->dir].layer;
	return true;
}

void get_constraints(const struct route_query *rq,
		     const struct gossmap_chan *chan,
		     int dir,
		     struct amount_msat *min,
		     struct amount_msat *max)
{
	struct short_channel_id_dir scidd;
	size_t idx = gossmap_chan_idx(rq->gossmap, chan);
	struct channel_bounds *bounds;

	/* Fast path: no information known, no reserve. */
	if (idx < tal_count(rq->capacities) && rq->capacities[idx] != 0) {
		*min = AMOUNT_MSAT(0);
		*max = amount_msat(fp16_to_u64(rq->capacities[idx]) * 1000);
		return;
	}

	scidd.scid = gossmap_chan_scid(rq->gossmap, chan);
	scidd.dir = dir;

	bounds = channel_bounds_htable_get(rq->bounds_htable, scidd.scid);
	if (bounds) {
		*min = bounds->half[dir].min;
		*max = bounds->half[dir].max;
	} else {
		/* No layer information but maybe some reserves. */
		*min = AMOUNT_MSAT(0);
		*max = gossmap_chan_get_capacity(rq->gossmap, chan);
	}

	/* Finally, if any is in use, subtract that! */
	reserve_sub(rq->reserved, &scidd, rq->layers, min);
	reserve_sub(rq->reserved, &scidd, rq->layers, max);
}
