#include "config.h"
#include <bitcoin/short_channel_id.h>
#include <ccan/asort/asort.h>
#include <ccan/tal/str/str.h>
#include <common/gossmap.h>
#include <common/memleak.h>
#include <plugins/askrene/child/additional_costs.h>
#include <plugins/askrene/child/route_query.h>
#include <plugins/askrene/layer.h>
#include <plugins/askrene/reserve.h>

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
		current_imp = intel->value.impression;

		/* We made payment along this channel?  Capacity has
		 * reduced */
		if (!amount_msat_sub(&bounds->half[dir].min,
				     bounds->half[dir].min, current_imp))
			bounds->half[dir].min = AMOUNT_MSAT(0);
		if (!amount_msat_sub(&bounds->half[dir].max,
				     bounds->half[dir].max, current_imp))
			bounds->half[dir].max = AMOUNT_MSAT(0);

		/* We made the other way?  Capacity has increased */
		if (!amount_msat_add(&bounds->half[!dir].min,
				     bounds->half[!dir].min, current_imp))
			bounds->half[!dir].min = AMOUNT_MSAT(-1ULL);
		if (!amount_msat_add(&bounds->half[!dir].max,
				     bounds->half[!dir].max, current_imp))
			bounds->half[!dir].max = AMOUNT_MSAT(-1ULL);
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

/* Compute the bounds that apply to every channel for which we have some
 * knowledge. */
static void precompute_bounds(struct route_query *rq)
{
	struct channel_intel_out *all_intels =
	    tal_arr(rq, struct channel_intel_out, 0);
	const struct channel_intel_out *intel;
	struct short_channel_id scid;
	struct channel_bounds *bounds = NULL;

	for (size_t i = 0; i < tal_count(rq->layers); i++)
		layer_get_intels(rq->layers[i], &all_intels);

	for (size_t i = 0; i < tal_count(all_intels); i++)
		all_intels[i].index = i;

	asort(all_intels, tal_count(all_intels), cmp_channel_intel, NULL);

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
