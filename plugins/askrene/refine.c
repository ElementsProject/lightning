#include "config.h"
#include <ccan/asort/asort.h>
#include <ccan/tal/str/str.h>
#include <common/gossmap.h>
#include <plugins/askrene/askrene.h>
#include <plugins/askrene/flow.h>
#include <plugins/askrene/refine.h>
#include <plugins/askrene/reserve.h>
#include <string.h>

/* Channel data for fast retrieval. */
struct channel_data {
	struct amount_msat htlc_min, htlc_max, liquidity_max;
	u32 fee_base_msat, fee_proportional_millionths;
	struct short_channel_id_dir scidd;
	u32 idx;
};

/* We (ab)use the reservation system to place temporary reservations
 * on channels while we are refining each flow.  This has the effect
 * of making flows aware of each other. */

/* Get the scidd for the i'th hop in flow */
static void get_scidd(const struct gossmap *gossmap,
		      const struct flow *flow,
		      size_t i,
		      struct short_channel_id_dir *scidd)
{
	scidd->scid = gossmap_chan_scid(gossmap, flow->path[i]);
	scidd->dir = flow->dirs[i];
}

static void destroy_reservations(struct reserve_hop *rhops, struct askrene *askrene)
{
	for (size_t i = 0; i < tal_count(rhops); i++)
		reserve_remove(askrene->reserved, &rhops[i]);
}

struct reserve_hop *new_reservations(const tal_t *ctx,
				     const struct route_query *rq)
{
	struct reserve_hop *rhops = tal_arr(ctx, struct reserve_hop, 0);

	/* Unreserve on free */
	tal_add_destructor2(rhops, destroy_reservations, get_askrene(rq->plugin));
	return rhops;
}

static struct reserve_hop *find_reservation(struct reserve_hop *rhops,
					    const struct short_channel_id_dir *scidd)
{
	for (size_t i = 0; i < tal_count(rhops); i++) {
		if (short_channel_id_dir_eq(scidd, &rhops[i].scidd))
			return &rhops[i];
	}
	return NULL;
}

/* Add/update reservation: we (ab)use this to temporarily avoid over-usage as
 * we refine. */
static void add_reservation(struct reserve_hop **reservations,
			    const struct route_query *rq,
			    const struct gossmap_chan *chan,
			    const struct short_channel_id_dir *scidd,
			    struct amount_msat amt)
{
	struct reserve_hop rhop, *prev;
	struct askrene *askrene = get_askrene(rq->plugin);
	size_t idx;

	/* Update in-place if possible */
	prev = find_reservation(*reservations, scidd);
	if (prev) {
		reserve_remove(askrene->reserved, prev);
		if (!amount_msat_accumulate(&prev->amount, amt))
			abort();
		reserve_add(askrene->reserved, prev, rq->cmd->id);
		return;
	}
	rhop.scidd = *scidd;
	rhop.amount = amt;
	reserve_add(askrene->reserved, &rhop, rq->cmd->id);

	/* Set capacities entry to 0 so it get_constraints() looks in reserve. */
	idx = gossmap_chan_idx(rq->gossmap, chan);
	if (idx < tal_count(rq->capacities))
		rq->capacities[idx] = 0;

	/* Record so destructor will unreserve */
	tal_arr_expand(reservations, rhop);
}

void create_flow_reservations(const struct route_query *rq,
			      struct reserve_hop **reservations,
			      const struct flow *flow)
{
	struct amount_msat msat;

	msat = flow->delivers;
	for (int i = tal_count(flow->path) - 1; i >= 0; i--) {
		const struct half_chan *h = flow_edge(flow, i);
		struct amount_msat amount_to_reserve;
		struct short_channel_id_dir scidd;

		get_scidd(rq->gossmap, flow, i, &scidd);

		/* Reserve more for local channels if it reduces capacity */
		if (!amount_msat_add(&amount_to_reserve, msat,
				     get_additional_per_htlc_cost(rq, &scidd)))
			abort();

		add_reservation(reservations, rq, flow->path[i], &scidd,
				amount_to_reserve);
		if (!amount_msat_add_fee(&msat,
					 h->base_fee, h->proportional_fee))
			plugin_err(rq->plugin, "Adding fee to amount");
	}
}

bool create_flow_reservations_verify(const struct route_query *rq,
				     struct reserve_hop **reservations,
				     const struct flow *flow)
{
	struct amount_msat msat;
	msat = flow->delivers;
	for (int i = tal_count(flow->path) - 1; i >= 0; i--) {
		struct amount_msat known_min, known_max;
		const struct half_chan *h = flow_edge(flow, i);
		struct amount_msat amount_to_reserve = msat;
		struct short_channel_id_dir scidd;

		get_scidd(rq->gossmap, flow, i, &scidd);
		get_constraints(rq, flow->path[i], flow->dirs[i], &known_min,
				&known_max);
		if (amount_msat_greater(amount_to_reserve, known_max))
			return false;

		if (!amount_msat_add_fee(&msat, h->base_fee,
					 h->proportional_fee))
			abort();
	}
	create_flow_reservations(rq, reservations, flow);
	return true;
}

/* We use an fp16_t approximatin for htlc_max/min: this gets the exact value. */
static struct amount_msat get_chan_htlc_max(const struct route_query *rq,
					    const struct gossmap_chan *c,
					    const struct short_channel_id_dir *scidd)
{
	struct amount_msat htlc_max;

	gossmap_chan_get_update_details(rq->gossmap,
					c, scidd->dir,
					NULL, NULL, NULL, NULL, NULL, NULL,
					NULL, &htlc_max);
	return htlc_max;
}

static struct amount_msat get_chan_htlc_min(const struct route_query *rq,
					    const struct gossmap_chan *c,
					    const struct short_channel_id_dir *scidd)
{
	struct amount_msat htlc_min;

	gossmap_chan_get_update_details(rq->gossmap,
					c, scidd->dir,
					NULL, NULL, NULL, NULL, NULL, NULL,
					&htlc_min, NULL);
	return htlc_min;
}

enum why_capped {
	CAPPED_HTLC_MAX,
	CAPPED_CAPACITY,
};

/* Cache channel data along the path used by this flow. */
static struct channel_data *new_channel_path_cache(const tal_t *ctx,
						   struct route_query *rq,
						   struct flow *flow)
{
	const size_t pathlen = tal_count(flow->path);
	struct channel_data *path = tal_arr(ctx, struct channel_data, pathlen);

	for (size_t i = 0; i < pathlen; i++) {
		/* knowledge on liquidity bounds */
		struct amount_msat known_min, known_max;
		const struct half_chan *h = flow_edge(flow, i);
		struct short_channel_id_dir scidd;

		get_scidd(rq->gossmap, flow, i, &scidd);
		get_constraints(rq, flow->path[i], flow->dirs[i], &known_min,
				&known_max);

		path[i].htlc_min = get_chan_htlc_min(rq, flow->path[i], &scidd);
		path[i].htlc_max = get_chan_htlc_max(rq, flow->path[i], &scidd);
		path[i].fee_base_msat = h->base_fee;
		path[i].fee_proportional_millionths = h->proportional_fee;
		path[i].liquidity_max = known_max;
		path[i].scidd = scidd;
		path[i].idx = scidd.dir +
			      2 * gossmap_chan_idx(rq->gossmap, flow->path[i]);
	}
	return path;
}

/* Cache channel data along multiple paths. */
static struct channel_data **new_channel_mpp_cache(const tal_t *ctx,
						   struct route_query *rq,
						   struct flow **flows)
{
	const size_t npaths = tal_count(flows);
	struct channel_data **paths =
	    tal_arr(ctx, struct channel_data *, npaths);
	for (size_t i = 0; i < npaths; i++) {
		paths[i] = new_channel_path_cache(paths, rq, flows[i]);
	}
	return paths;
}

/* Reverse order: bigger first */
static int revcmp_flows(const size_t *a, const size_t *b, struct flow **flows)
{
	if (amount_msat_eq(flows[*a]->delivers, flows[*b]->delivers))
		return 0;
	if (amount_msat_greater(flows[*a]->delivers, flows[*b]->delivers))
		return -1;
	return 1;
}

// TODO: unit test:
//      -> make a path
//      -> compute x = path_max_deliverable
//      -> check that htlc_max are all satisfied
//      -> check that (x+1) at least one htlc_max is violated
/* Given the channel constraints, return the maximum amount that can be
 * delivered.  Sets *bottleneck_idx to one of the contraining channels' idx, if non-NULL */
static struct amount_msat path_max_deliverable(struct channel_data *path,
					       u32 *bottleneck_idx)
{
	struct amount_msat deliver = AMOUNT_MSAT(-1);
	for (size_t i = 0; i < tal_count(path); i++) {
		deliver =
		    amount_msat_sub_fee(deliver, path[i].fee_base_msat,
					path[i].fee_proportional_millionths);
		if (amount_msat_greater(deliver, path[i].htlc_max)) {
			if (bottleneck_idx)
				*bottleneck_idx = path[i].idx;
			deliver = path[i].htlc_max;
		}
		if (amount_msat_greater(deliver, path[i].liquidity_max)) {
			if (bottleneck_idx)
				*bottleneck_idx = path[i].idx;
			deliver = path[i].liquidity_max;
		}
	}
	return deliver;
}

// TODO: unit test:
//      -> make a path
//      -> compute x = path_min_deliverable
//      -> check that htlc_min are all satisfied
//      -> check that (x-1) at least one htlc_min is violated
/* The least amount that we can deliver at the destination such that when one
 * computes the hop amounts backwards the htlc_min are always met. */
static struct amount_msat path_min_deliverable(struct channel_data *path)
{
	struct amount_msat least_send = AMOUNT_MSAT(1);
	const size_t pathlen = tal_count(path);
	for (size_t i = pathlen - 1; i < pathlen; i--) {
		least_send = amount_msat_max(least_send, path[i].htlc_min);
		if (!amount_msat_add_fee(&least_send, path[i].fee_base_msat,
					 path[i].fee_proportional_millionths))
			abort();
	}
	/* least_send: is the least amount we can send in order to deliver at
	 * least 1 msat at the destination. */
	struct amount_msat least_destination = least_send;
	for (size_t i = 0; i < pathlen; i++) {
		struct amount_msat in_value = least_destination;
		struct amount_msat out_value =
		    amount_msat_sub_fee(in_value, path[i].fee_base_msat,
					path[i].fee_proportional_millionths);
		assert(amount_msat_greater_eq(out_value, path[i].htlc_min));
		struct amount_msat x = out_value;
		if (!amount_msat_add_fee(&x, path[i].fee_base_msat,
					 path[i].fee_proportional_millionths))
			abort();
		/* if the in_value computed from the out_value is smaller than
		 * it should, then we add 1msat */
		if (amount_msat_less(x, in_value) &&
		    !amount_msat_accumulate(&out_value, AMOUNT_MSAT(1)))
			abort();
		/* check conditions */
		assert(amount_msat_greater_eq(out_value, path[i].htlc_min));
		x = out_value;
		assert(
		    amount_msat_add_fee(&x, path[i].fee_base_msat,
					path[i].fee_proportional_millionths) &&
		    amount_msat_greater_eq(x, in_value));
		least_destination = out_value;
	}
	return least_destination;
}

static const char *
remove_htlc_min_violations(const tal_t *ctx, struct route_query *rq,
			   const struct flow *flow,
			   const struct channel_data *channels)
{
	const char *error_message = NULL;
	struct amount_msat msat = flow->delivers;
	for (size_t i = tal_count(flow->path) - 1; i < tal_count(flow->path);
	     i--) {
		if (amount_msat_less(msat, channels[i].htlc_min)) {
			rq_log(
			    ctx, rq, LOG_INFORM,
			    "Sending %s across %s would violate htlc_min "
			    "(~%s), disabling this channel",
			    fmt_amount_msat(ctx, msat),
			    fmt_short_channel_id_dir(ctx, &channels[i].scidd),
			    fmt_amount_msat(ctx, channels[i].htlc_min));
			bitmap_set_bit(rq->disabled_chans, channels[i].idx);
			break;
		}
		if (!amount_msat_add_fee(
			&msat, channels[i].fee_base_msat,
			channels[i].fee_proportional_millionths)) {
			error_message =
			    rq_log(ctx, rq, LOG_BROKEN,
				   "%s: Adding fee to amount", __func__);
			break;
		}
	}
	return error_message;
}

static struct amount_msat sum_all_deliver(struct flow **flows,
					  size_t *flows_index)
{
	struct amount_msat all_deliver = AMOUNT_MSAT(0);
	for (size_t i = 0; i < tal_count(flows_index); i++) {
		if (!amount_msat_accumulate(&all_deliver,
					    flows[flows_index[i]]->delivers))
			abort();
	}
	return all_deliver;
}

/* It reduces the amount of the flows and/or removes some flows in order to
 * deliver no more than max_deliver. It will leave at least one flow.
 * Returns the total delivery amount. */
static struct amount_msat remove_excess(struct flow **flows,
					size_t **flows_index,
					struct amount_msat max_deliver)
{
	if (tal_count(flows) == 0)
		return AMOUNT_MSAT(0);

	struct amount_msat all_deliver, excess;
	all_deliver = sum_all_deliver(flows, *flows_index);

	/* early exit: there is no excess */
	if (!amount_msat_sub(&excess, all_deliver, max_deliver) ||
	    amount_msat_is_zero(excess))
		return all_deliver;

	asort(*flows_index, tal_count(*flows_index), revcmp_flows, flows);

	/* Remove the smaller parts if they deliver less than the
	 * excess.  */
	for (int i = tal_count(*flows_index) - 1; i >= 0; i--) {
		if (!amount_msat_sub(&excess, excess,
				     flows[(*flows_index)[i]]->delivers))
			break;
		if (!amount_msat_sub(&all_deliver, all_deliver,
				     flows[(*flows_index)[i]]->delivers))
			abort();
		tal_arr_remove(flows_index, i);
	}

	/* If we still have some excess, remove it from the
	 * current flows in the same proportion every flow contributes to the
	 * total. */
	struct amount_msat old_excess = excess;
	struct amount_msat old_deliver = all_deliver;
	for (size_t i = 0; i < tal_count(*flows_index); i++) {
		double fraction = amount_msat_ratio(
		    flows[(*flows_index)[i]]->delivers, old_deliver);
		struct amount_msat remove;

		if (!amount_msat_scale(&remove, old_excess, fraction))
			abort();

		/* rounding errors: don't remove more than excess */
		remove = amount_msat_min(remove, excess);

		if (!amount_msat_sub(&excess, excess, remove))
			abort();

		if (!amount_msat_sub(&all_deliver, all_deliver, remove) ||
		    !amount_msat_sub(&flows[(*flows_index)[i]]->delivers,
				     flows[(*flows_index)[i]]->delivers,
				     remove))
			abort();
	}

	/* any rounding error left, take it from the first */
	assert(tal_count(*flows_index) > 0);
	if (!amount_msat_sub(&all_deliver, all_deliver, excess) ||
	    !amount_msat_sub(&flows[(*flows_index)[0]]->delivers,
			     flows[(*flows_index)[0]]->delivers, excess))
		abort();
	return all_deliver;
}

/* It increases the flows to meet the deliver target. It does not increase any
 * flow beyond the tolerance fraction. It doesn't increase any flow above its
 * max_deliverable value.
 * Returns the total delivery amount. */
static struct amount_msat increase_flows(struct flow **flows,
					 size_t **flows_index,
					 struct amount_msat deliver,
					 double tolerance,
					 struct amount_msat *max_deliverable)
{
	if (tal_count(flows) == 0)
		return AMOUNT_MSAT(0);

	struct amount_msat all_deliver, defect;
	all_deliver = sum_all_deliver(flows, *flows_index);

	/* early exit: target is already met */
	if (!amount_msat_sub(&defect, deliver, all_deliver) ||
	    amount_msat_is_zero(defect))
		return all_deliver;

	asort(*flows_index, tal_count(*flows_index), revcmp_flows, flows);

	all_deliver = AMOUNT_MSAT(0);
	for (size_t i = 0;
	     i < tal_count(*flows_index) && !amount_msat_is_zero(defect); i++) {
		const size_t index = (*flows_index)[i];
		struct flow *flow = flows[index];
		struct amount_msat can_add = defect, amt;

		/* no more than tolerance */
		if (!amount_msat_scale(&amt, flow->delivers, tolerance))
			continue;
		else
			can_add = amount_msat_min(can_add, amt);

		/* no more than max_deliverable */
		if (!amount_msat_sub(&amt, max_deliverable[index],
				     flow->delivers))
			continue;
		else
			can_add = amount_msat_min(can_add, amt);

		if (!amount_msat_add(&flow->delivers, flow->delivers,
				     can_add) ||
		    !amount_msat_sub(&defect, defect, can_add) ||
		    !amount_msat_accumulate(&all_deliver, flow->delivers))
			abort();
	}
	return all_deliver;
}

static void write_selected_flows(const tal_t *ctx, size_t *flows_index,
				 struct flow ***flows)
{
	struct flow **tmp_flows = tal_arr(ctx, struct flow *, 0);
	for (size_t i = 0; i < tal_count(flows_index); i++) {
		tal_arr_expand(&tmp_flows, (*flows)[flows_index[i]]);
		(*flows)[flows_index[i]] = NULL;
	}
	for (size_t i = 0; i < tal_count(*flows); i++) {
		(*flows)[i] = tal_free((*flows)[i]);
	}
	tal_resize(flows, 0);
	for (size_t i = 0; i < tal_count(tmp_flows); i++) {
		tal_arr_expand(flows, tmp_flows[i]);
	}
	tal_free(tmp_flows);
}

const char *refine_flows(const tal_t *ctx, struct route_query *rq,
			 struct amount_msat deliver, struct flow ***flows,
			 u32 *bottleneck_idx)
{
	const tal_t *working_ctx = tal(ctx, tal_t);
	const char *error_message = NULL;
	struct amount_msat *max_deliverable;
	struct amount_msat *min_deliverable;
	struct channel_data **channel_mpp_cache;
	size_t *flows_index;

	/* we might need to access this data multiple times, so we cache
	 * it */
	channel_mpp_cache = new_channel_mpp_cache(working_ctx, rq, *flows);
	max_deliverable = tal_arrz(working_ctx, struct amount_msat,
				   tal_count(channel_mpp_cache));
	min_deliverable = tal_arrz(working_ctx, struct amount_msat,
				   tal_count(channel_mpp_cache));
	flows_index = tal_arrz(working_ctx, size_t, tal_count(*flows));
	for (size_t i = 0; i < tal_count(channel_mpp_cache); i++) {
		// FIXME: does path_max_deliverable work for a single
		// channel with 0 fees?
		max_deliverable[i] = path_max_deliverable(channel_mpp_cache[i], bottleneck_idx);
		min_deliverable[i] = path_min_deliverable(channel_mpp_cache[i]);
		/* We use an array of indexes to keep track of the order
		 * of the flows. Likewise flows can be removed by simply
		 * shrinking the flows_index array. */
		flows_index[i] = i;
	}

	/* do not deliver more than HTLC_MAX allow us */
	for (size_t i = 0; i < tal_count(flows_index); i++) {
		(*flows)[flows_index[i]]->delivers =
		    amount_msat_min((*flows)[flows_index[i]]->delivers,
				    max_deliverable[flows_index[i]]);
	}

	/* remove excess from MCF granularity if any */
	remove_excess(*flows, &flows_index, deliver);

	/* increase flows if necessary to meet the target */
	increase_flows(*flows, &flows_index, deliver, /* tolerance = */ 0.02,
		       max_deliverable);

	/* detect htlc_min violations */
	for (size_t i = 0; i < tal_count(flows_index);) {
		size_t k = flows_index[i];
		if (amount_msat_greater_eq((*flows)[k]->delivers,
					   min_deliverable[k])) {
			i++;
			continue;
		}
		/* htlc_min is not met for this flow */
		tal_arr_remove(&flows_index, i);
		error_message = remove_htlc_min_violations(
		    working_ctx, rq, (*flows)[k], channel_mpp_cache[k]);
		if (error_message)
			goto fail;
	}

	/* remove 0 amount flows if any */
	asort(flows_index, tal_count(flows_index), revcmp_flows, *flows);
	for (int i = tal_count(flows_index) - 1; i >= 0; i--) {
		if (!amount_msat_is_zero((*flows)[flows_index[i]]->delivers))
			break;
		tal_arr_remove(&flows_index, i);
	}

	/* finally write the remaining flows */
	write_selected_flows(working_ctx, flows_index, flows);

	tal_free(working_ctx);
	return NULL;

fail:
	tal_free(working_ctx);
	return error_message;
}

/* Order of flows according to path string */
static int cmppath_flows(const size_t *a, const size_t *b, char **paths_str)
{
	return strcmp(paths_str[*a], paths_str[*b]);
}

void squash_flows(const tal_t *ctx, struct route_query *rq,
		  struct flow ***flows)
{
	const tal_t *working_ctx = tal(ctx, tal_t);
	size_t *flows_index = tal_arrz(working_ctx, size_t, tal_count(*flows));
	char **paths_str = tal_arrz(working_ctx, char *, tal_count(*flows));
	struct channel_data **channel_mpp_cache =
	    new_channel_mpp_cache(working_ctx, rq, *flows);
	struct amount_msat *max_deliverable = tal_arrz(
	    working_ctx, struct amount_msat, tal_count(channel_mpp_cache));

	for (size_t i = 0; i < tal_count(flows_index); i++) {
		struct flow *flow = (*flows)[i];
		struct short_channel_id_dir scidd;
		flows_index[i] = i;
		paths_str[i] = tal_strdup(working_ctx, "");
		max_deliverable[i] = path_max_deliverable(channel_mpp_cache[i], NULL);

		for (size_t j = 0; j < tal_count(flow->path); j++) {
			scidd.scid =
			    gossmap_chan_scid(rq->gossmap, flow->path[j]);
			scidd.dir = flow->dirs[j];
			tal_append_fmt(
			    &paths_str[i], "%s%s", j > 0 ? "->" : "",
			    fmt_short_channel_id_dir(working_ctx, &scidd));
		}
	}

	asort(flows_index, tal_count(flows_index), cmppath_flows, paths_str);
	for (size_t i = 0; i < tal_count(flows_index); i++) {
		const size_t j = i + 1;
		struct amount_msat combined;
		struct amount_msat max = max_deliverable[flows_index[i]];

		/* same path? We merge */
		while (j < tal_count(flows_index) &&
		       cmppath_flows(&flows_index[i],
				     &flows_index[j],
                                     paths_str) == 0) {
			if (!amount_msat_add(
				&combined, (*flows)[flows_index[i]]->delivers,
				(*flows)[flows_index[j]]->delivers))
				abort();
			/* do we break any HTLC max limits */
			if (amount_msat_greater(combined, max))
				break;
			(*flows)[flows_index[i]]->delivers = combined;
			tal_arr_remove(&flows_index, j);
		}
	}

	write_selected_flows(working_ctx, flows_index, flows);

	tal_free(working_ctx);
}

double flows_probability(const tal_t *ctx, struct route_query *rq,
			 struct flow ***flows)
{
	const tal_t *working_ctx = tal(ctx, tal_t);
	struct reserve_hop *reservations = new_reservations(working_ctx, rq);
	double probability = 1.0;

	for (size_t i = 0; i < tal_count(*flows); i++) {
		probability *= flow_probability((*flows)[i], rq);
		create_flow_reservations(rq, &reservations, (*flows)[i]);
	}
	tal_free(working_ctx);
	return probability;
}

/* Compare flows by deliver amount */
static int reverse_cmp_flows(struct flow *const *fa, struct flow *const *fb,
			     void *unused UNUSED)
{
	if (amount_msat_eq((*fa)->delivers, (*fb)->delivers))
		return 0;
	if (amount_msat_greater((*fa)->delivers, (*fb)->delivers))
		return -1;
	return 1;
}

bool remove_flows(struct flow ***flows, u32 n)
{
	if (n == 0)
		goto fail;
	if (n > tal_count(*flows))
		goto fail;
	asort(*flows, tal_count(*flows), reverse_cmp_flows, NULL);
	for (size_t count = tal_count(*flows); n > 0; n--, count--) {
		assert(count > 0);
		tal_arr_remove(flows, count - 1);
	}
	return true;
fail:
	return false;
}
