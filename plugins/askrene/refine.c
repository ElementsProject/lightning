#include "config.h"
#include <ccan/tal/str/str.h>
#include <common/gossmap.h>
#include <plugins/askrene/askrene.h>
#include <plugins/askrene/flow.h>
#include <plugins/askrene/refine.h>
#include <plugins/askrene/reserve.h>

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

static struct reserve_hop *new_reservations(const tal_t *ctx,
					    const struct route_query *rq)
{
	struct reserve_hop *rhops = tal_arr(ctx, struct reserve_hop, 0);

	/* Unreserve on free */
	tal_add_destructor2(rhops, destroy_reservations, get_askrene(rq->plugin));
	return rhops;
}

/* Add reservation: we (ab)use this to temporarily avoid over-usage as
 * we refine. */
static void add_reservation(struct reserve_hop **reservations,
			    struct route_query *rq,
			    const struct flow *flow,
			    size_t i,
			    struct amount_msat amt)
{
	struct reserve_hop rhop;
	struct askrene *askrene = get_askrene(rq->plugin);
	size_t idx;

	get_scidd(rq->gossmap, flow, i, &rhop.scidd);
	rhop.amount = amt;

	reserve_add(askrene->reserved, &rhop, rq->cmd->id);

	/* Set capacities entry to 0 so it get_constraints() looks in reserve. */
	idx = gossmap_chan_idx(rq->gossmap, flow->path[i]);
	if (idx < tal_count(rq->capacities))
		rq->capacities[idx] = 0;

	/* Record so destructor will unreserve */
	tal_arr_expand(reservations, rhop);
}

/* We have a basic set of flows, but we need to add fees, and take into
 * account that "spendable" estimates are for a single HTLC.  This can
 * push us again over capacity or htlc_maximum_msat.
 *
 * We may have to reduce the flow amount in response to these.
 *
 * We also check for going below htlc_maximum_msat at this point: this
 * is unusual and means it's small, so we just remove that flow if
 * this happens, as we can make it up by buffing up the other flows
 * (or, it's simply impossible).
 */
static const char *constrain_flow(const tal_t *ctx,
				  struct route_query *rq,
				  struct flow *flow,
				  struct reserve_hop **reservations)
{
	struct amount_msat msat;
	int decreased = -1;
	const char *why_decreased = NULL;

	/* Walk backwards, adding fees and testing for htlc_max and
	 * capacity limits. */
	msat = flow->delivers;
	for (int i = tal_count(flow->path) - 1; i >= 0; i--) {
		const struct half_chan *h = flow_edge(flow, i);
		struct amount_msat min, max, amount_to_reserve;
		struct short_channel_id_dir scidd;
		const char *max_cause;

		/* We can pass constraints due to addition of fees! */
		get_constraints(rq, flow->path[i], flow->dirs[i], &min, &max);
		if (amount_msat_less(amount_msat(fp16_to_u64(h->htlc_max)), max)) {
			max_cause = "htlc_maximum_msat of ";
			max = amount_msat(fp16_to_u64(h->htlc_max));
		} else {
			max_cause = "channel capacity of ";
		}

		/* If amount is > max, we decrease and add note it in
		 * case something goes wrong later. */
		if (amount_msat_greater(msat, max)) {
			plugin_log(rq->plugin, LOG_DBG,
				   "Decreased %s to %s%s across %s",
				   fmt_amount_msat(tmpctx, msat),
				   max_cause,
				   fmt_amount_msat(tmpctx, max),
				   fmt_flows_step_scid(tmpctx, rq, flow, i));
			msat = max;
			decreased = i;
			why_decreased = max_cause;
		}

		/* Reserve more for local channels if it reduces capacity */
		get_scidd(rq->gossmap, flow, i, &scidd);
		if (!amount_msat_add(&amount_to_reserve, msat,
				     get_additional_per_htlc_cost(rq, &scidd)))
			abort();

		/* Reserve it, so if the next flow asks about the same channel,
		   it will see the reduced capacity from this one.  */
		add_reservation(reservations, rq, flow, i, amount_to_reserve);

		if (!amount_msat_add_fee(&msat, h->base_fee, h->proportional_fee))
			plugin_err(rq->plugin, "Adding fee to amount");
	}

	/* Now we know how much we could send, figure out how much would be
	 * actually delivered.  Here we also check for min_htlc violations. */
	for (size_t i = 0; i < tal_count(flow->path); i++) {
		const struct half_chan *h = flow_edge(flow, i);
		struct amount_msat next, min = amount_msat(fp16_to_u64(h->htlc_min));

		next = amount_msat_sub_fee(msat,
					   h->base_fee, h->proportional_fee);

		/* These failures are incredibly unlikely, but possible */
		if (amount_msat_is_zero(next)) {
			return tal_fmt(ctx, "Amount %s cannot pay its own fees across %s",
				       fmt_amount_msat(tmpctx, msat),
				       fmt_flows_step_scid(tmpctx, rq, flow, i));
		}

		/* Does happen if we try to pay 1 msat, and all paths have 1000msat min */
		if (amount_msat_less(next, min)) {
			return tal_fmt(ctx, "Amount %s below minimum across %s",
				       fmt_amount_msat(tmpctx, next),
				       fmt_flows_step_scid(tmpctx, rq, flow, i));
		}

		msat = next;
	}

	if (!amount_msat_eq(flow->delivers, msat)) {
		plugin_log(rq->plugin, LOG_DBG, "Flow changed to deliver %s not %s, because max constrained by %s%s",
			   fmt_amount_msat(tmpctx, msat),
			   fmt_amount_msat(tmpctx, flow->delivers),
			   why_decreased ? why_decreased : NULL,
			   decreased == -1 ? "none"
			   : fmt_flows_step_scid(tmpctx, rq, flow, decreased));
		flow->delivers = msat;
	}

	return NULL;
}

/* Flow is now delivering `extra` additional msat, so modify reservations */
static void add_to_flow(struct flow *flow,
			struct route_query *rq,
			struct reserve_hop **reservations,
			struct amount_msat extra)
{
	struct amount_msat orig, updated;

	orig = flow->delivers;
	if (!amount_msat_add(&updated, orig, extra))
		abort();

	flow->delivers = updated;

	/* Now add reservations accordingly (effects constraints on other flows)  */
	for (int i = tal_count(flow->path) - 1; i >= 0; i--) {
		const struct half_chan *h = flow_edge(flow, i);
		struct amount_msat diff;

		/* Can't happen, since updated >= orig */
		if (!amount_msat_sub(&diff, updated, orig))
			abort();
		add_reservation(reservations, rq, flow, i, diff);

		if (!amount_msat_add_fee(&orig, h->base_fee, h->proportional_fee))
			abort();
		if (!amount_msat_add_fee(&updated, h->base_fee, h->proportional_fee))
			abort();
	}
}

/* Check out remaining capacity for this flow.  Changes as other flows get
 * increased (which sets reservations) */
static struct amount_msat flow_remaining_capacity(struct route_query *rq,
						  const struct flow *flow)
{
	struct amount_msat max_msat = AMOUNT_MSAT(-1ULL);
	for (int i = tal_count(flow->path) - 1; i >= 0; i--) {
		const struct half_chan *h = flow_edge(flow, i);
		struct amount_msat min, max;

		/* We can pass constraints due to addition of fees! */
		get_constraints(rq, flow->path[i], flow->dirs[i], &min, &max);
		max = amount_msat_min(max, amount_msat(fp16_to_u64(h->htlc_max)));

		max_msat = amount_msat_min(max_msat, max);
		if (!amount_msat_add_fee(&max_msat, h->base_fee, h->proportional_fee))
			max_msat = AMOUNT_MSAT(-1ULL);
	}

	/* Calculate deliverable max */
	for (size_t i = 0; i < tal_count(flow->path); i++) {
		const struct half_chan *h = flow_edge(flow, i);
		max_msat = amount_msat_sub_fee(max_msat,
					       h->base_fee, h->proportional_fee);
	}
	return max_msat;
}

/* What's the "best" flow to add to? */
static struct flow *pick_most_likely_flow(struct route_query *rq,
					  struct flow **flows,
					  struct amount_msat additional)
{
	double best_prob = 0;
	struct flow *best_flow = NULL;

	for (size_t i = 0; i < tal_count(flows); i++) {
		struct amount_msat cap;
		double prob = flow_probability(flows[i], rq);
		if (prob < best_prob)
			continue;
		cap = flow_remaining_capacity(rq, flows[i]);
		if (amount_msat_less(cap, additional))
			continue;
		best_prob = prob;
		best_flow = flows[i];
		plugin_log(rq->plugin, LOG_DBG, "Best flow is #%zu!", i);
	}

	return best_flow;
}

/* A secondary check for htlc_min violations, after excess trimming. */
static const char *flow_violates_min(const tal_t *ctx,
				     struct route_query *rq,
				     const struct flow *flow)
{
	struct amount_msat msat = flow->delivers;
	for (int i = tal_count(flow->path) - 1; i >= 0; i--) {
		const struct half_chan *h = flow_edge(flow, i);
		struct amount_msat min = amount_msat(fp16_to_u64(h->htlc_min));

		plugin_log(rq->plugin, LOG_DBG, "flow_violates_min: %u/%zu amt=%s, min=%s",
			   i, tal_count(flow->path), fmt_amount_msat(tmpctx, msat), fmt_amount_msat(tmpctx, min));
		if (amount_msat_less(msat, min)) {
			struct short_channel_id_dir scidd;
			get_scidd(rq->gossmap, flow, i, &scidd);
			return tal_fmt(ctx, "Sending %s across %s would violate htlc_min (~%s)",
				       fmt_amount_msat(tmpctx, msat),
				       fmt_short_channel_id_dir(tmpctx, &scidd),
				       fmt_amount_msat(tmpctx, min));
		}
		if (!amount_msat_add_fee(&msat, h->base_fee, h->proportional_fee))
			plugin_err(rq->plugin, "Adding fee to amount");
	}
	return NULL;
}

const char *
refine_with_fees_and_limits(const tal_t *ctx,
			    struct route_query *rq,
			    struct amount_msat deliver,
			    struct flow ***flows)
{
	struct reserve_hop *reservations = new_reservations(NULL, rq);
	struct amount_msat more_to_deliver;
	const char *flow_constraint_error = NULL;
	const char *ret;

	for (size_t i = 0; i < tal_count(*flows);) {
		struct flow *flow = (*flows)[i];

		plugin_log(rq->plugin, LOG_DBG, "Constraining flow %zu: %s",
			   i, fmt_amount_msat(tmpctx, flow->delivers));
		for (size_t j = 0; j < tal_count(flow->path); j++) {
			struct amount_msat min, max;
			get_constraints(rq, flow->path[j], flow->dirs[j], &min, &max);
			plugin_log(rq->plugin, LOG_DBG, "->%s(max %s)",
				   fmt_flows_step_scid(tmpctx, rq, flow, j),
				   fmt_amount_msat(tmpctx, max));
		}

		flow_constraint_error = constrain_flow(tmpctx, rq, flow, &reservations);
		if (!flow_constraint_error) {
			i++;
			continue;
		}

		plugin_log(rq->plugin, LOG_DBG, "Flow was too constrained: %s",
			   flow_constraint_error);
		/* This flow was reduced to 0 / impossible, remove */
		tal_arr_remove(flows, i);
	}

	/* Due to granularity of MCF, we can deliver slightly more than expected:
	 * trim one in that case. */
	if (!amount_msat_sub(&more_to_deliver, deliver,
			     flowset_delivers(rq->plugin, *flows))) {
		struct amount_msat excess;
		if (!amount_msat_sub(&excess,
				     flowset_delivers(rq->plugin, *flows),
				     deliver))
			abort();
		for (size_t i = 0; i < tal_count(*flows); i++) {
			if (amount_msat_sub(&(*flows)[i]->delivers, (*flows)[i]->delivers, excess)) {
				const char *err;
				plugin_log(rq->plugin, LOG_DBG,
					   "Flows delivered %s extra, trimming %zu/%zu",
					   fmt_amount_msat(tmpctx, excess),
					   i, tal_count(*flows));
				/* In theory, this can violate min_htlc!  Thanks @Lagrang3! */
				err = flow_violates_min(tmpctx, rq, (*flows)[i]);
				if (err) {
					/* This flow was reduced to 0 / impossible, remove */
					tal_arr_remove(flows, i);
					i--;
					/* If this causes failure, indicate why! */
					flow_constraint_error = err;
					continue;
				}
				break;
			}
		}

		/* Usually this should shed excess, *BUT* maybe one
		 * was deleted instead for being below minimum */
		if (!amount_msat_sub(&more_to_deliver, deliver,
				     flowset_delivers(rq->plugin, *flows))) {
			ret = tal_fmt(ctx,
				      "Flowset delivers %s instead of %s, can't shed excess?",
				      fmt_amount_msat(tmpctx, flowset_delivers(rq->plugin, *flows)),
				      fmt_amount_msat(tmpctx, deliver));
			goto out;
		}

		plugin_log(rq->plugin, LOG_DBG, "After dealing with excess, more_to_deliver=%s",
			   fmt_amount_msat(tmpctx, more_to_deliver));
	}

	/* The residual is minimal.  In theory we could add one msat at a time
	 * to the most probably flow which has capacity.  For speed, we break it
	 * into the number of flows, then assign each one. */
	for (size_t i = 0; i < tal_count(*flows) && !amount_msat_is_zero(more_to_deliver); i++) {
		struct flow *f;
		struct amount_msat extra;

		/* How much more do we deliver?  Round up if we can */
		extra = amount_msat_div(more_to_deliver, tal_count(*flows) - i);
		if (amount_msat_less(extra, more_to_deliver)) {
			if (!amount_msat_accumulate(&extra, AMOUNT_MSAT(1)))
				abort();
		}

		/* In theory, this can happen.  If it ever does, we
		 * could try MCF again for the remainder. */
		f = pick_most_likely_flow(rq, *flows, extra);
		if (!f) {
			ret = tal_fmt(ctx, "We couldn't quite afford it, we need to send %s more for fees: please submit a bug report!",
				      fmt_amount_msat(tmpctx, more_to_deliver));
			goto out;
		}

		/* Make this flow deliver +extra, and modify reservations */
		add_to_flow(f, rq, &reservations, extra);

		/* Should not happen, since extra comes from div... */
		if (!amount_msat_sub(&more_to_deliver, more_to_deliver, extra))
			abort();
	}

	if (!amount_msat_eq(deliver, flowset_delivers(rq->plugin, *flows))) {
		/* This should only happen if there were no flows */
		if (tal_count(*flows) == 0) {
			ret = flow_constraint_error;
			goto out;
		}
		plugin_err(rq->plugin, "Flows delivered only %s of %s?",
			   fmt_amount_msat(tmpctx, flowset_delivers(rq->plugin, *flows)),
			   fmt_amount_msat(tmpctx, deliver));
	}
	ret = NULL;

out:
	tal_free(reservations);
	return ret;
}
