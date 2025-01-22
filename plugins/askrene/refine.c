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

static void subtract_reservation(struct reserve_hop **reservations,
				 const struct route_query *rq,
				 const struct gossmap_chan *chan,
				 const struct short_channel_id_dir *scidd,
				 struct amount_msat amt)
{
	struct reserve_hop *prev;
	struct askrene *askrene = get_askrene(rq->plugin);

	prev = find_reservation(*reservations, scidd);
	assert(prev);

	reserve_remove(askrene->reserved, prev);
	if (!amount_msat_sub(&prev->amount, prev->amount, amt))
		abort();
	/* Adding a zero reserve is weird, but legal and easy! */
	reserve_add(askrene->reserved, prev, rq->cmd->id);
}

static void create_flow_reservations(const struct route_query *rq,
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

static void remove_flow_reservations(const struct route_query *rq,
				     struct reserve_hop **reservations,
				     const struct flow *flow)
{
	struct amount_msat msat = flow->delivers;
	for (int i = tal_count(flow->path) - 1; i >= 0; i--) {
		const struct half_chan *h = flow_edge(flow, i);
		struct amount_msat amount_to_reserve;
		struct short_channel_id_dir scidd;

		get_scidd(rq->gossmap, flow, i, &scidd);

		/* Reserve more for local channels if it reduces capacity */
		if (!amount_msat_add(&amount_to_reserve, msat,
				     get_additional_per_htlc_cost(rq, &scidd)))
			abort();

		subtract_reservation(reservations, rq, flow->path[i], &scidd,
				     amount_to_reserve);
		if (!amount_msat_add_fee(&msat,
					 h->base_fee, h->proportional_fee))
			plugin_err(rq->plugin, "Adding fee to amount");
	}
}

static void change_flow_delivers(const struct route_query *rq,
				 struct flow *flow,
				 struct reserve_hop **reservations,
				 struct amount_msat new)
{
	remove_flow_reservations(rq, reservations, flow);
	flow->delivers = new;
	create_flow_reservations(rq, reservations, flow);
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

/* Get exact maximum we can deliver with this flow.  Returns reason
 * why this is the limit (max_hltc or capacity), and optionally sets scidd */
static enum why_capped flow_max_capacity(const struct route_query *rq,
					 const struct flow *flow,
					 struct amount_msat *deliverable,
					 struct short_channel_id_dir *scidd_why,
					 struct amount_msat *amount_why)
{
	struct amount_msat max_msat = AMOUNT_MSAT(-1ULL);
	enum why_capped why_capped = CAPPED_CAPACITY;

	for (int i = tal_count(flow->path) - 1; i >= 0; i--) {
		const struct half_chan *h = flow_edge(flow, i);
		struct amount_msat min, max, htlc_max;
		struct short_channel_id_dir scidd;

		get_scidd(rq->gossmap, flow, i, &scidd);
		/* We can pass constraints due to addition of fees! */
		get_constraints(rq, flow->path[i], flow->dirs[i], &min, &max);

		if (amount_msat_greater(max_msat, max)) {
			why_capped = CAPPED_CAPACITY;
			if (scidd_why)
				*scidd_why = scidd;
			if (amount_why)
				*amount_why = max;
			max_msat = max;
		}

		htlc_max = get_chan_htlc_max(rq, flow->path[i], &scidd);
		if (amount_msat_greater(max_msat, htlc_max)) {
			why_capped = CAPPED_HTLC_MAX;
			if (scidd_why)
				*scidd_why = scidd;
			if (amount_why)
				*amount_why = htlc_max;
			max_msat = htlc_max;
		}
		if (!amount_msat_add_fee(&max_msat, h->base_fee, h->proportional_fee))
			max_msat = AMOUNT_MSAT(-1ULL);
	}

	/* Calculate deliverable max */
	*deliverable = max_msat;
	for (size_t i = 0; i < tal_count(flow->path); i++) {
		const struct half_chan *h = flow_edge(flow, i);
		*deliverable = amount_msat_sub_fee(*deliverable,
						   h->base_fee,
						   h->proportional_fee);
	}
	return why_capped;
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
				  struct flow *flow)
{
	struct amount_msat deliverable, msat, amount_capped;
	enum why_capped why_capped;
	struct short_channel_id_dir scidd_capped;

	why_capped = flow_max_capacity(rq, flow, &deliverable,
				       &scidd_capped, &amount_capped);
	if (amount_msat_less(deliverable, flow->delivers)) {
		rq_log(tmpctx, rq, LOG_INFORM,
		       "Flow reduced to deliver %s not %s, because %s %s %s",
		       fmt_amount_msat(tmpctx, deliverable),
		       fmt_amount_msat(tmpctx, flow->delivers),
		       fmt_short_channel_id_dir(tmpctx, &scidd_capped),
		       why_capped == CAPPED_HTLC_MAX
		       ? "advertizes htlc_maximum_msat"
		       : "has remaining capacity",
		       fmt_amount_msat(tmpctx, amount_capped));
		flow->delivers = deliverable;
	}

	/* Now, check if any of them violate htlc_min */
	msat = flow->delivers;
	for (int i = tal_count(flow->path) - 1; i >= 0; i--) {
		const struct half_chan *h = flow_edge(flow, i);
		struct amount_msat min;
		struct short_channel_id_dir scidd;

		get_scidd(rq->gossmap, flow, i, &scidd);
		min = get_chan_htlc_min(rq, flow->path[i], &scidd);

		if (amount_msat_less(msat, min)) {
			return rq_log(ctx, rq, LOG_UNUSUAL,
				      "Amount %s below minimum %s across %s",
				      fmt_amount_msat(tmpctx, msat),
				      fmt_amount_msat(tmpctx, min),
				      fmt_short_channel_id_dir(tmpctx, &scidd));
		}
		if (!amount_msat_add_fee(&msat,
					 h->base_fee, h->proportional_fee))
			plugin_err(rq->plugin, "Adding fee to amount");
	}
	return NULL;
}

static struct amount_msat flow_remaining_capacity(const struct route_query *rq,
						  struct reserve_hop **reservations,
						  const struct flow *flow)
{
	struct amount_msat max, diff;

	/* Remove ourselves from reservation temporarily, so we don't
	 * accidentally cap! */
	remove_flow_reservations(rq, reservations, flow);
	flow_max_capacity(rq, flow, &max, NULL, NULL);

	/* This seems to happen.  Which is strange, since flows should
	   already be constrained. */
	if (!amount_msat_sub(&diff, max, flow->delivers)) {
		plugin_log(rq->plugin, LOG_BROKEN,
			   "Flow delivers %s but max only %s? flow=%s",
			   fmt_amount_msat(tmpctx, flow->delivers),
			   fmt_amount_msat(tmpctx, max),
			   fmt_flow_full(rq, rq, flow));
		for (size_t i = 0; i < tal_count(*reservations); i++) {
			plugin_log(rq->plugin, LOG_BROKEN,
				   "Reservation #%zi: %s on %s",
				   i,
				   fmt_amount_msat(tmpctx, (*reservations)[i].amount),
				   fmt_short_channel_id_dir(tmpctx, &(*reservations)[i].scidd));
		}
		diff = AMOUNT_MSAT(0);
	}
	create_flow_reservations(rq, reservations, flow);
	return diff;
}

/* What's the "best" flow to add to? */
static struct flow *pick_most_likely_flow(const struct route_query *rq,
					  struct flow **flows,
					  struct reserve_hop **reservations,
					  struct amount_msat additional)
{
	double best_prob = 0;
	struct flow *best_flow = NULL;

	for (size_t i = 0; i < tal_count(flows); i++) {
		struct amount_msat cap;
		double prob = flow_probability(flows[i], rq);
		if (prob < best_prob)
			continue;
		cap = flow_remaining_capacity(rq, reservations, flows[i]);
		if (amount_msat_less(cap, additional))
			continue;
		best_prob = prob;
		best_flow = flows[i];
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
		struct amount_msat min;
		struct short_channel_id_dir scidd;
		get_scidd(rq->gossmap, flow, i, &scidd);

		min = get_chan_htlc_min(rq, flow->path[i], &scidd);
		if (amount_msat_less(msat, min)) {
			return rq_log(ctx, rq, LOG_UNUSUAL,
				      "Sending %s across %s would violate htlc_min (~%s)",
				      fmt_amount_msat(tmpctx, msat),
				      fmt_short_channel_id_dir(tmpctx, &scidd),
				      fmt_amount_msat(tmpctx, min));
		}
		if (!amount_msat_add_fee(&msat, h->base_fee, h->proportional_fee))
			plugin_err(rq->plugin, "Adding fee to amount");
	}
	return NULL;
}

/* If one flow is constrained by htlc_max, we might be able to simply
 * duplicate it.  This is naive: it could still fail due to total
 * capacity, but it is a corner case anyway. */
static bool duplicate_one_flow(const struct route_query *rq,
			       struct reserve_hop **reservations,
			       struct flow ***flows)
{
	for (size_t i = 0; i < tal_count(*flows); i++) {
		struct flow *flow = (*flows)[i], *new_flow;
		struct amount_msat max, new_amount;
		/* Don't create 0 flow (shouldn't happen, but be sure) */
		if (amount_msat_less(flow->delivers, AMOUNT_MSAT(2)))
			continue;

		if (flow_max_capacity(rq, flow, &max, NULL, NULL)
		    != CAPPED_HTLC_MAX)
			continue;

		new_flow = tal(*flows, struct flow);
		new_flow->path = tal_dup_talarr(new_flow,
						const struct gossmap_chan *,
						flow->path);
		new_flow->dirs = tal_dup_talarr(new_flow, int,
						flow->dirs);
		new_flow->delivers = amount_msat_div(flow->delivers, 2);
		create_flow_reservations(rq, reservations, new_flow);

		if (!amount_msat_sub(&new_amount,
				     flow->delivers, new_flow->delivers))
			abort();
		change_flow_delivers(rq, flow, reservations, new_amount);
		tal_arr_expand(flows, new_flow);
		return true;
	}
	return false;
}

/* Stolen whole-cloth from @Lagrang3 in renepay's flow.c.  Wrong
 * because of htlc overhead in reservations! */
static double edge_probability(const struct route_query *rq,
			       const struct short_channel_id_dir *scidd,
			       struct amount_msat sent)
{
	struct amount_msat numerator, denominator;
	struct amount_msat mincap, maxcap, additional;
	const struct gossmap_chan *c = gossmap_find_chan(rq->gossmap, &scidd->scid);

	get_constraints(rq, c, scidd->dir, &mincap, &maxcap);

	/* We add an extra per-htlc reservation for the *next* HTLC, so we "over-reserve"
	 * on local channels.  Undo that! */
	additional = get_additional_per_htlc_cost(rq, scidd);
	if (!amount_msat_accumulate(&mincap, additional)
	    || !amount_msat_accumulate(&maxcap, additional))
		abort();

	if (amount_msat_less_eq(sent, mincap))
		return 1.0;
	else if (amount_msat_greater(sent, maxcap))
		return 0.0;

	/* Linear probability: 1 - (spend - min) / (max - min) */

	/* spend > mincap, from above. */
	if (!amount_msat_sub(&numerator, sent, mincap))
		abort();
	/* This can only fail is maxcap was < mincap,
	 * so we would be captured above */
	if (!amount_msat_sub(&denominator, maxcap, mincap))
		abort();
	return 1.0 - amount_msat_ratio(numerator, denominator);
}

const char *
refine_with_fees_and_limits(const tal_t *ctx,
			    struct route_query *rq,
			    struct amount_msat deliver,
			    struct flow ***flows,
			    double *flowset_probability)
{
	struct reserve_hop *reservations = new_reservations(NULL, rq);
	struct amount_msat more_to_deliver;
	const char *flow_constraint_error = NULL;
	const char *ret;
	bool tried_split_flow = false;

	for (size_t i = 0; i < tal_count(*flows);) {
		struct flow *flow = (*flows)[i];

		flow_constraint_error = constrain_flow(tmpctx, rq, flow);
		if (!flow_constraint_error) {
			create_flow_reservations(rq, &reservations, flow);
			i++;
			continue;
		}

		rq_log(tmpctx, rq, LOG_UNUSUAL, "Flow %zu/%zu was too constrained (%s) so removing it",
		       i, tal_count(*flows), flow_constraint_error);
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
			const char *err;
			struct amount_msat trimmed;
			if (!amount_msat_sub(&trimmed, (*flows)[i]->delivers, excess))
				continue;

			rq_log(tmpctx, rq, LOG_DBG,
			       "%s extra, trimming flow %zu/%zu",
			       fmt_amount_msat(tmpctx, excess), i, tal_count(*flows));
			change_flow_delivers(rq, (*flows)[i], &reservations, trimmed);
			/* In theory, this can violate min_htlc!  Thanks @Lagrang3! */
			err = flow_violates_min(tmpctx, rq, (*flows)[i]);
			if (err) {
				/* This flow was reduced to 0 / impossible, remove */
				remove_flow_reservations(rq, &reservations, (*flows)[i]);
				tal_arr_remove(flows, i);
				i--;
				/* If this causes failure, indicate why! */
				flow_constraint_error = err;
				continue;
			}
			break;
		}

		/* Usually this should shed excess, *BUT* maybe one
		 * was deleted instead for being below minimum */
		if (!amount_msat_sub(&more_to_deliver, deliver,
				     flowset_delivers(rq->plugin, *flows))) {
			ret = rq_log(ctx, rq, LOG_UNUSUAL,
				      "Flowset delivers %s instead of %s, can't shed excess?",
				      fmt_amount_msat(tmpctx, flowset_delivers(rq->plugin, *flows)),
				      fmt_amount_msat(tmpctx, deliver));
			goto out;
		}

		rq_log(tmpctx, rq, LOG_DBG,
		       "After dealing with excess, more_to_deliver=%s",
		       fmt_amount_msat(tmpctx, more_to_deliver));
	}

	/* The residual is minimal.  In theory we could add one msat at a time
	 * to the most probably flow which has capacity.  For speed, we break it
	 * into the number of flows, then assign each one. */
	while (!amount_msat_is_zero(more_to_deliver) && tal_count(*flows)) {
		struct flow *f;
		struct amount_msat extra, new_delivers;

		/* How much more do we deliver?  Round up if we can */
		extra = amount_msat_div(more_to_deliver, tal_count(*flows));
		if (amount_msat_less(extra, more_to_deliver)) {
			if (!amount_msat_accumulate(&extra, AMOUNT_MSAT(1)))
				abort();
		}

		/* This happens when we have a single flow, and hit
		 * htlc_max.  For this corner case, we split into an
		 * additional flow, but only once! */
		f = pick_most_likely_flow(rq, *flows, &reservations, extra);
		if (!f) {
			if (tried_split_flow || !duplicate_one_flow(rq, &reservations, flows)) {
				ret = rq_log(ctx, rq, LOG_BROKEN,
					     "We couldn't quite afford it, we need to send %s more for fees: please submit a bug report!",
					     fmt_amount_msat(tmpctx, more_to_deliver));
				goto out;
			}
			tried_split_flow = true;
			continue;
		}

		if (!amount_msat_add(&new_delivers, f->delivers, extra))
			abort();
		change_flow_delivers(rq, f, &reservations, new_delivers);

		/* Should not happen, since extra comes from div... */
		if (!amount_msat_sub(&more_to_deliver, more_to_deliver, extra))
			abort();
	}

	if (!amount_msat_eq(deliver, flowset_delivers(rq->plugin, *flows))) {
		/* This should only happen if there were no flows */
		if (tal_count(*flows) == 0) {
			ret = tal_steal(ctx, flow_constraint_error);
			goto out;
		}
		plugin_err(rq->plugin, "Flows delivered only %s of %s?",
			   fmt_amount_msat(tmpctx, flowset_delivers(rq->plugin, *flows)),
			   fmt_amount_msat(tmpctx, deliver));
	}

	ret = NULL;

	/* Total flowset probability is now easily calculated given reservations
	 * contains the total amounts through each channel (once we remove them) */
	destroy_reservations(reservations, get_askrene(rq->plugin));
	tal_add_destructor2(reservations, destroy_reservations, get_askrene(rq->plugin));

	*flowset_probability = 1.0;
	for (size_t i = 0; i < tal_count(reservations); i++) {
		const struct reserve_hop *r = &reservations[i];
		*flowset_probability *= edge_probability(rq, &r->scidd, r->amount);
	}

out:
	tal_free(reservations);
	return ret;
}
