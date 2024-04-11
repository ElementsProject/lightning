#include "config.h"
#include <ccan/bitmap/bitmap.h>
#include <plugins/renepay/mcf.h>
#include <plugins/renepay/routebuilder.h>

static bitmap *
make_disabled_bitmap(const tal_t *ctx, const struct gossmap *gossmap,
		     const struct chan_extra_map *chan_extra_map,
		     const struct short_channel_id *disabled_scids)
{
	bitmap *disabled =
	    tal_arrz(ctx, bitmap, BITMAP_NWORDS(gossmap_max_chan_idx(gossmap)));
	if (!disabled)
		return NULL;

	/* Disable every channel in the list of disabled scids. */
	for (size_t i = 0; i < tal_count(disabled_scids); i++) {
		struct gossmap_chan *c =
		    gossmap_find_chan(gossmap, &disabled_scids[i]);
		if (c)
			bitmap_set_bit(disabled, gossmap_chan_idx(gossmap, c));
	}
	/* Also disable every channel that we don't have in the chan_extra_map. */
	for (struct gossmap_chan *chan = gossmap_first_chan(gossmap); chan;
	     chan = gossmap_next_chan(gossmap, chan)) {
		const u32 chan_id = gossmap_chan_idx(gossmap, chan);
		struct short_channel_id scid = gossmap_chan_scid(gossmap, chan);
		struct chan_extra *ce =
		    chan_extra_map_get(chan_extra_map, scid);
		if (!ce)
			bitmap_set_bit(disabled, chan_id);
	}
	return disabled;
}

// static void uncertainty_commit_routes(struct uncertainty *uncertainty,
// 				   struct route **routes)
// {
// 	const size_t N = tal_count(routes);
// 	for (size_t i = 0; i < N; i++)
// 		uncertainty_commit_htlcs(uncertainty, routes[i]);
// }
static void uncertainty_remove_routes(struct uncertainty *uncertainty,
				   struct route **routes)
{
	const size_t N = tal_count(routes);
	for (size_t i = 0; i < N; i++)
		uncertainty_remove_htlcs(uncertainty, routes[i]);
}

static void mark_chan_disabled(const struct gossmap_chan *chan,
			       struct short_channel_id **disabled_scids,
			       bitmap *disabled_bitmap,
			       struct gossmap *gossmap)
{
	struct short_channel_id scid = gossmap_chan_scid(gossmap, chan);
	tal_arr_expand(disabled_scids, scid);
	bitmap_set_bit(disabled_bitmap, gossmap_chan_idx(gossmap, chan));
}

// TODO: check
/* Shave-off amounts that do not meet the liquidity constraints. Disable
 * channels that produce an htlc_max bottleneck. */
static struct flow **flows_adjust_htlcmax_constraints(
    const tal_t *ctx, struct flow **flows TAKES, struct gossmap *gossmap,
    struct chan_extra_map *chan_extra_map,
    struct short_channel_id **disabled_scids, bitmap *disabled_bitmap)
{
	struct flow **new_flows = tal_arr(ctx, struct flow *, 0);
	enum renepay_errorcode errorcode;

	for (size_t i = 0; i < tal_count(flows); i++) {
		struct flow *f = flows[i];
		struct amount_msat max_deliverable;
		const struct gossmap_chan *bad_channel;

		errorcode = flow_maximum_deliverable(
		    &max_deliverable, f, gossmap, chan_extra_map, &bad_channel);

		if (!errorcode) {
			// no issues
			f->amount =
			    amount_msat_min(flow_delivers(f), max_deliverable);

			tal_arr_expand(&new_flows, f);
		} else if (errorcode == RENEPAY_BAD_CHANNEL) {
			// this is a channel that we can disable
			mark_chan_disabled(bad_channel, disabled_scids,
					   disabled_bitmap, gossmap);
			continue;
		} else {
			// we had an unexpected error
			goto function_fail;
		}
	}

	for (size_t i = 0; i < tal_count(new_flows); i++) {
		tal_steal(new_flows, new_flows[i]);
	}

	if (taken(flows))
		tal_free(flows);
	return new_flows;

function_fail:
	if (taken(flows))
		tal_free(flows);
	return tal_free(new_flows);
}

// TODO: check
/* Disable channels that produce an htlc_min bottleneck. */
static struct flow **flows_adjust_htlcmin_constraints(
    const tal_t *ctx, struct flow **flows TAKES, struct gossmap *gossmap,
    struct chan_extra_map *chan_extra_map,
    struct short_channel_id **disabled_scids, bitmap *disabled_bitmap)
{
	struct flow **new_flows = tal_arr(ctx, struct flow *, 0);
	enum renepay_errorcode errorcode;
	struct amount_msat max_deliverable;

	for (size_t i = 0; i < tal_count(flows); i++) {
		struct flow *f = flows[i];
		const struct gossmap_chan *bad_channel;

		errorcode = flow_maximum_deliverable(
		    &max_deliverable, f, gossmap, chan_extra_map, &bad_channel);

		if (!errorcode) {
			// no issues
			f->amount =
			    amount_msat_min(flow_delivers(f), max_deliverable);

			tal_arr_expand(&new_flows, f);
		} else if (errorcode == RENEPAY_BAD_CHANNEL) {
			// this is a channel that we can disable
			mark_chan_disabled(bad_channel, disabled_scids,
					   disabled_bitmap, gossmap);
			continue;
		} else {
			// we had an unexpected error
			goto function_fail;
		}
	}

	for (size_t i = 0; i < tal_count(new_flows); i++) {
		tal_steal(new_flows, new_flows[i]);
	}

	if (taken(flows))
		tal_free(flows);
	return new_flows;

function_fail:
	if (taken(flows))
		tal_free(flows);
	return tal_free(new_flows);
}

/* Routes are computed and saved in the payment for later use. */
struct route **get_routes(const tal_t *ctx, struct payment *payment,

			  const struct node_id *source,
			  const struct node_id *destination,
			  struct gossmap *gossmap, struct uncertainty *uncertainty,

			  struct amount_msat amount_to_deliver,
			  const u32 final_cltv, struct amount_msat feebudget,

			  enum jsonrpc_errcode *ecode, const char **fail)
{
	assert(gossmap);
	assert(uncertainty);

	const tal_t *this_ctx = tal(ctx, tal_t);
	struct route **routes = tal_arr(ctx, struct route *, 0);

	double probability_budget = payment->min_prob_success;
	double delay_feefactor = payment->delay_feefactor;
	const double base_fee_penalty = payment->base_fee_penalty;
	const double prob_cost_factor = payment->prob_cost_factor;
	const unsigned int maxdelay = payment->maxdelay;

	bitmap *disabled_bitmap =
	    make_disabled_bitmap(this_ctx, gossmap, uncertainty->chan_extra_map,
				 payment->disabled_scids);
	if (!disabled_bitmap) {
		if (ecode)
			*ecode = PLUGIN_ERROR;
		if (fail)
			*fail =
			    tal_fmt(ctx, "Failed to build disabled_bitmap.");
		goto function_fail;
	}

	const struct gossmap_node *src, *dst;
	src = gossmap_find_node(gossmap, source);
	if (!src) {
		if (ecode)
			*ecode = PAY_ROUTE_NOT_FOUND;
		if (fail)
			*fail = tal_fmt(ctx, "We don't have any channels.");
		goto function_fail;
	}
	dst = gossmap_find_node(gossmap, destination);
	if (!dst) {
		if (ecode)
			*ecode = PAY_ROUTE_NOT_FOUND;
		if (fail)
			*fail = tal_fmt(
			    ctx,
			    "Destination is unknown in the network gossip.");
		goto function_fail;
	}

	char *errmsg;

	while (!amount_msat_zero(amount_to_deliver)) {

		/* TODO: choose an algorithm, could be something like
		 * payment->algorithm, that we set up based on command line
		 * options and that can be changed according to some conditions
		 * met during the payment process, eg. add "select_solver" pay
		 * mod. */
		/* TODO: use uncertainty instead of chan_extra */
		/* TODO: shall we add to possibility to blacklist nodes? */

		/* Min. Cost Flow algorithm to find optimal flows. */
		struct flow **flows =
		    minflow(this_ctx, gossmap, src, dst,
			    uncertainty_get_chan_extra_map(uncertainty),
			    disabled_bitmap, amount_to_deliver, feebudget,
			    probability_budget, delay_feefactor,
			    base_fee_penalty, prob_cost_factor, &errmsg);

		if (!flows) {
			if (ecode)
				*ecode = PAY_ROUTE_NOT_FOUND;

			if (fail)
				*fail = tal_fmt(
				    ctx,
				    "minflow couldn't find a feasible flow: %s",
				    errmsg);
			goto function_fail;
		}

		/* In previous implementations we would search for
		 * htlcmax/htlcmin violations and disable those channels and
		 * then redo the MCF computation. Now we instead remove only
		 * those flows for which there is a constraint violation and
		 * mark the involved channels as disabled for the next MCF
		 * iteration. */
		flows = flows_adjust_htlcmax_constraints(
		    this_ctx, take(flows), gossmap,
		    uncertainty_get_chan_extra_map(uncertainty),
		    &payment->disabled_scids, disabled_bitmap);
		if (!flows) {
			if (ecode)
				*ecode = PAY_ROUTE_NOT_FOUND;

			if (fail)
				*fail = tal_fmt(
				    ctx,
				    "failed to adjust htlcmax constraints.");

			goto function_fail;
		}

		flows = flows_adjust_htlcmin_constraints(
		    this_ctx, take(flows), gossmap,
		    uncertainty_get_chan_extra_map(uncertainty),
		    &payment->disabled_scids, disabled_bitmap);
		if (!flows) {
			if (ecode)
				*ecode = PAY_ROUTE_NOT_FOUND;

			if (fail)
				*fail = tal_fmt(
				    ctx,
				    "failed to adjust htlcmin constraints.");

			goto function_fail;
		}
		// TODO: check issue #7136

		/* Check the fee limits. */
		/* TODO: review this, only flows with non-zero amount */
		struct amount_msat fee;
		if (!flowset_fee(&fee, flows)) {
			if (ecode)
				*ecode = PLUGIN_ERROR;

			if (fail)
				*fail = tal_fmt(ctx, "flowset_fee failed");
			goto function_fail;
		}
		if (amount_msat_greater(fee, feebudget)) {
			if (ecode)
				*ecode = PAY_ROUTE_TOO_EXPENSIVE;

			if (fail)
				*fail = tal_fmt(
				    ctx,
				    "Fee exceeds our fee budget, fee=%s "
				    "(feebudget=%s)",
				    fmt_amount_msat(this_ctx, fee),
				    fmt_amount_msat(this_ctx, feebudget));
			goto function_fail;
		}

		/* Check the CLTV delay */
		/* TODO: review this, only flows with non-zero amounts */
		const u64 delay = flows_worst_delay(flows) + final_cltv;
		if (delay > maxdelay) {
			/* FIXME: What is a sane limit? */
			if (delay_feefactor > 1000) {
				if (ecode)
					*ecode = PAY_ROUTE_TOO_EXPENSIVE;
				if (fail)
					*fail = tal_fmt(
					    ctx,
					    "CLTV delay exceeds our CLTV "
					    "budget, delay=%" PRIu64
					    "(maxdelay=%u)",
					    delay, maxdelay);
				goto function_fail;
			}

			delay_feefactor *= 2;
			continue; // retry
		}

		/* Compute the flows probability */
		/* TODO: review this, only flows with non-zero amounts */
		double prob = flowset_probability(
		    this_ctx, flows, gossmap,
		    uncertainty_get_chan_extra_map(uncertainty), NULL);
		if (prob < 0) {
			if (ecode)
				*ecode = PLUGIN_ERROR;
			if (fail)
				*fail =
				    tal_fmt(ctx, "flowset_probability failed");
			goto function_fail;
		}

		struct amount_msat delivering;
		if (!flowset_delivers(&delivering, flows)) {
			if (ecode)
				*ecode = PLUGIN_ERROR;

			if (fail)
				*fail = tal_fmt(ctx, "flowset_delivers failed");
			goto function_fail;
		}

		/* OK, we are happy with these flows: convert to
		 * routes in the current payment. */
		delivering = AMOUNT_MSAT(0);
		fee = AMOUNT_MSAT(0);
		// TODO check ownership of these routes
		for (size_t i = 0; i < tal_count(flows); i++) {
			struct route *r = flow_to_route(
			    ctx, payment, payment->groupid,
			    payment->next_partid, payment->payment_hash,
			    final_cltv, gossmap, flows[i]);
			if (!r) {
				/* TODO: what could have gone wrong? */
				continue;
			}
			payment->next_partid++;
			uncertainty_commit_htlcs(uncertainty, r);
			tal_arr_expand(&routes, r);

			struct amount_msat route_fee = route_fees(r),
					   route_deliver = route_delivers(r);

			if (!amount_msat_add(&fee, fee, route_fee) ||
			    !amount_msat_add(&delivering, delivering,
					     route_deliver)) {
				if (ecode)
					*ecode = PLUGIN_ERROR;

				if (fail)
					*fail = tal_fmt(
					    ctx,
					    "%s (line %d) amount_msat "
					    "arithmetic overflow.",
					    __PRETTY_FUNCTION__, __LINE__);
				goto function_fail;
			}
		}

		/* For the next iteration get me the amount_to_deliver */
		if (!amount_msat_sub(&amount_to_deliver, amount_to_deliver,
				     delivering)) {
			/* In the next iteration we search routes that allocate
			 *amount_to_deliver - delivering If we have delivering >
			 *amount_to_deliver it means we have made a mistake
			 *somewhere.
			 */
			if (ecode)
				*ecode = PLUGIN_ERROR;

			if (fail)
				*fail = tal_fmt(
				    ctx,
				    "%s (line %d) delivering to destination "
				    "(%s) is more than requested (%s)",
				    __PRETTY_FUNCTION__, __LINE__,
				    fmt_amount_msat(this_ctx, delivering),
				    fmt_amount_msat(this_ctx,
						    amount_to_deliver));
			goto function_fail;
		}

		/* For the next iteration get me the feebudget */
		if (!amount_msat_sub(&feebudget, feebudget, fee)) {
			if (ecode)
				*ecode = PLUGIN_ERROR;

			if (fail)
				*fail = tal_fmt(
				    ctx,
				    "%s (line %d) routing fees (%s) exceed fee "
				    "budget (%s).",
				    __PRETTY_FUNCTION__, __LINE__,
				    fmt_amount_msat(this_ctx, fee),
				    fmt_amount_msat(this_ctx, feebudget));
			goto function_fail;
		}

		/* For the next iteration get me the probability_budget */
		if (prob < 1e-10) {
			/* this last flow probability is too small for division
			 */
			probability_budget = 1.0;
		} else {
			/* prob here is a conditional probability, the next
			 * round of flows will have a conditional probability
			 * prob2 and we would like that prob*prob2 >=
			 * probability_budget hence probability_budget/prob
			 * becomes the next iteration's target. */
			probability_budget =
			    MIN(1.0, probability_budget / prob);
		}
	}

	/* remove the temporary routes from the uncertainty network */
	uncertainty_remove_routes(uncertainty, routes);

	/* ownership */
	for (size_t i = 0; i < tal_count(routes); i++)
		routes[i] = tal_steal(routes, routes[i]);

	tal_free(this_ctx);
	return routes;

function_fail:
	/* remove the temporary routes from the uncertainty network */
	uncertainty_remove_routes(uncertainty, routes);

	/* Discard any routes we have constructed here. */
	tal_free(this_ctx);
	return tal_free(routes);
}
