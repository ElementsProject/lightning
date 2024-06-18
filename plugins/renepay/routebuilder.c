#include "config.h"
#include <ccan/bitmap/bitmap.h>
#include <plugins/renepay/mcf.h>
#include <plugins/renepay/routebuilder.h>

#include <stdio.h>

static void uncertainty_remove_routes(struct uncertainty *uncertainty,
				   struct route **routes)
{
	const size_t N = tal_count(routes);
	for (size_t i = 0; i < N; i++)
		uncertainty_remove_htlcs(uncertainty, routes[i]);
}

/* Shave-off amounts that do not meet the liquidity constraints. Disable
 * channels that produce an htlc_max bottleneck. */
static enum renepay_errorcode
flow_adjust_htlcmax_constraints(struct flow *flow, struct gossmap *gossmap,
				struct chan_extra_map *chan_extra_map,
				bitmap *disabled_bitmap)
{
	assert(flow);
	assert(gossmap);
	assert(chan_extra_map);
	assert(disabled_bitmap);
	assert(!amount_msat_zero(flow_delivers(flow)));

	enum renepay_errorcode errorcode;

	struct amount_msat max_deliverable;
	const struct gossmap_chan *bad_channel;

	errorcode = flow_maximum_deliverable(&max_deliverable, flow, gossmap,
					     chan_extra_map, &bad_channel);

	if (!errorcode) {
		assert(!amount_msat_zero(max_deliverable));

		// no issues
		flow->amount =
		    amount_msat_min(flow_delivers(flow), max_deliverable);

		return errorcode;
	}

	if (errorcode == RENEPAY_BAD_CHANNEL) {
		// this is a channel that we can disable
		// FIXME: log this error? disabling both directions?
		bitmap_set_bit(disabled_bitmap,
			       gossmap_chan_idx(gossmap, bad_channel) * 2 + 0);
		bitmap_set_bit(disabled_bitmap,
			       gossmap_chan_idx(gossmap, bad_channel) * 2 + 1);
	}

	// we had an unexpected error
	return errorcode;
}

static enum renepay_errorcode
route_check_constraints(struct route *route, struct gossmap *gossmap,
			struct uncertainty *uncertainty,
			bitmap *disabled_bitmap)
{
	assert(route);
	assert(route->hops);
	const size_t pathlen = tal_count(route->hops);
	if (!amount_msat_eq(route->amount, route->hops[pathlen - 1].amount))
		return RENEPAY_PRECONDITION_ERROR;
	if (!amount_msat_eq(route->amount_sent, route->hops[0].amount))
		return RENEPAY_PRECONDITION_ERROR;

	for (size_t i = 0; i < pathlen; i++) {
		struct route_hop *hop = &route->hops[i];
		int dir = hop->direction;
		struct gossmap_chan *chan =
		    gossmap_find_chan(gossmap, &hop->scid);
		assert(chan);
		struct chan_extra *ce =
		    uncertainty_find_channel(uncertainty, hop->scid);

		// check that we stay within the htlc max and min limits
		if (amount_msat_greater(hop->amount,
					channel_htlc_max(chan, dir)) ||
		    amount_msat_less(hop->amount,
				     channel_htlc_min(chan, dir))) {
			bitmap_set_bit(disabled_bitmap,
				       gossmap_chan_idx(gossmap, chan) * 2 +
					   dir);
			return RENEPAY_BAD_CHANNEL;
		}

		// check that the sum of all htlcs and this amount does not
		// exceed the maximum known by our knowledge
		struct amount_msat total_htlcs = ce->half[dir].htlc_total;
		if (!amount_msat_add(&total_htlcs, total_htlcs, hop->amount))
			return RENEPAY_AMOUNT_OVERFLOW;

		if (amount_msat_greater(total_htlcs, ce->half[dir].known_max))
			return RENEPAY_UNEXPECTED;
	}
	return RENEPAY_NOERROR;
}

static void tal_report_error(const tal_t *ctx, enum jsonrpc_errcode *ecode,
			     const char **fail,
			     enum jsonrpc_errcode error_value, const char *fmt,
			     ...)
{
	tal_t *this_ctx = tal(ctx, tal_t);

	va_list ap;
	const char *str;

	va_start(ap, fmt);
	str = tal_vfmt(this_ctx, fmt, ap);
	va_end(ap);

	if (ecode)
		*ecode = error_value;

	if (fail)
		*fail = tal_fmt(ctx, "%s", str);

	this_ctx = tal_free(this_ctx);
}

/* Routes are computed and saved in the payment for later use. */
struct route **get_routes(const tal_t *ctx,
			  struct payment_info *payment_info,

			  const struct node_id *source,
			  const struct node_id *destination,
			  struct gossmap *gossmap,
			  struct uncertainty *uncertainty,
			  struct disabledmap *disabledmap,

			  struct amount_msat amount_to_deliver,
			  struct amount_msat feebudget,

			  u64 *next_partid,
			  u64 groupid,

			  enum jsonrpc_errcode *ecode,
			  const char **fail)
{
	assert(gossmap);
	assert(uncertainty);

	const tal_t *this_ctx = tal(ctx, tal_t);
	struct route **routes = tal_arr(ctx, struct route *, 0);

	double probability_budget = payment_info->min_prob_success;
	double delay_feefactor = payment_info->delay_feefactor;
	const double base_fee_penalty = payment_info->base_fee_penalty;
	const double prob_cost_factor = payment_info->prob_cost_factor;
	const unsigned int maxdelay = payment_info->maxdelay;
	const u32 max_hops = payment_info->max_hops;
	bool delay_feefactor_updated = true;

	bitmap *disabled_bitmap =
	    tal_disabledmap_get_bitmap(this_ctx, disabledmap, gossmap);

	if (!disabled_bitmap) {
		tal_report_error(ctx, ecode, fail, PLUGIN_ERROR,
				 "Failed to build disabled_bitmap.");
		goto function_fail;
	}

	/* Also disable every channel that we don't have in the chan_extra_map.
	 * We might have channels in the gossmap that are not usable for
	 * probability computations for example if we don't know their capacity.
	 * We can tell the solver to ignore those channels by disabling them
	 * here.
	 */
	for (struct gossmap_chan *chan = gossmap_first_chan(gossmap); chan;
	     chan = gossmap_next_chan(gossmap, chan)) {
		const u32 chan_id = gossmap_chan_idx(gossmap, chan);
		struct short_channel_id scid = gossmap_chan_scid(gossmap, chan);
		struct chan_extra *ce =
		    chan_extra_map_get(uncertainty->chan_extra_map, scid);
		if (!ce) {
			bitmap_set_bit(disabled_bitmap, chan_id * 2 + 0);
			bitmap_set_bit(disabled_bitmap, chan_id * 2 + 1);
		}
	}

	const struct gossmap_node *src, *dst;
	src = gossmap_find_node(gossmap, source);
	if (!src) {
		tal_report_error(ctx, ecode, fail, PAY_ROUTE_NOT_FOUND,
				 "We don't have any channels.");
		goto function_fail;
	}
	dst = gossmap_find_node(gossmap, destination);
	if (!dst) {
		tal_report_error(
		    ctx, ecode, fail, PAY_ROUTE_NOT_FOUND,
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

		/* Min. Cost Flow algorithm to find optimal flows. */
		struct flow **flows =
		    minflow(this_ctx, gossmap, src, dst,
			    uncertainty_get_chan_extra_map(uncertainty),
			    disabled_bitmap, amount_to_deliver, feebudget,
			    probability_budget, delay_feefactor,
			    base_fee_penalty, prob_cost_factor, max_hops,
			    &errmsg);
		delay_feefactor_updated = false;

		if (!flows) {
			tal_report_error(
			    ctx, ecode, fail, PAY_ROUTE_NOT_FOUND,
			    "minflow couldn't find a feasible flow: %s",
			    errmsg);
			goto function_fail;
		}

		enum renepay_errorcode errorcode;
		for (size_t i = 0; i < tal_count(flows); i++) {

			// do we overpay?
			if (amount_msat_greater(flows[i]->amount,
						amount_to_deliver)) {
				// should not happen
				tal_report_error(
				    ctx, ecode, fail, PLUGIN_ERROR,
				    "%s: flow is delivering to destination "
				    "(%s) more than requested (%s)",
				    __func__,
				    fmt_amount_msat(this_ctx, flows[i]->amount),
				    fmt_amount_msat(this_ctx,
						    amount_to_deliver));
				goto function_fail;
			}

			// fees considered, remove the least amount as to fit in
			// with the htlcmax constraints
			errorcode = flow_adjust_htlcmax_constraints(
			    flows[i], gossmap,
			    uncertainty_get_chan_extra_map(uncertainty),
			    disabled_bitmap);
			if (errorcode == RENEPAY_BAD_CHANNEL)
				// we handle a bad channel error by disabling
				// it, infinite loops are avoided since we have
				// everytime less and less channels
				continue;
			if (errorcode) {
				// any other error is bad
				tal_report_error(
				    ctx, ecode, fail, PLUGIN_ERROR,
				    "flow_adjust_htlcmax_constraints returned "
				    "errorcode: %s",
				    renepay_errorcode_name(errorcode));
				goto function_fail;
			}

			// a bound check, we shouldn't deliver a zero amount, it
			// would mean a bug somewhere
			if (amount_msat_zero(flows[i]->amount)) {
				tal_report_error(ctx, ecode, fail, PLUGIN_ERROR,
						 "flow conveys a zero amount");
				goto function_fail;
			}

			const double prob = flow_probability(
			    flows[i], gossmap,
			    uncertainty_get_chan_extra_map(uncertainty));
			if (prob < 0) {
				// should not happen
				tal_report_error(ctx, ecode, fail, PLUGIN_ERROR,
						 "flow_probability failed");
				goto function_fail;
			}

			// this flow seems good, build me a route
			struct route *r = flow_to_route(
			    this_ctx, groupid, *next_partid,
			    payment_info->payment_hash,
			    payment_info->final_cltv, gossmap, flows[i]);

			if (!r) {
				tal_report_error(
				    ctx, ecode, fail, PLUGIN_ERROR,
				    "%s failed to build route from flow.",
				    __func__);
				goto function_fail;
			}

			const struct amount_msat fee = route_fees(r);
			const struct amount_msat delivering = route_delivers(r);

			// are we still within the fee budget?
			if (amount_msat_greater(fee, feebudget)) {
				tal_report_error(
				    ctx, ecode, fail, PAY_ROUTE_TOO_EXPENSIVE,
				    "Fee exceeds our fee budget, fee=%s "
				    "(feebudget=%s)",
				    fmt_amount_msat(this_ctx, fee),
				    fmt_amount_msat(this_ctx, feebudget));
				goto function_fail;
			}

			// check the CLTV delay does not exceed our settings
			const unsigned int delay = route_delay(r);
			if (delay > maxdelay) {
				if (!delay_feefactor_updated) {
					delay_feefactor *= 2;
					delay_feefactor_updated = true;
				}

				/* FIXME: What is a sane limit? */
				if (delay_feefactor > 1000) {
					tal_report_error(
					    ctx, ecode, fail,
					    PAY_ROUTE_TOO_EXPENSIVE,
					    "CLTV delay exceeds our CLTV "
					    "budget, delay=%u (maxdelay=%u)",
					    delay, maxdelay);
					goto function_fail;
				}
				continue;
			}

			// check that the route satisfy all constraints
			errorcode = route_check_constraints(
			    r, gossmap, uncertainty, disabled_bitmap);

			if (errorcode == RENEPAY_BAD_CHANNEL)
				continue;
			if (errorcode) {
				// any other error is bad
				tal_report_error(
				    ctx, ecode, fail, PLUGIN_ERROR,
				    "route_check_constraints returned "
				    "errorcode: %s",
				    renepay_errorcode_name(errorcode));
				goto function_fail;
			}

			// update the fee budget
			if (!amount_msat_sub(&feebudget, feebudget, fee)) {
				// should never happen
				tal_report_error(
				    ctx, ecode, fail, PLUGIN_ERROR,
				    "%s routing fees (%s) exceed fee "
				    "budget (%s).",
				    __func__,
				    fmt_amount_msat(this_ctx, fee),
				    fmt_amount_msat(this_ctx, feebudget));
				goto function_fail;
			}

			// update the amount that we deliver
			if (!amount_msat_sub(&amount_to_deliver,
					     amount_to_deliver, delivering)) {
				// should never happen
				tal_report_error(
				    ctx, ecode, fail, PLUGIN_ERROR,
				    "%s: route delivering to destination (%s) "
				    "is more than requested (%s)",
				    __func__,
				    fmt_amount_msat(this_ctx, delivering),
				    fmt_amount_msat(this_ctx,
						    amount_to_deliver));
				goto function_fail;
			}

			// update the probability target
			if (prob < 1e-10) {
				// probability is too small for division
				probability_budget = 1.0;
			} else {
				/* prob here is a conditional probability, the
				 * next flow will have a conditional
				 * probability prob2 and we would like that
				 * prob*prob2 >= probability_budget hence
				 * probability_budget/prob becomes the next
				 * iteration's target. */
				probability_budget =
				    MIN(1.0, probability_budget / prob);
			}

			// route added
			(*next_partid)++;
			uncertainty_commit_htlcs(uncertainty, r);
			tal_arr_expand(&routes, r);
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
