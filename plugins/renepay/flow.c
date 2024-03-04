#include "config.h"
#include <assert.h>
#include <ccan/tal/str/str.h>
#include <ccan/tal/tal.h>
#include <common/fp16.h>
#include <common/overflows.h>
#include <math.h>
#include <plugins/renepay/flow.h>
#include <stdio.h>

#ifndef SUPERVERBOSE
#define SUPERVERBOSE(...)
#else
#define SUPERVERBOSE_ENABLED 1
#endif

/* Returns the greatest amount we can deliver to the destination using this
 * route. It takes into account the current knowledge, pending HTLC,
 * htlc_max and fees. */
static bool flow_maximum_deliverable(struct amount_msat *max_deliverable,
				     const struct flow *flow,
				     const struct gossmap *gossmap,
				     struct chan_extra_map *chan_extra_map)
{
	assert(tal_count(flow->path) > 0);
	assert(tal_count(flow->dirs) > 0);
	assert(tal_count(flow->path) == tal_count(flow->dirs));
	struct amount_msat x;

	if (!channel_liquidity(&x, gossmap, chan_extra_map, flow->path[0],
			       flow->dirs[0]))
		return false;
	x = amount_msat_min(x, channel_htlc_max(flow->path[0], flow->dirs[0]));

	for (size_t i = 1; i < tal_count(flow->path); ++i) {
		// ith node can forward up to 'liquidity_cap' because of the ith
		// channel liquidity bound
		struct amount_msat liquidity_cap;

		if (!channel_liquidity(&liquidity_cap, gossmap, chan_extra_map,
				       flow->path[i], flow->dirs[i]))
			return false;

		/* ith node can receive up to 'x', therefore he will not forward
		 * more than 'forward_cap' that we compute below inverting the
		 * fee equation. */
		struct amount_msat forward_cap;
		if (!channel_maximum_forward(&forward_cap, flow->path[i],
					     flow->dirs[i], x))
			return false;

		struct amount_msat x_new =
		    amount_msat_min(forward_cap, liquidity_cap);
		x_new = amount_msat_min(
		    x_new, channel_htlc_max(flow->path[i], flow->dirs[i]));

		if (!amount_msat_less_eq(x_new, x))
			return false;

		// safety check: amounts decrease along the route
		assert(amount_msat_less_eq(x_new, x));

		struct amount_msat x_check = x_new;

		if (!amount_msat_zero(x_new) &&
		    !amount_msat_add_fee(&x_check, flow_edge(flow, i)->base_fee,
					 flow_edge(flow, i)->proportional_fee))
			return false;

		// safety check: the max liquidity in the next hop + fees cannot
		// be greater than then max liquidity in the current hop, IF the
		// next hop is non-zero.
		assert(amount_msat_less_eq(x_check, x));

		x = x_new;
	}
	*max_deliverable = x;
	return true;
}

/* How much do we deliver to destination using this set of routes */
static bool flow_set_delivers(struct amount_msat *delivers, struct flow **flows)
{
	struct amount_msat final = AMOUNT_MSAT(0);
	for (size_t i = 0; i < tal_count(flows); i++) {
		size_t n = tal_count(flows[i]->amounts);
		struct amount_msat this_final = flows[i]->amounts[n - 1];

		if (!amount_msat_add(&final, this_final, final))
			return false;
	}
	*delivers = final;
	return true;
}

/* How much this flow (route with amounts) is delivering to the destination
 * node. */
static inline struct amount_msat flow_delivers(const struct flow *flow)
{
	return flow->amounts[tal_count(flow->amounts) - 1];
}

/* Checks if the flows satisfy the liquidity bounds imposed by the known maximum
 * liquidity and pending HTLCs.
 *
 * FIXME The function returns false even in the case of failure. The caller has
 * no way of knowing the difference between a failure of evaluation and a
 * negative answer. */
static bool check_liquidity_bounds(struct flow **flows,
				   const struct gossmap *gossmap,
				   struct chan_extra_map *chan_extra_map)
{
	bool check = true;
	for (size_t i = 0; i < tal_count(flows); ++i) {
		struct amount_msat max_deliverable;
		if (!flow_maximum_deliverable(&max_deliverable, flows[i],
					      gossmap, chan_extra_map))
			return false;
		struct amount_msat delivers = flow_delivers(flows[i]);
		check &= amount_msat_less_eq(delivers, max_deliverable);
	}
	return check;
}

/* flows should be a set of optimal routes delivering an amount that is
 * slighty less than amount_to_deliver. We will try to reallocate amounts in
 * these flows so that it delivers the exact amount_to_deliver to the
 * destination.
 * Returns how much we are delivering at the end. */
bool flows_fit_amount(const tal_t *ctx, struct amount_msat *amount_allocated,
		      struct flow **flows, struct amount_msat amount_to_deliver,
		      const struct gossmap *gossmap,
		      struct chan_extra_map *chan_extra_map, char **fail)
{
	tal_t *this_ctx = tal(ctx, tal_t);
	char *errmsg;

	struct amount_msat total_deliver;
	if (!flow_set_delivers(&total_deliver, flows)) {
		if (fail)
			*fail = tal_fmt(
			    ctx, "(%s, line %d) flow_set_delivers failed",
			    __PRETTY_FUNCTION__, __LINE__);
		goto function_fail;
	}
	if (amount_msat_greater_eq(total_deliver, amount_to_deliver)) {
		*amount_allocated = total_deliver;
		goto function_success;
	}

	struct amount_msat deficit;
	if (!amount_msat_sub(&deficit, amount_to_deliver, total_deliver)) {
		// this should not happen, because we already checked that
		// total_deliver<amount_to_deliver
		if (fail)
			*fail = tal_fmt(
			    ctx,
			    "(%s, line %d) unexpected amount_msat_sub failure",
			    __PRETTY_FUNCTION__, __LINE__);
		goto function_fail;
	}

	/* FIXME Current algorithm assigns as much of the deficit as possible to
	 * the list of routes, we can improve this lets say in order to maximize
	 * the probability. If the deficit is very small with respect to the
	 * amount each flow carries then optimization here will not make much
	 * difference. */
	for (size_t i = 0; i < tal_count(flows) && !amount_msat_zero(deficit);
	     ++i) {
		struct amount_msat max_deliverable;
		if (!flow_maximum_deliverable(&max_deliverable, flows[i],
					      gossmap, chan_extra_map)) {
			if (fail)
				*fail =
				    tal_fmt(ctx,
					    "(%s, line %d) "
					    "flow_maximum_deliverable failed",
					    __PRETTY_FUNCTION__, __LINE__);

			goto function_fail;
		}
		struct amount_msat delivers = flow_delivers(flows[i]);

		struct amount_msat diff;
		if (!amount_msat_sub(&diff, max_deliverable, delivers)) {
			// this should never happen, a precondition of this
			// function is that the flows already respect the
			// liquidity bounds.
			if (fail)
				*fail = tal_fmt(ctx,
						"(%s, line %d) unexpected "
						"amount_msat_sub failure",
						__PRETTY_FUNCTION__, __LINE__);

			goto function_fail;
		}

		if (amount_msat_zero(diff))
			continue;

		diff = amount_msat_min(diff, deficit);

		if (!amount_msat_sub(&deficit, deficit, diff)) {
			// this should never happen
			if (fail)
				*fail = tal_fmt(ctx,
						"(%s, line %d) unexpected "
						"amount_msat_sub failure",
						__PRETTY_FUNCTION__, __LINE__);
			goto function_fail;
		}
		if (!amount_msat_add(&delivers, delivers, diff)) {
			if (fail)
				*fail = tal_fmt(
				    ctx,
				    "(%s, line %d) amount_msat_add overflow",
				    __PRETTY_FUNCTION__, __LINE__);
			goto function_fail;
		}

		if (!flow_complete(this_ctx, flows[i], gossmap, chan_extra_map,
				   delivers, &errmsg)) {
			if (fail)
				*fail = tal_fmt(
				    ctx,
				    "(%s, line %d) flow_complete failed: %s",
				    __PRETTY_FUNCTION__, __LINE__, errmsg);
			goto function_fail;
		}
	}
	if (!check_liquidity_bounds(flows, gossmap, chan_extra_map)) {
		// this should not happen if our algorithm is correct
		if (fail)
			*fail = tal_fmt(ctx,
					"(%s, line %d) liquidity bounds not "
					"satisfied or failed check",
					__PRETTY_FUNCTION__, __LINE__);
		goto function_fail;
	}
	if (!flow_set_delivers(amount_allocated, flows)) {
		if (fail)
			*fail = tal_fmt(
			    ctx, "(%s, line %d) flow_set_delivers failed",
			    __PRETTY_FUNCTION__, __LINE__);
		goto function_fail;
	}

function_success:
	tal_free(this_ctx);
	return true;

function_fail:
	tal_free(this_ctx);
	return false;
}

/* Helper function to fill in amounts and success_prob for flow
 *
 * @ctx: tal context for allocated objects that outlive this function call, eg.
 * fail
 * @flow: the flow we want to complete with precise amounts
 * @gossmap: state of the network
 * @chan_extra_map: state of the network
 * @delivered: how much we are supposed to deliver at destination
 * @fail: here we write verbose message errors in case of failure
 *
 * IMPORTANT: here we do not commit flows to chan_extra, flows are commited
 * after we send those htlc.
 *
 * IMPORTANT: flow->success_prob is misleading, because that's the prob. of
 * success provided that there are no other flows in the current MPP flow set.
 * */
bool flow_complete(const tal_t *ctx, struct flow *flow,
		   const struct gossmap *gossmap,
		   struct chan_extra_map *chan_extra_map,
		   struct amount_msat delivered, char **fail)
{
	assert(flow);
	assert(gossmap);
	assert(chan_extra_map);
	tal_t *this_ctx = tal(ctx, tal_t);
	char *errmsg;

	flow->success_prob = 1.0;
	flow->amounts =
	    tal_arr(flow, struct amount_msat, tal_count(flow->path));

	struct amount_msat max_deliverable;
	if (!flow_maximum_deliverable(&max_deliverable, flow, gossmap,
				      chan_extra_map)) {
		if (fail)
			*fail = tal_fmt(ctx, "flow_maximum_deliverable failed");
		goto function_fail;
	}
	// we cannot deliver more than it is allowed by the liquidity
	// constraints: HTLC max, fees, known_max
	delivered = amount_msat_min(delivered, max_deliverable);

	for (int i = tal_count(flow->path) - 1; i >= 0; i--) {
		const struct chan_extra_half *h = get_chan_extra_half_by_chan(
		    gossmap, chan_extra_map, flow->path[i], flow->dirs[i]);

		if (!h) {
			if (fail)
				*fail = tal_fmt(
				    ctx, "channel not found in chan_extra_map");
			goto function_fail;
		}

		flow->amounts[i] = delivered;
		double prob =
		    edge_probability(this_ctx, h->known_min, h->known_max,
				     h->htlc_total, delivered, &errmsg);
		if (prob < 0) {
			if (fail)
				*fail = tal_fmt(
				    ctx, "edge_probability failed: %s", errmsg);
			goto function_fail;
		}
		flow->success_prob *= prob;

		if (!amount_msat_add_fee(
			&delivered, flow_edge(flow, i)->base_fee,
			flow_edge(flow, i)->proportional_fee)) {
			if (fail)
				*fail = tal_fmt(ctx, "fee overflow");
			goto function_fail;
		}
	}
	tal_free(this_ctx);
	return true;

function_fail:
	tal_free(this_ctx);
	return false;
}

/* Compute the prob. of success of a set of concurrent set of flows.
 *
 * IMPORTANT: this is not simply the multiplication of the prob. of success of
 * all of them, because they're not independent events. A flow that passes
 * through a channel c changes that channel's liquidity and then if another flow
 * passes through that same channel the previous liquidity change must be taken
 * into account.
 *
 * 	P(A and B) != P(A) * P(B),
 *
 * but
 *
 * 	P(A and B) = P(A) * P(B | A)
 *
 * also due to the linear form of P() we have
 *
 * 	P(A and B) = P(A + B)
 * 	*/
struct chan_inflight_flow
{
	struct amount_msat half[2];
};

// TODO(eduardo): here chan_extra_map should be const
// TODO(eduardo): here flows should be const
double flowset_probability(const tal_t *ctx, struct flow **flows,
			   const struct gossmap *const gossmap,
			   struct chan_extra_map *chan_extra_map, char **fail)
{
	assert(flows);
	assert(gossmap);
	assert(chan_extra_map);
	tal_t *this_ctx = tal(ctx, tal_t);
	char *errmsg;
	double prob = 1.0;

	// TODO(eduardo): should it be better to use a map instead of an array
	// here?
	const size_t max_num_chans = gossmap_max_chan_idx(gossmap);
	struct chan_inflight_flow *in_flight =
	    tal_arr(this_ctx, struct chan_inflight_flow, max_num_chans);

	for (size_t i = 0; i < max_num_chans; ++i) {
		in_flight[i].half[0] = in_flight[i].half[1] = AMOUNT_MSAT(0);
	}

	for (size_t i = 0; i < tal_count(flows); ++i) {
		const struct flow *f = flows[i];
		for (size_t j = 0; j < tal_count(f->path); ++j) {
			const struct chan_extra_half *h =
			    get_chan_extra_half_by_chan(gossmap, chan_extra_map,
							f->path[j], f->dirs[j]);
			if (!h) {
				if (fail)
				*fail = tal_fmt(
				    ctx,
				    "channel not found in chan_extra_map");
				goto function_fail;
			}
			const u32 c_idx = gossmap_chan_idx(gossmap, f->path[j]);
			const int c_dir = f->dirs[j];

			const struct amount_msat deliver = f->amounts[j];

			struct amount_msat prev_flow;
			if (!amount_msat_add(&prev_flow, h->htlc_total,
					     in_flight[c_idx].half[c_dir])) {
				if (fail)
				*fail = tal_fmt(
				    ctx, "in-flight amount_msat overflow");
				goto function_fail;
			}

			double edge_prob =
			    edge_probability(this_ctx, h->known_min, h->known_max,
					     prev_flow, deliver, &errmsg);
			if (edge_prob < 0) {
				if (fail)
				*fail = tal_fmt(ctx,
						"edge_probability failed: %s",
						errmsg);
				goto function_fail;
			}
			prob *= edge_prob;

			if (!amount_msat_add(&in_flight[c_idx].half[c_dir],
					     in_flight[c_idx].half[c_dir],
					     deliver)) {
				if (fail)
				*fail = tal_fmt(
				    ctx, "in-flight amount_msat overflow");
				goto function_fail;
			}
		}
	}
	tal_free(this_ctx);
	return prob;

	function_fail:
	tal_free(this_ctx);
	return -1;
}

bool flowset_fee(struct amount_msat *ret, struct flow **flows)
{
	assert(ret);
	assert(flows);
	struct amount_msat fee = AMOUNT_MSAT(0);

	for (size_t i = 0; i < tal_count(flows); i++) {
		struct amount_msat this_fee;
		size_t n = tal_count(flows[i]->amounts);

		if (!amount_msat_sub(&this_fee, flows[i]->amounts[0],
				     flows[i]->amounts[n - 1])) {
			return false;
		}
		if (!amount_msat_add(&fee, this_fee, fee)) {
			return false;
		}
	}
	*ret = fee;
	return true;
}

/* Helper to access the half chan at flow index idx */
const struct half_chan *flow_edge(const struct flow *flow, size_t idx)
{
	assert(flow);
	assert(idx < tal_count(flow->path));
	return &flow->path[idx]->half[flow->dirs[idx]];
}

#ifndef SUPERVERBOSE_ENABLED
#undef SUPERVERBOSE
#endif
