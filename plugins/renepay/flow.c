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

struct amount_msat *tal_flow_amounts(const tal_t *ctx, const struct flow *flow,
				     bool compute_fees)
{
	const size_t pathlen = tal_count(flow->path);
	struct amount_msat *amounts = tal_arr(ctx, struct amount_msat, pathlen);
	amounts[pathlen - 1] = flow->amount;

	for (int i = (int)pathlen - 2; i >= 0; i--) {
		const struct half_chan *h = flow_edge(flow, i + 1);
		amounts[i] = amounts[i + 1];
		if (compute_fees &&
		    !amount_msat_add_fee(&amounts[i], h->base_fee,
					 h->proportional_fee))
			goto function_fail;
	}

	return amounts;

function_fail:
	return tal_free(amounts);
}

const char *fmt_flows(const tal_t *ctx, const struct gossmap *gossmap,
		      struct chan_extra_map *chan_extra_map,
		      struct flow **flows)
{
	tal_t *this_ctx = tal(ctx, tal_t);
	char *buff = tal_fmt(ctx, "%zu subflows\n", tal_count(flows));
	for (size_t i = 0; i < tal_count(flows); i++) {
		struct amount_msat fee, delivered;
		tal_append_fmt(&buff, "   ");
		for (size_t j = 0; j < tal_count(flows[i]->path); j++) {
			struct short_channel_id scid =
			    gossmap_chan_scid(gossmap, flows[i]->path[j]);
			tal_append_fmt(&buff, "%s%s", j ? "->" : "",
				       fmt_short_channel_id(this_ctx, scid));
		}
		delivered = flows[i]->amount;
		if (!flow_fee(&fee, flows[i])) {
			abort();
		}
		tal_append_fmt(&buff, " prob %.2f, %s delivered with fee %s\n",
			       flows[i]->success_prob,
			       fmt_amount_msat(this_ctx, delivered),
			       fmt_amount_msat(this_ctx, fee));
	}

	tal_free(this_ctx);
	return buff;
}

/* Returns the greatest amount we can deliver to the destination using this
 * route. It takes into account the current knowledge, pending HTLC,
 * htlc_max and fees.
 *
 * It fails if the maximum that we can
 * deliver at node i is smaller than the minimum required to forward the least
 * amount greater than zero to the next node. */
enum renepay_errorcode
flow_maximum_deliverable(struct amount_msat *max_deliverable,
			 const struct flow *flow,
			 const struct gossmap *gossmap,
			 struct chan_extra_map *chan_extra_map,
			 const struct gossmap_chan **bad_channel)
{
	assert(tal_count(flow->path) > 0);
	assert(tal_count(flow->dirs) > 0);
	assert(tal_count(flow->path) == tal_count(flow->dirs));
	struct amount_msat x;
	enum renepay_errorcode err;

	err = channel_liquidity(&x, gossmap, chan_extra_map, flow->path[0],
			       flow->dirs[0]);
	if(err){
		if(bad_channel)*bad_channel = flow->path[0];
		return err;
	}
	x = amount_msat_min(x, gossmap_chan_htlc_max(flow->path[0], flow->dirs[0]));

	if(amount_msat_zero(x))
	{
		if(bad_channel)*bad_channel = flow->path[0];
		return RENEPAY_BAD_CHANNEL;
	}

	for (size_t i = 1; i < tal_count(flow->path); ++i) {
		// ith node can forward up to 'liquidity_cap' because of the ith
		// channel liquidity bound
		struct amount_msat liquidity_cap;

		err = channel_liquidity(&liquidity_cap, gossmap, chan_extra_map,
				       flow->path[i], flow->dirs[i]);
		if(err) {
			if(bad_channel)*bad_channel = flow->path[i];
			return err;
		}

		/* ith node can receive up to 'x', therefore he will not forward
		 * more than 'forward_cap' that we compute below inverting the
		 * fee equation. */
		struct amount_msat forward_cap;
		err = channel_maximum_forward(&forward_cap, flow->path[i],
					     flow->dirs[i], x);
		if(err)
		{
			if(bad_channel)*bad_channel = flow->path[i];
			return err;
		}
		struct amount_msat x_new =
		    amount_msat_min(forward_cap, liquidity_cap);
		x_new = amount_msat_min(
		    x_new, gossmap_chan_htlc_max(flow->path[i], flow->dirs[i]));

		/* safety check: amounts decrease along the route */
		assert(amount_msat_less_eq(x_new, x));

		if(amount_msat_zero(x_new))
		{
			if(bad_channel)*bad_channel = flow->path[i];
			return RENEPAY_BAD_CHANNEL;
		}

		/* safety check: the max liquidity in the next hop + fees cannot
		 be greater than the max liquidity in the current hop, IF the
		 next hop is non-zero. */
		struct amount_msat x_check = x_new;
		assert(
		    amount_msat_add_fee(&x_check, flow_edge(flow, i)->base_fee,
					flow_edge(flow, i)->proportional_fee));
		assert(amount_msat_less_eq(x_check, x));

		x = x_new;
	}
	assert(!amount_msat_zero(x));
	*max_deliverable = x;
	return RENEPAY_NOERROR;
}

/* Returns the smallest amount we can send so that the destination can get one
 * HTLC of any size. It takes into account htlc_min and fees.
 * */
// static enum renepay_errorcode
// flow_minimum_sendable(struct amount_msat *min_sendable UNUSED,
// 		      const struct flow *flow UNUSED,
// 		      const struct gossmap *gossmap UNUSED,
// 		      struct chan_extra_map *chan_extra_map UNUSED)
// {
// 	// TODO
// 	return RENEPAY_NOERROR;
// }

/* How much do we deliver to destination using this set of routes */
bool flowset_delivers(struct amount_msat *delivers, struct flow **flows)
{
	struct amount_msat final = AMOUNT_MSAT(0);
	for (size_t i = 0; i < tal_count(flows); i++) {
		if (!amount_msat_add(&final, flows[i]->amount, final))
			return false;
	}
	*delivers = final;
	return true;
}

/* FIXME: pass a pointer to const here */
size_t flowset_size(struct flow **flows)
{
	size_t size = 0;
	for (size_t i = 0; i < tal_count(flows); i++)
		size += tal_count(flows[i]->path);
	return size;
}

/* Checks if the flows satisfy the liquidity bounds imposed by the known maximum
 * liquidity and pending HTLCs.
 *
 * FIXME The function returns false even in the case of failure. The caller has
 * no way of knowing the difference between a failure of evaluation and a
 * negative answer. */
// static bool check_liquidity_bounds(struct flow **flows,
// 				   const struct gossmap *gossmap,
// 				   struct chan_extra_map *chan_extra_map)
// {
// 	bool check = true;
// 	for (size_t i = 0; i < tal_count(flows); ++i) {
// 		struct amount_msat max_deliverable;
// 		if (!flow_maximum_deliverable(&max_deliverable, flows[i],
// 					      gossmap, chan_extra_map))
// 			return false;
// 		struct amount_msat delivers = flow_delivers(flows[i]);
// 		check &= amount_msat_less_eq(delivers, max_deliverable);
// 	}
// 	return check;
// }

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

/* @ctx: allocator
 * @flows: flows for which the probability is computed
 * @gossmap: gossip
 * @chan_extra_map: knowledge
 * @compute_fees: compute fees along the way or not
 * @fail: if a failure occurs, returns a message to the caller
 * */
// TODO(eduardo): here chan_extra_map should be const
// TODO(eduardo): here flows should be const
double flowset_probability(const tal_t *ctx, struct flow **flows,
			   const struct gossmap *const gossmap,
			   struct chan_extra_map *chan_extra_map,
			   bool compute_fees,
			   char **fail)
{
	assert(flows);
	assert(gossmap);
	assert(chan_extra_map);
	tal_t *this_ctx = tal(ctx, tal_t);
	double prob = 1.0;

	// TODO(eduardo): should it be better to use a map instead of an array
	// here?
	const size_t max_num_chans = gossmap_max_chan_idx(gossmap);
	struct chan_inflight_flow *in_flight =
	    tal_arr(this_ctx, struct chan_inflight_flow, max_num_chans);

	if (!in_flight) {
		if (fail)
			*fail = tal_fmt(ctx, "failed to allocate memory");
		goto function_fail;
	}

	for (size_t i = 0; i < max_num_chans; ++i) {
		in_flight[i].half[0] = in_flight[i].half[1] = AMOUNT_MSAT(0);
	}

	for (size_t i = 0; i < tal_count(flows); ++i) {
		const struct flow *f = flows[i];
		const size_t pathlen = tal_count(f->path);
		struct amount_msat *amounts =
		    tal_flow_amounts(this_ctx, f, compute_fees);
		if (!amounts)
		{
			if (fail)
			*fail = tal_fmt(
			    ctx,
			    "failed to compute amounts along the path");
			goto function_fail;
		}

		for (size_t j = 0; j < pathlen; ++j) {
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

			const struct amount_msat deliver = amounts[j];

			struct amount_msat prev_flow, all_inflight;
			if (!amount_msat_add(&prev_flow, h->htlc_total,
					     in_flight[c_idx].half[c_dir]) ||
			    !amount_msat_add(&all_inflight, prev_flow,
					     deliver)) {
				if (fail)
					*fail = tal_fmt(
					    ctx,
					    "in-flight amount_msat overflow");
				goto function_fail;
			}

			if (!amount_msat_less_eq(all_inflight, h->known_max)) {
				if (fail)
					*fail = tal_fmt(
					    ctx,
					    "in-flight (%s) exceeds known_max "
					    "(%s)",
					    fmt_amount_msat(ctx, all_inflight),
					    fmt_amount_msat(ctx, h->known_max));
				goto function_fail;
			}

			double edge_prob = edge_probability(
			    h->known_min, h->known_max, prev_flow, deliver);

			if (edge_prob < 0) {
				if (fail)
				*fail = tal_fmt(ctx,
						"edge_probability failed");
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

bool flow_spend(struct amount_msat *ret, struct flow *flow)
{
	assert(ret);
	assert(flow);
	const size_t pathlen = tal_count(flow->path);
	struct amount_msat spend = flow->amount;

	for (int i = (int)pathlen - 2; i >= 0; i--) {
		const struct half_chan *h = flow_edge(flow, i + 1);
		if (!amount_msat_add_fee(&spend, h->base_fee,
					 h->proportional_fee))
			goto function_fail;
	}

	*ret = spend;
	return true;

function_fail:
	return false;
}

bool flow_fee(struct amount_msat *ret, struct flow *flow)
{
	assert(ret);
	assert(flow);
	struct amount_msat fee;
	struct amount_msat spend;
	if (!flow_spend(&spend, flow))
		goto function_fail;
	if (!amount_msat_sub(&fee, spend, flow->amount))
		goto function_fail;

	*ret = fee;
	return true;

function_fail:
	return false;
}

bool flowset_fee(struct amount_msat *ret, struct flow **flows)
{
	assert(ret);
	assert(flows);
	struct amount_msat fee = AMOUNT_MSAT(0);
	for (size_t i = 0; i < tal_count(flows); i++) {
		struct amount_msat this_fee;
		if (!flow_fee(&this_fee, flows[i]))
			return false;
		if (!amount_msat_add(&fee, this_fee, fee))
			return false;
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

/* Assign the delivered amount to the flow if it fits
 the path maximum capacity. */
bool flow_assign_delivery(struct flow *flow, const struct gossmap *gossmap,
			  struct chan_extra_map *chan_extra_map,
			  struct amount_msat requested_amount)
{
	struct amount_msat max_deliverable = AMOUNT_MSAT(0);
	if (flow_maximum_deliverable(&max_deliverable, flow, gossmap,
				      chan_extra_map, NULL))
		return false;
	assert(!amount_msat_zero(max_deliverable));
	flow->amount = amount_msat_min(requested_amount, max_deliverable);
	return true;
}

/* Helper function to find the success_prob for a single flow
 *
 * IMPORTANT: flow->success_prob is misleading, because that's the prob. of
 * success provided that there are no other flows in the current MPP flow set.
 * */
double flow_probability(struct flow *flow, const struct gossmap *gossmap,
			struct chan_extra_map *chan_extra_map,
			bool compute_fees)
{
	assert(flow);
	assert(gossmap);
	assert(chan_extra_map);
	const size_t pathlen = tal_count(flow->path);
	struct amount_msat spend = flow->amount;
	double prob = 1.0;

	for (int i = (int)pathlen - 1; i >= 0; i--) {
		const struct half_chan *h = flow_edge(flow, i);
		const struct chan_extra_half *eh = get_chan_extra_half_by_chan(
		    gossmap, chan_extra_map, flow->path[i], flow->dirs[i]);

		prob *= edge_probability(eh->known_min, eh->known_max,
					 eh->htlc_total, spend);

		if (prob < 0)
			goto function_fail;
		if (compute_fees && !amount_msat_add_fee(&spend, h->base_fee,
							 h->proportional_fee))
			goto function_fail;
	}

	return prob;

function_fail:
	return -1.;
}

u64 flow_delay(const struct flow *flow)
{
	u64 delay = 0;
	for (size_t i = 0; i < tal_count(flow->path); i++)
		delay += flow_edge(flow, i)->delay;
	return delay;
}

u64 flows_worst_delay(struct flow **flows)
{
	u64 maxdelay = 0;
	for (size_t i = 0; i < tal_count(flows); i++) {
		u64 delay = flow_delay(flows[i]);
		if (delay > maxdelay)
			maxdelay = delay;
	}
	return maxdelay;
}

#ifndef SUPERVERBOSE_ENABLED
#undef SUPERVERBOSE
#endif
