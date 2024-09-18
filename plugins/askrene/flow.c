#include "config.h"
#include <assert.h>
#include <ccan/tal/str/str.h>
#include <ccan/tal/tal.h>
#include <common/fp16.h>
#include <common/overflows.h>
#include <math.h>
#include <plugins/askrene/askrene.h>
#include <plugins/askrene/flow.h>
#include <plugins/libplugin.h>
#include <stdio.h>

#ifndef SUPERVERBOSE
#define SUPERVERBOSE(...)
#else
#define SUPERVERBOSE_ENABLED 1
#endif

/* Checks BOLT 7 HTLC fee condition:
 *	recv >= base_fee + (send*proportional_fee)/1000000 */
static bool check_fee_inequality(struct amount_msat recv, struct amount_msat send,
				 u64 base_fee, u64 proportional_fee)
{
	// nothing to forward, any incoming amount is good
	if (amount_msat_is_zero(send))
		return true;
	// FIXME If this addition fails we return false. The caller will not be
	// able to know that there was an addition overflow, he will just assume
	// that the fee inequality was not satisfied.
	if (!amount_msat_add_fee(&send, base_fee, proportional_fee))
		return false;
	return amount_msat_greater_eq(recv, send);
}

/* Let `recv` be the maximum amount this channel can receive, this function
 * computes the maximum amount this channel can forward `send`.
 * From BOLT7 specification wee need to satisfy the following inequality:
 *
 *	recv-send >= base_fee + floor(send*proportional_fee/1000000)
 *
 * That is equivalent to have
 *
 *	send <= Bound(recv,send)
 *
 * where
 *
 *	Bound(recv, send) = ((recv - base_fee)*1000000 + (send*proportional_fee)
 *% 1000000)/(proportional_fee+1000000)
 *
 * However the quantity we want to determine, `send`, appears on both sides of
 * the equation. However the term `send*proportional_fee) % 1000000` only
 * contributes by increasing the bound by at most one so that we can neglect
 * the extra term and use instead
 *
 *	Bound_simple(recv) = ((recv -
 *base_fee)*1000000)/(proportional_fee+1000000)
 *
 * as the upper bound for `send`. Formally one can check that
 *
 *	Bound_simple(recv) <= Bound(recv, send) < Bound_simple(recv) + 2
 *
 * So that if one wishes to find the very highest value of `send` that
 * satisfies
 *
 *	send <= Bound(recv, send)
 *
 * it is enough to compute
 *
 *	send = Bound_simple(recv)
 *
 *  which already satisfies the fee equation and then try to go higher
 *  with send+1, send+2, etc. But we know that it is enough to try up to
 *  send+1 because Bound(recv, send) < Bound_simple(recv) + 2.
 * */
static struct amount_msat channel_maximum_forward(const struct gossmap_chan *chan,
						  const int dir,
						  struct amount_msat recv)
{
	const u64 b = chan->half[dir].base_fee,
		  p = chan->half[dir].proportional_fee;

	const u64 one_million = 1000000;
	u64 x_msat =
	    recv.millisatoshis; /* Raw: need to invert the fee equation */

	// special case, when recv - base_fee <= 0, we cannot forward anything
	if (x_msat <= b)
		return AMOUNT_MSAT(0);

	x_msat -= b;

	/* recv must be a real number of msat... */
	assert(!mul_overflows_u64(one_million, x_msat));

	struct amount_msat best_send =
	    AMOUNT_MSAT_INIT((one_million * x_msat) / (one_million + p));

	/* Try to increase the value we send (up tp the last millisat) until we
	 * fail to fulfill the fee inequality. It takes only one iteration
	 * though. */
	for (size_t i = 0; i < 10; ++i) {
		struct amount_msat next_send;
		if (!amount_msat_add(&next_send, best_send, amount_msat(1)))
			abort();

		if (check_fee_inequality(recv, next_send, b, p))
			best_send = next_send;
		else
			break;
	}
	return best_send;
}

static struct amount_msat *flow_amounts(const tal_t *ctx,
					struct plugin *plugin,
					const struct flow *flow)
{
	const size_t pathlen = tal_count(flow->path);
	struct amount_msat *amounts = tal_arr(ctx, struct amount_msat, pathlen);
	amounts[pathlen - 1] = flow->amount;

	for (int i = (int)pathlen - 2; i >= 0; i--) {
		const struct half_chan *h = flow_edge(flow, i + 1);
		amounts[i] = amounts[i + 1];
		if (!amount_msat_add_fee(&amounts[i], h->base_fee,
					 h->proportional_fee)) {
			plugin_err(plugin, "Could not add fee %u/%u to amount %s in %i/%zu",
				   h->base_fee, h->proportional_fee,
				   fmt_amount_msat(tmpctx, amounts[i+1]),
				   i, pathlen);
		}
	}

	return amounts;
}

const char *fmt_flows(const tal_t *ctx, const struct route_query *rq,
		      struct flow **flows)
{
	double tot_prob = flowset_probability(flows, rq);
	assert(tot_prob >= 0);
	char *buff = tal_fmt(ctx, "%zu subflows, prob %2lf\n", tal_count(flows),
			     tot_prob);
	for (size_t i = 0; i < tal_count(flows); i++) {
		struct amount_msat fee, delivered;
		tal_append_fmt(&buff, "   ");
		for (size_t j = 0; j < tal_count(flows[i]->path); j++) {
			struct short_channel_id scid =
			    gossmap_chan_scid(rq->gossmap, flows[i]->path[j]);
			tal_append_fmt(&buff, "%s%s", j ? "->" : "",
				       fmt_short_channel_id(tmpctx, scid));
		}
		delivered = flows[i]->amount;
		fee = flow_fee(rq->plugin, flows[i]);
		tal_append_fmt(&buff, " prob %.2f, %s delivered with fee %s\n",
			       flows[i]->success_prob,
			       fmt_amount_msat(tmpctx, delivered),
			       fmt_amount_msat(tmpctx, fee));
	}

	return buff;
}

/* Returns the greatest amount we can deliver to the destination using this
 * route. It takes into account the current knowledge, pending HTLC,
 * htlc_max and fees.
 *
 * It fails if the maximum that we can
 * deliver at node i is smaller than the minimum required to forward the least
 * amount greater than zero to the next node. */
const struct gossmap_chan *
flow_maximum_deliverable(struct amount_msat *max_deliverable,
			 const struct flow *flow,
			 const struct route_query *rq)
{
	struct amount_msat maxcap;

	assert(tal_count(flow->path) > 0);
	assert(tal_count(flow->dirs) > 0);
	assert(tal_count(flow->path) == tal_count(flow->dirs));

	get_constraints(rq, flow->path[0], flow->dirs[0], NULL, &maxcap);
	maxcap = amount_msat_min(maxcap, gossmap_chan_htlc_max(flow->path[0], flow->dirs[0]));

	if (amount_msat_is_zero(maxcap))
		return flow->path[0];

	for (size_t i = 1; i < tal_count(flow->path); ++i) {
		// ith node can forward up to 'liquidity_cap' because of the ith
		// channel liquidity bound
		struct amount_msat liquidity_cap;

		get_constraints(rq, flow->path[i], flow->dirs[i], NULL, &liquidity_cap);

		/* ith node can receive up to 'x', therefore he will not forward
		 * more than 'forward_cap' that we compute below inverting the
		 * fee equation. */
		struct amount_msat forward_cap;
		forward_cap = channel_maximum_forward(flow->path[i], flow->dirs[i],
						      maxcap);
		struct amount_msat new_max = amount_msat_min(forward_cap, liquidity_cap);
		new_max = amount_msat_min(new_max,
					  gossmap_chan_htlc_max(flow->path[i], flow->dirs[i]));

		/* safety check: amounts decrease along the route */
		assert(amount_msat_less_eq(new_max, maxcap));

		if (amount_msat_is_zero(new_max))
			return flow->path[i];

		/* safety check: the max liquidity in the next hop + fees cannot
		 be greater than the max liquidity in the current hop, IF the
		 next hop is non-zero. */
		struct amount_msat check = new_max;
		assert(
		    amount_msat_add_fee(&check, flow_edge(flow, i)->base_fee,
					flow_edge(flow, i)->proportional_fee));
		assert(amount_msat_less_eq(check, maxcap));

		maxcap = new_max;
	}
	assert(!amount_msat_is_zero(maxcap));
	*max_deliverable = maxcap;
	return NULL;
}

/* Returns the smallest amount we can send so that the destination can get one
 * HTLC of any size. It takes into account htlc_min and fees.
 * */
// static enum askrene_errorcode
// flow_minimum_sendable(struct amount_msat *min_sendable UNUSED,
// 		      const struct flow *flow UNUSED,
// 		      const struct gossmap *gossmap UNUSED,
// 		      struct chan_extra_map *chan_extra_map UNUSED)
// {
// 	// TODO
// 	return ASKRENE_NOERROR;
// }

/* How much do we deliver to destination using this set of routes */
struct amount_msat flowset_delivers(struct plugin *plugin,
				    struct flow **flows)
{
	struct amount_msat final = AMOUNT_MSAT(0);
	for (size_t i = 0; i < tal_count(flows); i++) {
		if (!amount_msat_accumulate(&final, flows[i]->amount)) {
			plugin_err(plugin, "Could not add flowsat %s to %s (%zu/%zu)",
				   fmt_amount_msat(tmpctx, flows[i]->amount),
				   fmt_amount_msat(tmpctx, final),
				   i, tal_count(flows));
		}
	}
	return final;
}

static double edge_probability(struct amount_msat sent,
			       struct amount_msat mincap,
			       struct amount_msat maxcap,
			       struct amount_msat used)
{
	struct amount_msat numerator, denominator;

	if (!amount_msat_sub(&mincap, mincap, used))
		mincap = AMOUNT_MSAT(0);
	if (!amount_msat_sub(&maxcap, maxcap, used))
		maxcap = AMOUNT_MSAT(0);

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

double flowset_probability(struct flow **flows,
			   const struct route_query *rq)
{
	double prob = 1.0;

	// TODO(eduardo): should it be better to use a map instead of an array
	// here?
	const size_t max_num_chans = gossmap_max_chan_idx(rq->gossmap);
	struct chan_inflight_flow *in_flight =
	    tal_arrz(tmpctx, struct chan_inflight_flow, max_num_chans);

	for (size_t i = 0; i < tal_count(flows); ++i) {
		const struct flow *f = flows[i];
		const size_t pathlen = tal_count(f->path);
		struct amount_msat *amounts = flow_amounts(tmpctx, rq->plugin, f);

		for (size_t j = 0; j < pathlen; ++j) {
			struct amount_msat mincap, maxcap;
			const int c_dir = f->dirs[j];
			const u32 c_idx = gossmap_chan_idx(rq->gossmap, f->path[j]);
			const struct amount_msat deliver = amounts[j];

			get_constraints(rq, f->path[j], c_dir, &mincap, &maxcap);

			prob *= edge_probability(deliver, mincap, maxcap,
						 in_flight[c_idx].half[c_dir]);

			if (!amount_msat_accumulate(&in_flight[c_idx].half[c_dir],
						    deliver)) {
				plugin_err(rq->plugin, "Could not add %s to inflight %s",
					   fmt_amount_msat(tmpctx, deliver),
					   fmt_amount_msat(tmpctx, in_flight[c_idx].half[c_dir]));
			}
		}
	}
	return prob;
}

struct amount_msat flow_spend(struct plugin *plugin, const struct flow *flow)
{
	const size_t pathlen = tal_count(flow->path);
	struct amount_msat spend = flow->amount;

	for (int i = (int)pathlen - 1; i >= 0; i--) {
		const struct half_chan *h = flow_edge(flow, i);
		if (!amount_msat_add_fee(&spend, h->base_fee,
					 h->proportional_fee)) {
			plugin_err(plugin, "Could not add fee %u/%u to amount %s in %i/%zu",
				   h->base_fee, h->proportional_fee,
				   fmt_amount_msat(tmpctx, spend),
				   i, pathlen);
		}
	}

	return spend;
}

struct amount_msat flow_fee(struct plugin *plugin, const struct flow *flow)
{
	struct amount_msat spend = flow_spend(plugin, flow);
	struct amount_msat fee;
	if (!amount_msat_sub(&fee, spend, flow->amount)) {
		plugin_err(plugin, "Could not subtract %s from %s for fee",
				   fmt_amount_msat(tmpctx, flow->amount),
				   fmt_amount_msat(tmpctx, spend));
	}

	return fee;
}

struct amount_msat flowset_fee(struct plugin *plugin, struct flow **flows)
{
	struct amount_msat fee = AMOUNT_MSAT(0);
	for (size_t i = 0; i < tal_count(flows); i++) {
		struct amount_msat this_fee = flow_fee(plugin, flows[i]);
		if (!amount_msat_accumulate(&fee, this_fee)) {
			plugin_err(plugin, "Could not add %s to %s for flowset fee",
				   fmt_amount_msat(tmpctx, this_fee),
				   fmt_amount_msat(tmpctx, fee));
		}
	}
	return fee;
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
const struct gossmap_chan *
flow_assign_delivery(struct flow *flow,
		     const struct route_query *rq,
		     struct amount_msat requested_amount)
{
	struct amount_msat max_deliverable;
	const struct gossmap_chan *badchan;

	badchan = flow_maximum_deliverable(&max_deliverable, flow, rq);
	if (badchan)
		return badchan;
	assert(!amount_msat_is_zero(max_deliverable));
	flow->amount = amount_msat_min(requested_amount, max_deliverable);
	return NULL;
}

/* Helper function to find the success_prob for a single flow
 *
 * IMPORTANT: flow->success_prob is misleading, because that's the prob. of
 * success provided that there are no other flows in the current MPP flow set.
 * */
double flow_probability(const struct flow *flow,
			const struct route_query *rq)
{
	const size_t pathlen = tal_count(flow->path);
	struct amount_msat spend = flow->amount;
	double prob = 1.0;

	for (int i = (int)pathlen - 1; i >= 0; i--) {
		const struct half_chan *h = flow_edge(flow, i);
		struct amount_msat mincap, maxcap;

		get_constraints(rq, flow->path[i], flow->dirs[i], &mincap, &maxcap);
		prob *= edge_probability(spend, mincap, maxcap, AMOUNT_MSAT(0));

		if (!amount_msat_add_fee(&spend, h->base_fee,
					 h->proportional_fee)) {
			plugin_err(rq->plugin, "Could not add fee %u/%u to amount %s in %i/%zu",
				   h->base_fee, h->proportional_fee,
				   fmt_amount_msat(tmpctx, spend),
				   i, pathlen);
		}
	}

	return prob;
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
