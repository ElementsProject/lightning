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

static struct amount_msat *flow_amounts(const tal_t *ctx,
					struct plugin *plugin,
					const struct flow *flow)
{
	const size_t pathlen = tal_count(flow->path);
	struct amount_msat *amounts = tal_arr(ctx, struct amount_msat, pathlen);
	amounts[pathlen - 1] = flow->delivers;

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

/* How much do we deliver to destination using this set of routes */
struct amount_msat flowset_delivers(struct plugin *plugin,
				    struct flow **flows)
{
	struct amount_msat final = AMOUNT_MSAT(0);
	for (size_t i = 0; i < tal_count(flows); i++) {
		if (!amount_msat_accumulate(&final, flows[i]->delivers)) {
			plugin_err(plugin, "Could not add flowsat %s to %s (%zu/%zu)",
				   fmt_amount_msat(tmpctx, flows[i]->delivers),
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
	struct amount_msat spend = flow->delivers;

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
	if (!amount_msat_sub(&fee, spend, flow->delivers)) {
		plugin_err(plugin, "Could not subtract %s from %s for fee",
				   fmt_amount_msat(tmpctx, flow->delivers),
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

/* Helper function to find the success_prob for a single flow
 *
 * IMPORTANT: flow->success_prob is misleading, because that's the prob. of
 * success provided that there are no other flows in the current MPP flow set.
 * */
double flow_probability(const struct flow *flow,
			const struct route_query *rq)
{
	const size_t pathlen = tal_count(flow->path);
	struct amount_msat spend = flow->delivers;
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
