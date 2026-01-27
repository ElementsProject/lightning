#include "config.h"
#include <assert.h>
#include <ccan/tal/str/str.h>
#include <ccan/tal/tal.h>
#include <common/fp16.h>
#include <common/overflows.h>
#include <math.h>
#include <plugins/askrene/askrene.h>
#include <plugins/askrene/child/flow.h>
#include <plugins/libplugin.h>
#include <stdio.h>

#ifndef SUPERVERBOSE
#define SUPERVERBOSE(...)
#else
#define SUPERVERBOSE_ENABLED 1
#endif

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
		struct short_channel_id_dir scidd;
		scidd.scid = gossmap_chan_scid(rq->gossmap, flow->path[i]);
		scidd.dir = flow->dirs[i];

		prob *= edge_probability(rq, &scidd, spend);

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

const char *fmt_flows_step_scid(const tal_t *ctx,
				const struct route_query *rq,
				const struct flow *flow, size_t i)
{
	struct short_channel_id_dir scidd;

	scidd.scid = gossmap_chan_scid(rq->gossmap, flow->path[i]);
	scidd.dir = flow->dirs[i];
	return fmt_short_channel_id_dir(ctx, &scidd);
}

#ifndef SUPERVERBOSE_ENABLED
#undef SUPERVERBOSE
#endif
