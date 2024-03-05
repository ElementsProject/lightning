#ifndef LIGHTNING_PLUGINS_RENEPAY_FLOW_H
#define LIGHTNING_PLUGINS_RENEPAY_FLOW_H
#include "config.h"
#include <bitcoin/short_channel_id.h>
#include <ccan/htable/htable_type.h>
#include <common/amount.h>
#include <common/gossmap.h>
#include <plugins/renepay/chan_extra.h>

/* An actual partial flow. */
struct flow {
	const struct gossmap_chan **path;
	/* The directions to traverse. */
	int *dirs;
	/* Amounts for this flow (fees mean this shrinks across path). */

	/* Probability of success (0-1) */
	double success_prob;

	struct amount_msat amount;
};

/* Helper to access the half chan at flow index idx */
const struct half_chan *flow_edge(const struct flow *flow, size_t idx);

/* A big number, meaning "don't bother" (not infinite, since you may add) */
#define FLOW_INF_COST 100000000.0

/* Cost function to send @f msat through @c in direction @dir,
 * given we already have a flow of prev_flow. */
double flow_edge_cost(const struct gossmap *gossmap,
		      const struct gossmap_chan *c, int dir,
		      const struct amount_msat known_min,
		      const struct amount_msat known_max,
		      struct amount_msat prev_flow,
		      struct amount_msat f,
		      double mu,
		      double basefee_penalty,
		      double delay_riskfactor);

/* Function to fill in amounts and success_prob for flow. */
bool flow_complete(const tal_t *ctx, struct flow *flow,
		   const struct gossmap *gossmap,
		   struct chan_extra_map *chan_extra_map,
		   struct amount_msat delivered, char **fail);

/* Compute the prob. of success of a set of concurrent set of flows. */
double flowset_probability(const tal_t *ctx, struct flow **flows,
			   const struct gossmap *const gossmap,
			   struct chan_extra_map *chan_extra_map, char **fail);

/* How much do we need to send to make this flow arrive. */
bool flow_spend(struct amount_msat *ret, struct flow *flow);

/* How much do we pay in fees to make this flow arrive. */
bool flow_fee(struct amount_msat *ret, struct flow *flow);

bool flowset_fee(struct amount_msat *fee, struct flow **flows);

/* flows should be a set of optimal routes delivering an amount that is
 * slighty less than amount_to_deliver. We will try to reallocate amounts in
 * these flows so that it delivers the exact amount_to_deliver to the
 * destination.
 * Returns how much we are delivering at the end. */
bool flows_fit_amount(const tal_t *ctx, struct amount_msat *amount_allocated,
		      struct flow **flows, struct amount_msat amount_to_deliver,
		      const struct gossmap *gossmap,
		      struct chan_extra_map *chan_extra_map, char **fail);

struct amount_msat *tal_flow_amounts(const tal_t *ctx, const struct flow *flow);

#endif /* LIGHTNING_PLUGINS_RENEPAY_FLOW_H */
