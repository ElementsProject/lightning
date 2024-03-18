#ifndef LIGHTNING_PLUGINS_RENEPAY_FLOW_H
#define LIGHTNING_PLUGINS_RENEPAY_FLOW_H
#include "config.h"
#include <bitcoin/short_channel_id.h>
#include <ccan/htable/htable_type.h>
#include <common/amount.h>
#include <common/gossmap.h>
#include <plugins/renepay/chan_extra.h>
#include <plugins/renepay/errorcodes.h>

/* An actual partial flow. */
struct flow {
	const struct gossmap_chan **path;
	/* The directions to traverse. */
	int *dirs;
	/* Amounts for this flow (fees mean this shrinks across path). */
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

/* Compute the prob. of success of a set of concurrent set of flows. */
double flowset_probability(const tal_t *ctx, struct flow **flows,
			   const struct gossmap *const gossmap,
			   struct chan_extra_map *chan_extra_map, char **fail);

/* How much do we need to send to make this flow arrive. */
bool flow_spend(struct amount_msat *ret, struct flow *flow);

/* How much do we pay in fees to make this flow arrive. */
bool flow_fee(struct amount_msat *ret, struct flow *flow);

bool flowset_fee(struct amount_msat *fee, struct flow **flows);

bool flowset_delivers(struct amount_msat *delivers, struct flow **flows);

static inline struct amount_msat flow_delivers(const struct flow *flow)
{
	return flow->amount;
}

struct amount_msat *tal_flow_amounts(const tal_t *ctx, const struct flow *flow);

enum renepay_errorcode
flow_maximum_deliverable(struct amount_msat *max_deliverable,
			 const struct flow *flow,
			 const struct gossmap *gossmap,
			 struct chan_extra_map *chan_extra_map,
			 const struct gossmap_chan **bad_channel);

/* Assign the delivered amount to the flow if it fits
 the path maximum capacity. */
bool flow_assign_delivery(struct flow *flow, const struct gossmap *gossmap,
			  struct chan_extra_map *chan_extra_map,
			  struct amount_msat requested_amount);

double flow_probability(struct flow *flow, const struct gossmap *gossmap,
			struct chan_extra_map *chan_extra_map);

u64 flow_delay(const struct flow *flow);
u64 flows_worst_delay(struct flow **flows);

struct flow **
flows_ensure_liquidity_constraints(const tal_t *ctx, struct flow **flows TAKES,
				   const struct gossmap *gossmap,
				   struct chan_extra_map *chan_extra_map);

#endif /* LIGHTNING_PLUGINS_RENEPAY_FLOW_H */
