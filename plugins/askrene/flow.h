#ifndef LIGHTNING_PLUGINS_ASKRENE_FLOW_H
#define LIGHTNING_PLUGINS_ASKRENE_FLOW_H
#include "config.h"
#include <bitcoin/short_channel_id.h>
#include <common/amount.h>
#include <common/gossmap.h>

struct plugin;
struct route_query;

/* An actual partial flow. */
struct flow {
	const struct gossmap_chan **path;
	/* The directions to traverse. */
	int *dirs;
	/* Amount delivered */
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
double flowset_probability(struct flow **flows,
			   const struct route_query *rq);

/* How much do we need to send to make this flow arrive. */
struct amount_msat flow_spend(struct plugin *plugin, const struct flow *flow);

/* How much do we pay in fees to make this flow arrive. */
struct amount_msat flow_fee(struct plugin *plugin, const struct flow *flow);

struct amount_msat flowset_fee(struct plugin *plugin, struct flow **flows);

struct amount_msat flowset_delivers(struct plugin *plugin,
				    struct flow **flows);

static inline struct amount_msat flow_delivers(const struct flow *flow)
{
	return flow->amount;
}

double flow_probability(const struct flow *flow,
			const struct route_query *rq);

u64 flow_delay(const struct flow *flow);
u64 flows_worst_delay(struct flow **flows);

#endif /* LIGHTNING_PLUGINS_ASKRENE_FLOW_H */
