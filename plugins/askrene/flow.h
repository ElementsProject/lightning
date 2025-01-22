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
	struct amount_msat delivers;
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

/* What's the success probability of this flow in isolation? */
double flow_probability(const struct flow *flow,
			const struct route_query *rq);

/* How much do we need to send to make this flow arrive. */
struct amount_msat flow_spend(struct plugin *plugin, const struct flow *flow);

/* How much do we pay in fees to make this flow arrive. */
struct amount_msat flow_fee(struct plugin *plugin, const struct flow *flow);

/* What fee to we pay for this entire flow set? */
struct amount_msat flowset_fee(struct plugin *plugin, struct flow **flows);

/* How much does this entire flowset deliver? */
struct amount_msat flowset_delivers(struct plugin *plugin,
				    struct flow **flows);

/* How much CLTV does this flow require? */
u64 flow_delay(const struct flow *flow);

/* Max CLTV any of these flows requires */
u64 flows_worst_delay(struct flow **flows);

const char *fmt_flows_step_scid(const tal_t *ctx,
				const struct route_query *rq,
				const struct flow *flow, size_t i);

/* When we need to debug */
const char *fmt_flow_full(const tal_t *ctx,
			  const struct route_query *rq,
			  const struct flow *flow);
#endif /* LIGHTNING_PLUGINS_ASKRENE_FLOW_H */
