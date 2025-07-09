#ifndef LIGHTNING_PLUGINS_ASKRENE_REFINE_H
#define LIGHTNING_PLUGINS_ASKRENE_REFINE_H
#include "config.h"
#include <ccan/tal/tal.h>

struct route_query;
struct amount_msat;
struct flow;

struct reserve_hop *new_reservations(const tal_t *ctx,
				     const struct route_query *rq);

void create_flow_reservations(const struct route_query *rq,
			      struct reserve_hop **reservations,
			      const struct flow *flow);

/* Modify flows to meet HTLC min/max requirements.
 * It takes into account the exact value of the fees expected at each hop. */
const char *refine_flows(const tal_t *ctx, struct route_query *rq,
			 struct amount_msat deliver, struct flow ***flows);
#endif /* LIGHTNING_PLUGINS_ASKRENE_REFINE_H */
