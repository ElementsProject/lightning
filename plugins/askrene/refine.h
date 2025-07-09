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

/* create flow reservations, but first verify that the flow indeeds fits in the
 * liquidity constraints. Takes into account reservations that include per HTLC
 * extra amounts to pay for onchain fees. */
bool create_flow_reservations_verify(const struct route_query *rq,
				     struct reserve_hop **reservations,
				     const struct flow *flow);

/* Modify flows to meet HTLC min/max requirements.
 * It takes into account the exact value of the fees expected at each hop. */
const char *refine_flows(const tal_t *ctx, struct route_query *rq,
			 struct amount_msat deliver, struct flow ***flows);

/* Duplicated flows are merged into one. This saves in base fee and HTLC fees.
 */
void squash_flows(const tal_t *ctx, struct route_query *rq,
		  struct flow ***flows);

double flows_probability(const tal_t *ctx, struct route_query *rq,
			 struct flow ***flows);
#endif /* LIGHTNING_PLUGINS_ASKRENE_REFINE_H */
