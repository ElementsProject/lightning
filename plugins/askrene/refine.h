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
 * It takes into account the exact value of the fees expected at each hop.
 * If we reduce flows because it's too large for one channel, *bottleneck_idx
 * is set to the idx of a channel which caused a reduction (if non-NULL).
 */
const char *refine_flows(const tal_t *ctx, struct route_query *rq,
			 struct amount_msat deliver, struct flow ***flows,
			 u32 *bottleneck_idx);

/* Duplicated flows are merged into one. This saves in base fee and HTLC fees.
 */
void squash_flows(const tal_t *ctx, struct route_query *rq,
		  struct flow ***flows);

double flows_probability(const tal_t *ctx, struct route_query *rq,
			 struct flow ***flows);

/* Modify flows so only N remain, if we can.  Returns an error if we cannot. */
const char *reduce_num_flows(const tal_t *ctx,
			     const struct route_query *rq,
			     struct flow ***flows,
			     struct amount_msat deliver,
			     size_t num_parts);
#endif /* LIGHTNING_PLUGINS_ASKRENE_REFINE_H */
