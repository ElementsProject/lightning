#ifndef LIGHTNING_PLUGINS_ASKRENE_REFINE_H
#define LIGHTNING_PLUGINS_ASKRENE_REFINE_H
#include "config.h"
#include <ccan/tal/tal.h>

struct route_query;
struct amount_msat;
struct flow;

/* We got an answer from min-cost-flow, but we now need to:
 * 1. Add fixup exact delivery amounts since MCF deals in larger granularity than msat.
 * 2. Add fees which accumulate through the route.
 * 3. Check for htlc_minimum_msat violations (we simply remove those flows).
 * 4. Trim any flows which (after fees) now violate maximum htlc_minimum_msat/capacity bounds.
 *
 * We try to reassign missing sats to the remaining flows, which is usually easy.
 *
 * Returns NULL on success, or an error message for the caller.
 */
const char *
refine_with_fees_and_limits(const tal_t *ctx,
			    struct route_query *rq,
			    struct amount_msat deliver,
			    struct flow ***flows,
			    double *flowset_probability);
#endif /* LIGHTNING_PLUGINS_ASKRENE_REFINE_H */
