#ifndef LIGHTNING_PLUGINS_ASKRENE_MCF_H
#define LIGHTNING_PLUGINS_ASKRENE_MCF_H
/* Eduardo Quintela's (lagrang3@protonmail.com) Min Cost Flow implementation
 * from renepay, as modified to fit askrene */
#include "config.h"
#include <common/amount.h>
#include <common/gossmap.h>

struct route_query;

/**
 * optimal_payment_flow - API for min cost flow function(s).
 * @ctx: context to allocate returned flows from
 * @rq: the route_query we're processing (for logging)
 * @source: the source to start from
 * @target: the target to pay
 * @amount: the amount we want to reach @target
 * @mu: 0 = corresponds to only probabilities, 100 corresponds to only fee.
 *
 * @delay_feefactor converts 1 block delay into msat, as if it were an additional
 * fee.  So if a CLTV delay on a node is 5 blocks, that's treated as if it
 * were a fee of 5 * @delay_feefactor.
 *
 * @base_fee_penalty: factor to compute additional proportional cost from each
 * unit of base fee. So #base_fee_penalty will be added to the effective
 * proportional fee for each msat of base fee.
 *
 * 	effective_ppm = proportional_fee + base_fee_msat * base_fee_penalty
 *
 * Return a series of subflows which deliver amount to target, or NULL.
 */
struct flow **minflow(const tal_t *ctx,
		      const struct route_query *rq,
		      const struct gossmap_node *source,
		      const struct gossmap_node *target,
		      struct amount_msat amount,
		      u32 mu,
		      double delay_feefactor,
		      double base_fee_penalty);
#endif /* LIGHTNING_PLUGINS_ASKRENE_MCF_H */
