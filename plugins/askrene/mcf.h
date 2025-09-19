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
 * @delay_feefactor: convert 1 block delay into msat.
 * @single_part: don't do MCF at all, just create a single flow.
 *
 * @delay_feefactor converts 1 block delay into msat, as if it were an additional
 * fee.  So if a CLTV delay on a node is 5 blocks, that's treated as if it
 * were a fee of 5 * @delay_feefactor.
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
		      double base_prob);

/**
 * API for min cost single path.
 * @ctx: context to allocate returned flows from
 * @rq: the route_query we're processing (for logging)
 * @source: the source to start from
 * @target: the target to pay
 * @amount: the amount we want to reach @target
 * @mu: 0 = corresponds to only probabilities, 100 corresponds to only fee.
 * @delay_feefactor: convert 1 block delay into msat.
 *
 * @delay_feefactor converts 1 block delay into msat, as if it were an additional
 * fee.  So if a CLTV delay on a node is 5 blocks, that's treated as if it
 * were a fee of 5 * @delay_feefactor.
 *
 * Returns an array with one flow which deliver amount to target, or NULL.
 */
struct flow **single_path_flow(const tal_t *ctx, const struct route_query *rq,
			       const struct gossmap_node *source,
			       const struct gossmap_node *target,
			       struct amount_msat amount, u32 mu,
			       double delay_feefactor,
			       double base_prob);

/* To sanity check: this is the approximation mcf uses for the cost
 * of each channel. */
struct amount_msat linear_flow_cost(const struct flow *flow,
				    struct amount_msat total_amount,
				    double delay_feefactor);

/* A wrapper to the min. cost flow solver that actually takes into consideration
 * the extra msats per channel needed to pay for fees. */
const char *default_routes(const tal_t *ctx, struct route_query *rq,
			   const struct gossmap_node *srcnode,
			   const struct gossmap_node *dstnode,
			   struct amount_msat amount,
			   struct amount_msat maxfee, u32 finalcltv,
			   u32 maxdelay, struct flow ***flows,
			   double *probability);

/* A wrapper to the single-path constrained solver. */
const char *single_path_routes(const tal_t *ctx, struct route_query *rq,
			       const struct gossmap_node *srcnode,
			       const struct gossmap_node *dstnode,
			       struct amount_msat amount,
			       struct amount_msat maxfee, u32 finalcltv,
			       u32 maxdelay, struct flow ***flows,
			       double *probability);

#endif /* LIGHTNING_PLUGINS_ASKRENE_MCF_H */
