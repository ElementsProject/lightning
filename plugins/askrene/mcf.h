#ifndef LIGHTNING_PLUGINS_ASKRENE_MCF_H
#define LIGHTNING_PLUGINS_ASKRENE_MCF_H
/* Eduardo Quintela's (lagrang3@protonmail.com) Min Cost Flow implementation
 * from renepay, as modified to fit askrene */
#include "config.h"
#include <common/amount.h>
#include <common/gossmap.h>

struct route_query;

enum {
	RENEPAY_ERR_OK,
	// No feasible flow found, either there is not enough known liquidity (or capacity)
	// in the channels to complete the payment
	RENEPAY_ERR_NOFEASIBLEFLOW,
	// There is at least one feasible flow, but the the cheapest solution that we
	// found is too expensive, we return the result anyways.
	RENEPAY_ERR_NOCHEAPFLOW
};



/**
 * optimal_payment_flow - API for min cost flow function(s).
 * @ctx: context to allocate returned flows from
 * @gossmap: the gossip map
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
 * @prob_cost_factor: factor used to monetize the probability cost. It is
 * defined as the number of ppm (parts per million of the total payment) we
 * are willing to pay to improve the probability of success by 0.1%.
 *
 * 	k_microsat = floor(1000*prob_cost_factor * payment_sat)
 *
 * this k is used to compute a prob. cost in units of microsats
 *
 * 	cost(payment) = - k_microsat * log Prob(payment)
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
		      double base_fee_penalty,
		      u32 prob_cost_factor);
#endif /* LIGHTNING_PLUGINS_ASKRENE_MCF_H */
