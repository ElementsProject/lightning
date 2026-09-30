#ifndef LIGHTNING_PLUGINS_ASKRENE_CHILD_MCF_H
#define LIGHTNING_PLUGINS_ASKRENE_CHILD_MCF_H
/* Eduardo Quintela's (lagrang3@protonmail.com) Min Cost Flow implementation
 * from renepay, as modified to fit askrene */
#include "config.h"
#include <ccan/time/time.h>
#include <common/amount.h>
#include <common/gossmap.h>
#include <common/jsonrpc_errors.h>

struct flow;
struct route_query;

/* A wrapper to the min. cost flow solver that actually takes into consideration
 * the extra msats per channel needed to pay for fees. */
const char *default_routes(const tal_t *ctx, struct route_query *rq,
			   struct timemono deadline,
			   const struct gossmap_node *srcnode,
			   const struct gossmap_node *dstnode,
			   struct amount_msat amount,
			   struct amount_msat maxfee, u32 finalcltv,
			   u32 maxdelay, size_t maxparts, struct flow ***flows,
			   double *probability,
			   enum jsonrpc_errcode *ecode);

/* A wrapper to the single-path constrained solver. */
const char *single_path_routes(const tal_t *ctx, struct route_query *rq,
			       struct timemono deadline,
			       const struct gossmap_node *srcnode,
			       const struct gossmap_node *dstnode,
			       struct amount_msat amount,
			       struct amount_msat maxfee, u32 finalcltv,
			       u32 maxdelay, struct flow ***flows,
			       double *probability,
			       enum jsonrpc_errcode *ecode);

/* The probability of forwarding a payment amount given a high and low liquidity
 * bounds.
 * @low: the liquidity is known to be greater or equal than "low"
 * @high: the liquidity is known to be less than "high"
 * @amount: how much is required to forward */
double pickhardt_richter_probability(struct amount_msat low,
				     struct amount_msat high,
				     struct amount_msat amount);

#endif /* LIGHTNING_PLUGINS_ASKRENE_CHILD_MCF_H */
