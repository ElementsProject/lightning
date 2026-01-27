#ifndef LIGHTNING_PLUGINS_ASKRENE_MCF_H
#define LIGHTNING_PLUGINS_ASKRENE_MCF_H
/* Eduardo Quintela's (lagrang3@protonmail.com) Min Cost Flow implementation
 * from renepay, as modified to fit askrene */
#include "config.h"
#include <common/amount.h>
#include <common/gossmap.h>

struct route_query;

/* A wrapper to the min. cost flow solver that actually takes into consideration
 * the extra msats per channel needed to pay for fees. */
const char *default_routes(const tal_t *ctx, struct route_query *rq,
			   struct timemono deadline,
			   const struct gossmap_node *srcnode,
			   const struct gossmap_node *dstnode,
			   struct amount_msat amount,
			   struct amount_msat maxfee, u32 finalcltv,
			   u32 maxdelay, struct flow ***flows,
			   double *probability);

/* A wrapper to the single-path constrained solver. */
const char *single_path_routes(const tal_t *ctx, struct route_query *rq,
			       struct timemono deadline,
			       const struct gossmap_node *srcnode,
			       const struct gossmap_node *dstnode,
			       struct amount_msat amount,
			       struct amount_msat maxfee, u32 finalcltv,
			       u32 maxdelay, struct flow ***flows,
			       double *probability);

#endif /* LIGHTNING_PLUGINS_ASKRENE_MCF_H */
