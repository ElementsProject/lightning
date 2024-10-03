#ifndef LIGHTNING_PLUGINS_ASKRENE_EXPLAIN_FAILURE_H
#define LIGHTNING_PLUGINS_ASKRENE_EXPLAIN_FAILURE_H
#include "config.h"
#include <common/amount.h>

struct route_query;
struct gossmap_node;

/* When MCF returns nothing, try to explain why */
const char *explain_failure(const tal_t *ctx,
			    const struct route_query *rq,
			    const struct gossmap_node *srcnode,
			    const struct gossmap_node *dstnode,
			    struct amount_msat amount);

#endif /* LIGHTNING_PLUGINS_ASKRENE_EXPLAIN_FAILURE_H */
