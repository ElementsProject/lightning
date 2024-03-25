#ifndef LIGHTNING_PLUGINS_RENEPAY_ROUTEBUILDER_H
#define LIGHTNING_PLUGINS_RENEPAY_ROUTEBUILDER_H

#include "config.h"
#include <ccan/tal/tal.h>
#include <common/gossmap.h>
#include <plugins/renepay/payment.h>
#include <plugins/renepay/route.h>
#include <plugins/renepay/uncertainty.h>

struct route **get_routes(const tal_t *ctx, struct payment *payment,

			  const struct node_id *source,
			  const struct node_id *destination,
			  struct gossmap *gossmap, struct uncertainty *uncertainty,

			  struct amount_msat amount_to_deliver,
			  const u32 final_cltv, struct amount_msat feebudget,

			  enum jsonrpc_errcode *ecode, const char **fail);

#endif /* LIGHTNING_PLUGINS_RENEPAY_ROUTEBUILDER_H */
