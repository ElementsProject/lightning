#ifndef LIGHTNING_PLUGINS_RENEPAY_ROUTEBUILDER_H
#define LIGHTNING_PLUGINS_RENEPAY_ROUTEBUILDER_H

#include "config.h"
#include <ccan/tal/tal.h>
#include <common/gossmap.h>
#include <plugins/renepay/disabledmap.h>
#include <plugins/renepay/payment_info.h>
#include <plugins/renepay/route.h>
#include <plugins/renepay/uncertainty.h>

struct route **get_routes(const tal_t *ctx,
			  struct payment_info *payment_info,

			  const struct node_id *source,
			  const struct node_id *destination,
			  struct gossmap *gossmap,
			  struct uncertainty *uncertainty,
			  struct disabledmap *disabledmap,

			  struct amount_msat amount_to_deliver,
			  struct amount_msat feebudget,
			  
			  u64 *next_partid,
			  u64 groupid,  

			  enum jsonrpc_errcode *ecode,
			  const char **fail);

#endif /* LIGHTNING_PLUGINS_RENEPAY_ROUTEBUILDER_H */
