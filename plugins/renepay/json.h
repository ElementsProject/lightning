#ifndef LIGHTNING_PLUGINS_RENEPAY_JSON_H
#define LIGHTNING_PLUGINS_RENEPAY_JSON_H
#include "config.h"
#include <common/json_parse_simple.h>
#include <plugins/renepay/route.h>

struct payment_result *tal_sendpay_result_from_json(const tal_t *ctx,
						    const char *buf,
						    const jsmntok_t *sub);

const char *routekey_from_json(struct routekey *key, const char *buf,
			       const jsmntok_t *params);

#endif /* LIGHTNING_PLUGINS_RENEPAY_JSON_H */
