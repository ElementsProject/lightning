#include "config.h"
#include <plugins/renepay/json.h>

struct payment_result *tal_sendpay_result_from_json(const tal_t *ctx,
						    const char *buf,
						    const jsmntok_t *sub)
{
	// TODO
	return NULL;
}

const char *routekey_from_json(struct routekey *key, const char *buf,
			       const jsmntok_t *params)
{
	// TODO
	return NULL;
}
