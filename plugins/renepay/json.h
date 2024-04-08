#ifndef LIGHTNING_PLUGINS_RENEPAY_JSON_H
#define LIGHTNING_PLUGINS_RENEPAY_JSON_H

#include <plugins/renepay/payment.h>
#include <plugins/renepay/route.h>

struct routekey *tal_routekey_from_json(const tal_t *ctx, const char *buf,
					const jsmntok_t *obj);

struct payment_result *tal_sendpay_result_from_json(const tal_t *ctx,
						    const char *buffer,
						    const jsmntok_t *toks);

void json_add_payment(struct json_stream *s, const struct payment *payment);

void json_add_route(struct json_stream *s, const struct route *route);

#endif /* LIGHTNING_PLUGINS_RENEPAY_JSON_H */
