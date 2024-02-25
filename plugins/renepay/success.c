/* on_success:
 * This handles the success of a route. We send the information learned to
 * uncertainty network, we flag the payment as PAYMENT_SUCCESS and we move to
 * the finish section. */

#include "config.h"
#include <plugins/renepay/payplugin.h>
#include <plugins/renepay/route.h>
#include <plugins/renepay/success.h>

const char *routekey_from_json(struct routekey *key, const char *buf,
			       const jsmntok_t *params);
const char *routekey_from_json(struct routekey *key, const char *buf,
			       const jsmntok_t *params)
{
	// TODO
	return NULL;
}

struct payment_result *tal_sendpay_result_from_json(const tal_t *ctx,
						    const char *buf,
						    const jsmntok_t *sub);
struct payment_result *tal_sendpay_result_from_json(const tal_t *ctx,
						    const char *buf,
						    const jsmntok_t *sub)
{
	// TODO
	return NULL;
}

struct command_result *notification_sendpay_success(struct command *cmd,
						    const char *buf,
						    const jsmntok_t *params)
{
	const char *err;
	const jsmntok_t *sub = json_get_member(buf, params, "sendpay_success");

	struct routekey key;
	err = routekey_from_json(&key, buf, sub);
	if (err)
		plugin_err(pay_plugin->plugin,
			   "Missing fields (%s) in notification: %.*s", err,
			   json_tok_full_len(sub), json_tok_full(buf, sub));

	struct route *route =
	    route_map_get(pay_plugin->route_map,
			  &key); // TODO declare a route_map inside pay_plugin

	if (!route)
		/* This sendpay is not linked to any route in our database, we
		 * skip it. */
		return notification_handled(cmd);

	route->result = tal_sendpay_result_from_json(route, buf, sub);
	if (route->result == NULL)
		plugin_err(pay_plugin->plugin,
			   "Unable to parse sendpay_failure: %.*s",
			   json_tok_full_len(sub), json_tok_full(buf, sub));

	assert(route->result->status == SENDPAY_COMPLETE);

	// update information
	unetwork_route_success(pay_plugin->unetwork,
			       route); // TODO: define unetwork
	unetwork_remove_htlcs(pay_plugin->unetwork,
			     route); // TODO: define unetwork

	// finish if this payment is in progress
	struct payment *payment = route->payment;

	if (payment->status != PAYMENT_SUCCESS) {
		// TODO
		// route_note(route, LOG_INFORM, "Success");
		payment->status = PAYMENT_SUCCESS;
		payment->preimage = tal_dup(payment, struct preimage,
					    route->result->payment_preimage);
		payment_finish(payment);
	}
	route = tal_free(route);
	return notification_handled(cmd);
}

// FIXME: double-check that we actually get one notification for each sendpay,
// ie. that after some time we don't have yet pending sendpays for old failed or
// successful payments that we havent processed because we haven't received the
// notification
