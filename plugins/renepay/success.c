/* on_success:
 * This handles the success of a route. We send the information learned to
 * uncertainty network, we flag the payment as PAYMENT_SUCCESS and we move to
 * the finish section. */

#include "config.h"
#include <plugins/renepay/parse_json.h>
#include <plugins/renepay/payplugin.h>
#include <plugins/renepay/route.h>
#include <plugins/renepay/success.h>

struct command_result *notification_sendpay_success(struct command *cmd,
						    const char *buf,
						    const jsmntok_t *params)
{
	const jsmntok_t *sub = json_get_member(buf, params, "sendpay_success");

	struct routekey *key = tal_routekey_from_json(tmpctx, buf, sub);
	if (!key)
		plugin_err(pay_plugin->plugin,
			   "Unable to get routekey from sendpay_success: %.*s",
			   json_tok_full_len(sub), json_tok_full(buf, sub));

	struct route *route = route_map_get(pay_plugin->route_map, key);

	if (!route)
		/* This sendpay is not linked to any route in our database, we
		 * skip it. */
		return notification_handled(cmd);

	route->result = tal_sendpay_result_from_json(route, buf, sub);
	if (route->result == NULL)
		plugin_err(pay_plugin->plugin,
			   "Unable to parse sendpay_success: %.*s",
			   json_tok_full_len(sub), json_tok_full(buf, sub));

	assert(route->result->status == SENDPAY_COMPLETE);

	// update information
	unetwork_route_success(pay_plugin->unetwork, route);
	unetwork_remove_htlcs(pay_plugin->unetwork, route);

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
