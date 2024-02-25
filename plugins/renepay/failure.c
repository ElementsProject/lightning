#include "config.h"
#include <common/jsonrpc_errors.h>
#include <plugins/renepay/failure.h>
#include <plugins/renepay/finish.h>
#include <plugins/renepay/json.h>
#include <plugins/renepay/payplugin.h>
#include <plugins/renepay/route.h>

struct command_result *notification_sendpay_failure(struct command *cmd,
						    const char *buf,
						    const jsmntok_t *params)
{
	const char *err;
	// enum jsonrpc_errcode errcode;
	const jsmntok_t *sub = json_get_member(buf, params, "sendpay_failure");

	struct routekey key;
	err = routekey_from_json(&key, buf, json_get_member(buf, sub, "data"));
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
		plugin_err(cmd->plugin, "Unable to parse sendpay_failure: %.*s",
			   json_tok_full_len(sub), json_tok_full(buf, sub));

	assert(route->result->status == SENDPAY_FAILED);

	// update gossmap

	// update information

	// decide wether to continue or to finish

	route = tal_free(route); // TODO add destructor to route that removes it
				 // from the route_map
				 // TODO check when a route is created
	return notification_handled(cmd);
}
