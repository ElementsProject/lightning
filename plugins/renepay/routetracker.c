#include "config.h"
#include <common/json_stream.h>
#include <plugins/renepay/json.h>
#include <plugins/renepay/payment.h>
#include <plugins/renepay/payplugin.h>
#include <plugins/renepay/routefail.h>
#include <plugins/renepay/routetracker.h>

static struct payment *route_get_payment_verify(struct route *route)
{
	struct payment *payment =
	    payment_map_get(pay_plugin->payment_map, route->key.payment_hash);
	if (!payment)
		plugin_err(pay_plugin->plugin,
			   "%s: no payment associated with routekey %s",
			   __func__,
			   fmt_routekey(tmpctx, &route->key));
	return payment;
}

struct routetracker *new_routetracker(const tal_t *ctx, struct payment *payment)
{
	struct routetracker *rt = tal(ctx, struct routetracker);

	rt->computed_routes = tal_arr(rt, struct route *, 0);
	rt->sent_routes = tal(rt, struct route_map);
	rt->finalized_routes = tal_arr(rt, struct route *, 0);

	if (!rt->computed_routes || !rt->sent_routes || !rt->finalized_routes)
		/* bad allocation */
		return tal_free(rt);

	route_map_init(rt->sent_routes);
	return rt;
}

bool routetracker_have_results(struct routetracker *routetracker)
{
	return route_map_count(routetracker->sent_routes) == 0 &&
	       tal_count(routetracker->finalized_routes) > 0;
}

void routetracker_cleanup(struct routetracker *routetracker)
{
	// TODO
}

static struct command_result *
routetracker_add_to_final(struct route_notification *r)
{
	struct payment *payment = r->payment;
	struct command *cmd = r->cmd;
	struct route *route = r->route;
	struct routetracker *routetracker = payment->routetracker;

	r = tal_free(r);

	tal_arr_expand(&routetracker->finalized_routes, route);
	tal_steal(routetracker->finalized_routes, route);

	if (payment->exec_state == INVALID_STATE) {
		/* payment is offline, collect results now and set the payment
		 * state accordingly. */
		assert(payment_commands_empty(payment));
		assert(payment->status == PAYMENT_FAIL ||
		       payment->status == PAYMENT_SUCCESS);

		struct preimage *payment_preimage = NULL;
		enum jsonrpc_errcode final_error = LIGHTNINGD;
		const char *final_msg = NULL;

		tal_collect_results(tmpctx, payment->routetracker,
				    &payment_preimage, &final_error,
				    &final_msg);

		if (payment_preimage) {
			/* If we have the preimage that means one succeed, we
			 * inmediately finish the payment. */
			register_payment_success(payment,
						 take(payment_preimage));
		}
		else if (final_msg) {
			/* We received a sendpay result with a final error
			 * message, we inmediately finish the payment. */
			register_payment_fail(payment, final_error, "%s",
					      final_msg);
		}
	}
	return notification_handled(cmd);
}

static void remove_route(struct route *route, struct route_map *map)
{
	route_map_del(map, route);
}

/* This route is pending, ie. locked in HTLCs.
 * Called either:
 *	- after a sendpay is accepted,
 *	- or after listsendpays reveals some pending route that we didn't
 *	previously know about. */
void route_pending_register(struct routetracker *routetracker,
			    struct route *route)
{
	assert(route);
	assert(routetracker);
	struct payment *payment = route_get_payment_verify(route);
	assert(payment);
	assert(payment->groupid == route->key.groupid);

	/* we already keep track of this route */
	if (route_map_get(pay_plugin->pending_routes, &route->key))
		plugin_err(pay_plugin->plugin,
			   "%s: tracking a route (%s) duplicate?",
			   __func__,
			   fmt_routekey(tmpctx, &route->key));

	if (!route_map_del(routetracker->sent_routes, route))
		plugin_err(pay_plugin->plugin,
			   "%s: tracking a route (%s) not computed by this "
			   "payment call",
			   __func__,
			   fmt_routekey(tmpctx, &route->key));

	if (!tal_steal(pay_plugin->pending_routes, route) ||
	    !route_map_add(pay_plugin->pending_routes, route) ||
	    !tal_add_destructor2(route, remove_route,
				 pay_plugin->pending_routes))
		plugin_err(pay_plugin->plugin, "%s: failed to register route.",
			   __func__);

	if (!amount_msat_add(&payment->total_sent, payment->total_sent,
			     route_sends(route)) ||
	    !amount_msat_add(&payment->total_delivering,
			     payment->total_delivering,
			     route_delivers(route))) {
		plugin_err(pay_plugin->plugin,
			   "%s: amount_msat arithmetic overflow.",
			   __func__);
	}
}

void tal_collect_results(const tal_t *ctx, struct routetracker *routetracker,
			 struct preimage **payment_preimage,
			 enum jsonrpc_errcode *final_error,
			 const char **final_msg)
{
	assert(routetracker);
	const size_t ncompleted = tal_count(routetracker->finalized_routes);
	for (size_t i = 0; i < ncompleted; i++) {
		struct route *r = routetracker->finalized_routes[i];
		assert(r);
		assert(r->result);

		assert(r->result->status == SENDPAY_COMPLETE ||
		       r->result->status == SENDPAY_FAILED);

		/* Any success is a success. */
		if (r->result->status == SENDPAY_COMPLETE && payment_preimage) {
			assert(r->result->payment_preimage);
			*payment_preimage =
			    tal_dup(ctx, struct preimage,
				    r->result->payment_preimage);
			break;
		}

		if (r->final_msg) {
			if (final_error)
				*final_error = r->final_error;

			if (final_msg)
				*final_msg = tal_strdup(ctx, r->final_msg);
		}
	}
	for (size_t i = 0; i < ncompleted; i++)
		tal_free(routetracker->finalized_routes[i]);
	tal_resize(&routetracker->finalized_routes, 0);
}

static struct command_result *
askrene_unreserve_done(struct command *cmd, const char *buf,
		       const jsmntok_t *tok, struct route_notification *r)
{
	return routetracker_add_to_final(r);
}
static struct command_result *
askrene_unreserve_fail(struct command *cmd, const char *buf,
		       const jsmntok_t *tok, struct route_notification *r)
{
	/* FIXME: we should implement a safer way to add and remove reserves. */
	plugin_log(cmd->plugin, LOG_UNUSUAL, "askrene-unreserve failed: %.*s",
		   json_tok_full_len(tok), json_tok_full(buf, tok));
	return askrene_unreserve_done(cmd, buf, tok, r);
}

struct command_result *route_unreserve(struct route_notification *r)
{
	if (!route_is_reserved(r->route))
		return routetracker_add_to_final(r);

	struct out_req *req = jsonrpc_request_start(
	    r->cmd->plugin, r->cmd, "askrene-unreserve", askrene_unreserve_done,
	    askrene_unreserve_fail, r);
	json_array_start(req->js, "path");
	for (size_t i = 0; i < tal_count(r->route->hops); i++) {
		json_object_start(req->js, NULL);
		json_add_short_channel_id(req->js, "short_channel_id",
					  r->route->hops[i].scid);
		json_add_num(req->js, "direction", r->route->hops[i].direction);
		json_add_amount_msat(req->js, "amount_msat",
				     r->route->hops[i].amount);
		json_object_end(req->js);
	}
	json_array_end(req->js);
	return send_outreq(r->cmd->plugin, req);
}

struct command_result *notification_sendpay_failure(struct command *cmd,
						    const char *buf,
						    const jsmntok_t *params)
{
	plugin_log(pay_plugin->plugin, LOG_DBG,
		   "sendpay_failure notification: %.*s",
		   json_tok_full_len(params), json_tok_full(buf, params));

	// enum jsonrpc_errcode errcode;
	const jsmntok_t *sub = json_get_member(buf, params, "sendpay_failure");

	struct routekey *key = tal_routekey_from_json(
	    tmpctx, buf, json_get_member(buf, sub, "data"));
	if (!key)
		plugin_err(pay_plugin->plugin,
			   "Unable to get routekey from sendpay_failure: %.*s",
			   json_tok_full_len(sub), json_tok_full(buf, sub));

	struct payment *payment =
	    payment_map_get(pay_plugin->payment_map, key->payment_hash);

	if (!payment) {
		/* This sendpay is not linked to any route in our database, we
		 * skip it. */
		return notification_handled(cmd);
	}

	struct routetracker *routetracker = payment->routetracker;
	assert(routetracker);
	struct route *route =
	    route_map_get(pay_plugin->pending_routes, key);
	if (!route) {
		route = tal_route_from_json(tmpctx, buf,
					    json_get_member(buf, sub, "data"));
		if (!route)
			plugin_err(pay_plugin->plugin,
				   "Failed to get route information from "
				   "sendpay_failure: %.*s",
				   json_tok_full_len(sub),
				   json_tok_full(buf, sub));
	}

	assert(route->result == NULL);
	route->result = tal_sendpay_result_from_json(route, buf, sub);
	if (route->result == NULL)
		plugin_err(pay_plugin->plugin,
			   "Unable to parse sendpay_failure: %.*s",
			   json_tok_full_len(sub), json_tok_full(buf, sub));

	if (route->result->status != SENDPAY_FAILED) {
		/* FIXME shouldn't this be always SENDPAY_FAILED? */
		const jsmntok_t *datatok = json_get_member(buf, sub, "data");
		const jsmntok_t *statustok =
		    json_get_member(buf, datatok, "status");
		const char *status_str = json_strdup(tmpctx, buf, statustok);

		plugin_log(pay_plugin->plugin, LOG_UNUSUAL,
			   "sendpay_failure notification returned status=%s",
			   status_str);
		route->result->status = SENDPAY_FAILED;
	}

	/* we do some error processing steps before calling */
	struct route_notification *r = tal(NULL, struct route_notification);
	r->cmd = cmd;
	r->payment = payment;
	r->route = route;
	return routefail_start(r);
}

struct command_result *notification_sendpay_success(struct command *cmd,
						    const char *buf,
						    const jsmntok_t *params)
{
	plugin_log(pay_plugin->plugin, LOG_DBG,
		   "sendpay_success notification: %.*s",
		   json_tok_full_len(params), json_tok_full(buf, params));

	const jsmntok_t *sub = json_get_member(buf, params, "sendpay_success");

	struct routekey *key = tal_routekey_from_json(tmpctx, buf, sub);
	if (!key)
		plugin_err(pay_plugin->plugin,
			   "Unable to get routekey from sendpay_success: %.*s",
			   json_tok_full_len(sub), json_tok_full(buf, sub));

	struct payment *payment =
	    payment_map_get(pay_plugin->payment_map, key->payment_hash);

	if (!payment) {
		/* This sendpay is not linked to any route in our database, we
		 * skip it. */
		return notification_handled(cmd);
	}

	struct route *route =
	    route_map_get(pay_plugin->pending_routes, key);
	if (!route) {
		/* This route was not created by us, make a basic route
		 * information dummy without hop details to pass onward. */
		route = tal_route_from_json(tmpctx, buf, sub);
		if(!route)
		plugin_err(pay_plugin->plugin,
			   "Failed to get route information from sendpay_success: %.*s",
			   json_tok_full_len(sub), json_tok_full(buf, sub));
	}

	assert(route->result == NULL);
	route->result = tal_sendpay_result_from_json(route, buf, sub);
	if (route->result == NULL)
		plugin_err(pay_plugin->plugin,
			   "Unable to parse sendpay_success: %.*s",
			   json_tok_full_len(sub), json_tok_full(buf, sub));

	assert(route->result->status == SENDPAY_COMPLETE);

	struct route_notification *r = tal(NULL, struct route_notification);
	r->cmd = cmd;
	r->payment = payment;
	r->route = route;
	return route_unreserve(r);
}
