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
			   __PRETTY_FUNCTION__,
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

static void routetracker_add_to_final(struct routetracker *routetracker,
				      struct route *route)
{
	tal_arr_expand(&routetracker->finalized_routes, route);
	tal_steal(routetracker->finalized_routes, route);
}
static void route_success_register(struct routetracker *routetracker,
				   struct route *route)
{
	if(route->hops){
		uncertainty_route_success(pay_plugin->uncertainty, route);
		uncertainty_remove_htlcs(pay_plugin->uncertainty, route);
	}
	routetracker_add_to_final(routetracker, route);
}
void route_failure_register(struct routetracker *routetracker,
			    struct route *route)
{
	struct payment_result *result = route->result;
	assert(result);

	/* Update the knowledge in the uncertaity network. */
	if (route->hops) {
		assert(result->erring_index);
		int path_len = tal_count(route->hops);

		/* index of the last channel before the erring node */
		const int last_good_channel = *result->erring_index - 1;

		if (last_good_channel >= path_len) {
			plugin_err(pay_plugin->plugin,
				   "last_good_channel (%d) >= path_len (%d)",
				   last_good_channel, path_len);
		}

		/* All channels before the erring node could forward the
		 * payment. */
		for (int i = 0; i <= last_good_channel; i++) {
			uncertainty_channel_can_send(pay_plugin->uncertainty,
						     route->hops[i].scid,
						     route->hops[i].direction);
		}

		if (result->failcode == WIRE_TEMPORARY_CHANNEL_FAILURE &&
		    (last_good_channel + 1) < path_len) {
			/* A WIRE_TEMPORARY_CHANNEL_FAILURE could mean not
			 * enough liquidity to forward the payment or cannot add
			 * one more HTLC.
			 */
			uncertainty_channel_cannot_send(
			    pay_plugin->uncertainty,
			    route->hops[last_good_channel + 1].scid,
			    route->hops[last_good_channel + 1].direction);
		}
		uncertainty_remove_htlcs(pay_plugin->uncertainty, route);
	}
	routetracker_add_to_final(routetracker, route);
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
static void route_pending_register(struct routetracker *routetracker,
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
			   __PRETTY_FUNCTION__,
			   fmt_routekey(tmpctx, &route->key));

	if (!route_map_del(routetracker->sent_routes, route))
		plugin_err(pay_plugin->plugin,
			   "%s: tracking a route (%s) not computed by this "
			   "payment call",
			   __PRETTY_FUNCTION__,
			   fmt_routekey(tmpctx, &route->key));

	uncertainty_commit_htlcs(pay_plugin->uncertainty, route);

	if (!tal_steal(pay_plugin, route) ||
	    !route_map_add(pay_plugin->pending_routes, route) ||
	    !tal_add_destructor2(route, remove_route,
				 pay_plugin->pending_routes))
		plugin_err(pay_plugin->plugin, "%s: failed to register route.",
			   __PRETTY_FUNCTION__);

	if (!amount_msat_add(&payment->total_sent, payment->total_sent,
			     route_sends(route)) ||
	    !amount_msat_add(&payment->total_delivering,
			     payment->total_delivering,
			     route_delivers(route))) {
		plugin_err(pay_plugin->plugin,
			   "%s: amount_msat arithmetic overflow.",
			   __PRETTY_FUNCTION__);
	}
}

/* Callback function for sendpay request success. */
static struct command_result *sendpay_done(struct command *cmd,
					   const char *buf UNUSED,
					   const jsmntok_t *result UNUSED,
					   struct route *route)
{
	assert(route);
	struct payment *payment = route_get_payment_verify(route);
	route_pending_register(payment->routetracker, route);
	return command_still_pending(cmd);
}

/* sendpay really only fails immediately in two ways:
 * 1. We screwed up and misused the API.
 * 2. The first peer is disconnected.
 */
static struct command_result *sendpay_failed(struct command *cmd,
					     const char *buf,
					     const jsmntok_t *tok,
					     struct route *route)
{
	assert(route);
	struct payment *payment = route_get_payment_verify(route);
	struct routetracker *routetracker = payment->routetracker;
	assert(routetracker);

	enum jsonrpc_errcode errcode;
	const char *msg;
	const char *err;

	err = json_scan(tmpctx, buf, tok, "{code:%,message:%}",
			JSON_SCAN(json_to_jsonrpc_errcode, &errcode),
			JSON_SCAN_TAL(tmpctx, json_strdup, &msg));
	if (err)
		plugin_err(pay_plugin->plugin,
			   "Unable to parse sendpay error: %s, json: %.*s", err,
			   json_tok_full_len(tok), json_tok_full(buf, tok));

	payment_note(payment, LOG_INFORM,
		     "Sendpay failed: partid=%" PRIu64
		     " errorcode:%d message=%s",
		     route->key.partid, errcode, msg);

	if (errcode != PAY_TRY_OTHER_ROUTE) {
		plugin_log(pay_plugin->plugin, LOG_UNUSUAL,
			   "Strange error from sendpay: %.*s",
			   json_tok_full_len(tok), json_tok_full(buf, tok));
	}

	/* There is no new knowledge from this kind of failure.
	 * We just disable this scid. */
	payment_disable_chan(payment, route->hops[0].scid, LOG_INFORM,
			     "sendpay didn't like first hop: %s", msg);

	if (!route_map_del(routetracker->sent_routes, route))
		plugin_err(pay_plugin->plugin,
			   "%s: route (%s) is not marked as sent",
			   __PRETTY_FUNCTION__,
			   fmt_routekey(tmpctx, &route->key));
	tal_free(route);
	return command_still_pending(cmd);
}

void payment_collect_results(struct payment *payment,
			     struct preimage **payment_preimage,
			     enum jsonrpc_errcode *final_error,
			     const char **final_msg)
{
	assert(payment);
	struct routetracker *routetracker = payment->routetracker;
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
			    tal_dup(tmpctx, struct preimage,
				    r->result->payment_preimage);
			tal_free(r);
			continue;
		}

		/* We should never start a new groupid while there are pending
		 * onions with a different groupid. We ignore any failure that
		 * does not have the same groupid as the one we used for our
		 * routes. */
		if (payment->groupid != r->key.groupid) {
			plugin_log(pay_plugin->plugin, LOG_UNUSUAL,
				   "%s: current groupid=%" PRIu64
				   ", but recieved a sendpay result with "
				   "groupid=%" PRIu64,
				   __PRETTY_FUNCTION__, payment->groupid,
				   r->key.groupid);
			tal_free(r);
			continue;
		}

		assert(r->result->status == SENDPAY_FAILED &&
		       payment->groupid == r->key.groupid);

		if (r->final_msg) {
			if (final_error)
				*final_error = r->final_error;

			if (final_msg)
				*final_msg = tal_strdup(tmpctx, r->final_msg);
		}

		if (!amount_msat_sub(&payment->total_delivering,
				     payment->total_delivering,
				     route_delivers(r)) ||
		    !amount_msat_sub(&payment->total_sent, payment->total_sent,
				     route_sends(r))) {
			plugin_err(pay_plugin->plugin,
				   "%s: routes do not add up to "
				   "payment total amount.",
				   __PRETTY_FUNCTION__);
		}
		tal_free(r);
	}
	tal_resize(&routetracker->finalized_routes, 0);
}

struct command_result *route_sendpay_request(struct command *cmd,
					     struct route *route TAKES,
					     struct payment *payment)
{
	struct out_req *req =
	    jsonrpc_request_start(pay_plugin->plugin, cmd, "sendpay",
				  sendpay_done, sendpay_failed, route);

	json_add_route(req->js, route, payment);

	route_map_add(payment->routetracker->sent_routes, route);
	if(taken(route))
		tal_steal(payment->routetracker->sent_routes, route);
	return send_outreq(pay_plugin->plugin, req);
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

	/* we do some error processing steps before calling
	 * route_failure_register. */
	return routefail_start(route, route, cmd);
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

	struct routetracker *routetracker = payment->routetracker;
	assert(routetracker);
	struct route *route =
	    route_map_get(pay_plugin->pending_routes, key);
	if (!route) {
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
	// TODO: knowledge update here
	route_success_register(payment->routetracker, route);
	return notification_handled(cmd);
}
