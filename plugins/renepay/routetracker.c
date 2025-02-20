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

void routetracker_add_to_final(struct routetracker *routetracker,
			       struct route *route)
{
	tal_arr_expand(&routetracker->finalized_routes, route);
	tal_steal(routetracker->finalized_routes, route);

	struct payment *payment =
	    payment_map_get(pay_plugin->payment_map, route->key.payment_hash);
	assert(payment);
	if (payment->exec_state == INVALID_STATE) {
		/* payment is offline, collect results now and set the payment
		 * state accordingly. */
		assert(payment_commands_empty(payment));
		assert(payment->status == PAYMENT_FAIL ||
		       payment->status == PAYMENT_SUCCESS);

		struct preimage *payment_preimage = NULL;
		enum jsonrpc_errcode final_error = LIGHTNINGD;
		const char *final_msg = NULL;

		/* Finalized routes must be processed and removed in order to
		 * free the uncertainty network's HTLCs. */
		payment_collect_results(payment, &payment_preimage,
					&final_error, &final_msg);

		if (payment_preimage) {
			/* If we have the preimage that means one succeed, we
			 * inmediately finish the payment. */
			register_payment_success(payment,
						 take(payment_preimage));
			return;
		}
		if (final_msg) {
			/* We received a sendpay result with a final error
			 * message, we inmediately finish the payment. */
			register_payment_fail(payment, final_error, "%s",
					      final_msg);
			return;
		}
	}
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

/* Callback function for sendpay request success. */
static struct command_result *sendpay_done(struct command *cmd,
					   const char *method UNUSED,
					   const char *buf,
					   const jsmntok_t *result,
					   struct route *route)
{
	assert(route);
	struct payment *payment = route_get_payment_verify(route);
	route_pending_register(payment->routetracker, route);

	const jsmntok_t *t;
	size_t i;
	bool ret;

	const jsmntok_t *secretstok =
	    json_get_member(buf, result, "shared_secrets");

	if (secretstok) {
		assert(secretstok->type == JSMN_ARRAY);

		route->shared_secrets =
		    tal_arr(route, struct secret, secretstok->size);
		json_for_each_arr(i, t, secretstok)
		{
			ret = json_to_secret(buf, t, &route->shared_secrets[i]);
			assert(ret);
		}
	} else
		route->shared_secrets = NULL;
	return command_still_pending(cmd);
}

/* sendpay really only fails immediately in two ways:
 * 1. We screwed up and misused the API.
 * 2. The first peer is disconnected.
 */
static struct command_result *sendpay_failed(struct command *cmd,
					     const char *method UNUSED,
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
	struct short_channel_id_dir scidd_disable = {
	    .scid = route->hops[0].scid, .dir = route->hops[0].direction};
	payment_disable_chan(payment, scidd_disable, LOG_INFORM,
			     "sendpay didn't like first hop: %s", msg);

	if (!route_map_del(routetracker->sent_routes, route))
		plugin_err(pay_plugin->plugin,
			   "%s: route (%s) is not marked as sent",
			   __func__,
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
			break;
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
				   __func__, payment->groupid,
				   r->key.groupid);
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
				   __func__);
		}
	}
	for (size_t i = 0; i < ncompleted; i++)
		tal_free(routetracker->finalized_routes[i]);
	tal_resize(&routetracker->finalized_routes, 0);
}

struct command_result *route_sendpay_request(struct command *cmd,
					     struct route *route TAKES,
					     struct payment *payment)
{
	const struct payment_info *pinfo = &payment->payment_info;
	struct out_req *req = jsonrpc_request_start(
	    cmd, "renesendpay", sendpay_done, sendpay_failed, route);

	const size_t pathlen = tal_count(route->hops);
	json_add_sha256(req->js, "payment_hash", &pinfo->payment_hash);
	json_add_u64(req->js, "partid", route->key.partid);
	json_add_u64(req->js, "groupid", route->key.groupid);
	json_add_string(req->js, "invoice", pinfo->invstr);
	json_add_node_id(req->js, "destination", &pinfo->destination);
	json_add_amount_msat(req->js, "amount_msat", route->amount_deliver);
	json_add_amount_msat(req->js, "total_amount_msat", pinfo->amount);
	json_add_u32(req->js, "final_cltv", pinfo->final_cltv);

	if (pinfo->label)
		json_add_string(req->js, "label", pinfo->label);
	if (pinfo->description)
		json_add_string(req->js, "description", pinfo->description);

	json_array_start(req->js, "route");
	/* An empty route means a payment to oneself, pathlen=0 */
	for (size_t j = 0; j < pathlen; j++) {
		const struct route_hop *hop = &route->hops[j];
		json_object_start(req->js, NULL);
		json_add_node_id(req->js, "id", &hop->node_id);
		json_add_short_channel_id(req->js, "channel", hop->scid);
		json_add_amount_msat(req->js, "amount_msat", hop->amount);
		json_add_num(req->js, "direction", hop->direction);
		json_add_u32(req->js, "delay", hop->delay);
		json_add_string(req->js, "style", "tlv");
		json_object_end(req->js);
	}
	json_array_end(req->js);

	/* Either we have a payment_secret for BOLT11 or blinded_paths for
	 * BOLT12 */
	if (pinfo->payment_secret)
		json_add_secret(req->js, "payment_secret", pinfo->payment_secret);
	else {
		assert(pinfo->blinded_paths);
		const struct blinded_path *bpath =
		    pinfo->blinded_paths[route->path_num];
		json_myadd_blinded_path(req->js, "blinded_path", bpath);

	}

	route_map_add(payment->routetracker->sent_routes, route);
	if (taken(route))
		tal_steal(payment->routetracker->sent_routes, route);
	return send_outreq(req);
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
	route->result = tal_sendpay_result_from_json(route, buf, sub,
						     route->shared_secrets);
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
	return routefail_start(payment, route, cmd);
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
		/* This route was not created by us, make a basic route
		 * information dummy without hop details to pass onward. */
		route = tal_route_from_json(tmpctx, buf, sub);
		if(!route)
		plugin_err(pay_plugin->plugin,
			   "Failed to get route information from sendpay_success: %.*s",
			   json_tok_full_len(sub), json_tok_full(buf, sub));
	}

	assert(route->result == NULL);
	route->result = tal_sendpay_result_from_json(route, buf, sub,
						     route->shared_secrets);
	if (route->result == NULL)
		plugin_err(pay_plugin->plugin,
			   "Unable to parse sendpay_success: %.*s",
			   json_tok_full_len(sub), json_tok_full(buf, sub));

	assert(route->result->status == SENDPAY_COMPLETE);
	routetracker_add_to_final(payment->routetracker, route);
	return notification_handled(cmd);
}
