#include <common/json_stream.h>
#include <plugins/renepay/json.h>
#include <plugins/renepay/payment.h>
#include <plugins/renepay/payplugin.h>
#include <plugins/renepay/routefail.h>
#include <plugins/renepay/routetracker.h>

struct routetracker *new_routetracker(const tal_t *ctx)
{
	struct routetracker *rt = tal(ctx, struct routetracker);

	rt->sent_routes = tal(rt, struct route_map);
	route_map_init(rt->sent_routes);

	rt->pending_routes = tal(rt, struct route_map);
	route_map_init(rt->pending_routes);

	rt->finalized_routes = tal_arr(rt, struct route *, 0);
	return rt;
}

size_t routetracker_count_sent(struct routetracker *routetracker)
{
	return route_map_count(routetracker->sent_routes);
}

void routetracker_cleanup(struct routetracker *routetracker)
{
	// TODO
}

static void routetracker_add_to_final(struct routetracker *routetracker,
				      struct route *route)
{
	if (!route_map_del(routetracker->pending_routes, route))
		plugin_err(pay_plugin->plugin,
			   "%s: route with key %s is not in pending_routes",
			   __PRETTY_FUNCTION__,
			   fmt_routekey(tmpctx, &route->key));
	tal_arr_expand(&routetracker->finalized_routes, route);
	tal_steal(routetracker, route);
}
static void route_is_success(struct route *route)
{
	routetracker_add_to_final(route->payment->routetracker, route);
}
void route_is_failure(struct route *route)
{
	routetracker_add_to_final(route->payment->routetracker, route);
}
static void route_sent(struct route *route)
{
	struct routetracker *routetracker = route->payment->routetracker;
	route_map_add(routetracker->sent_routes, route);
	tal_steal(routetracker, route);
}
static void route_sendpay_fail(struct route *route TAKES)
{
	struct routetracker *routetracker = route->payment->routetracker;
	if (!route_map_del(routetracker->sent_routes, route))
		plugin_log(pay_plugin->plugin, LOG_UNUSUAL,
			   "%s: route (%s) is not marked as sent",
			   __PRETTY_FUNCTION__,
			   fmt_routekey(tmpctx, &route->key));
	tal_free(route);
}

/* This route is pending, ie. locked in HTLCs.
 * Called either:
 *	- after a sendpay is accepted,
 *	- or after listsendpays reveals some pending route that we didn't
 *	previously know about. */
void route_pending(const struct route *route)
{
	assert(route);
	struct payment *payment = route->payment;
	assert(payment);
	assert(payment->groupid == route->key.groupid);
	struct routetracker *routetracker = payment->routetracker;
	assert(routetracker);

	/* we already keep track of this route */
	if (route_map_get(routetracker->pending_routes, &route->key))
		return;

	if (!route_map_del(routetracker->sent_routes, route))
		plugin_log(pay_plugin->plugin, LOG_DBG,
			   "%s: tracking a route (%s) not computed by this "
			   "payment call",
			   __PRETTY_FUNCTION__,
			   fmt_routekey(tmpctx, &route->key));

	uncertainty_commit_htlcs(pay_plugin->uncertainty, route);
	route_map_add(routetracker->pending_routes, route);
	tal_steal(routetracker, route);

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

static void route_result_collected(struct route *route TAKES)
{
	assert(route);
	assert(route->result);
	// TODO: also improve knowledge here?
	uncertainty_remove_htlcs(pay_plugin->uncertainty, route);

	assert(route->payment);
	struct payment *payment = route->payment;
	assert(payment->groupid == route->key.groupid);

	if (route->result->status == SENDPAY_FAILED) {
		if (!amount_msat_sub(&payment->total_delivering,
				     payment->total_delivering,
				     route_delivers(route)) ||
		    !amount_msat_sub(&payment->total_sent, payment->total_sent,
				     route_sends(route))) {
			plugin_err(pay_plugin->plugin,
				   "%s: routes do not add up to "
				   "payment total amount.",
				   __PRETTY_FUNCTION__);
		}
	}
	tal_free(route);
}

/* Callback function for sendpay request success. */
static struct command_result *sendpay_done(struct command *cmd,
					   const char *buf UNUSED,
					   const jsmntok_t *result UNUSED,
					   struct route *route)
{
	assert(route);
	route_pending(route);
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
	assert(route->payment);
	struct payment *payment = route->payment;

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

	route_sendpay_fail(take(route));
	return command_still_pending(cmd);
}

void payment_collect_results(struct payment *payment,
			     struct preimage **payment_preimage,
			     enum jsonrpc_errcode *final_error,
			     const char **final_msg)
{
	assert(payment);
	assert(payment->routetracker);
	struct routetracker *routetracker;
	const size_t ncompleted = tal_count(routetracker->finalized_routes);
	for (size_t i = 0; i < ncompleted; i++) {
		struct route *r = routetracker->finalized_routes[i];
		assert(r);
		assert(r->result);

		/* We should never start a new groupid while there are pending
		 * onions with a different groupid. */
		if (payment->groupid != r->key.groupid) {
			plugin_err(pay_plugin->plugin,
				   "%s: current groupid=%" PRIu64
				   ", but recieved a sendpay result with "
				   "groupid=%" PRIu64,
				   __PRETTY_FUNCTION__, payment->groupid,
				   r->key.groupid);
		}

		assert(r->result->status == SENDPAY_COMPLETE ||
		       r->result->status == SENDPAY_FAILED);
		if (r->result->status == SENDPAY_COMPLETE && payment_preimage) {
			assert(r->result->payment_preimage);
			*payment_preimage =
			    tal_dup(payment, struct preimage,
				    r->result->payment_preimage);
		}

		if (r->result->status == SENDPAY_FAILED) {
			if (r->final_msg) {
				if (final_error)
					*final_error = r->final_error;

				if (final_msg)
					*final_msg =
					    tal_strdup(tmpctx, r->final_msg);
			}
		}
		route_result_collected(take(r));
	}
	tal_resize(routetracker->finalized_routes, 0);
}

struct command_result *route_sendpay_request(struct command *cmd,
					     struct route *route)
{
	struct out_req *req =
	    jsonrpc_request_start(pay_plugin->plugin, cmd, "sendpay",
				  sendpay_done, sendpay_failed, route);
	json_array_start(req->js, "route");
	assert(route->hops);
	const size_t pathlen = tal_count(route->hops);
	assert(pathlen > 0);

	struct payment *payment = route->payment;
	assert(payment);

	for (size_t j = 0; j < pathlen; j++) {
		const struct route_hop *hop = &route->hops[j];

		json_object_start(req->js, NULL);
		json_add_node_id(req->js, "id", &hop->node_id);
		json_add_short_channel_id(req->js, "channel", &hop->scid);
		json_add_amount_msat(req->js, "amount_msat", hop->amount);
		json_add_num(req->js, "direction", hop->direction);
		json_add_u32(req->js, "delay", hop->delay);
		json_add_string(req->js, "style", "tlv");
		json_object_end(req->js);
	}
	json_array_end(req->js);
	json_add_sha256(req->js, "payment_hash", &payment->payment_hash);
	json_add_secret(req->js, "payment_secret", payment->payment_secret);

	/* FIXME: sendpay has a check that we don't total more than
	 * the exact amount, if we're setting partid (i.e. MPP).
	 * However, we always set partid, and we add a shadow amount if
	 * we've only have one part, so we have to use that amount
	 * here.
	 *
	 * The spec was loosened so you are actually allowed
	 * to overpay, so this check is now overzealous. */
	if (amount_msat_greater(route_delivers(route), payment->amount)) {
		json_add_amount_msat(req->js, "amount_msat",
				     route_delivers(route));
	} else {
		json_add_amount_msat(req->js, "amount_msat", payment->amount);
	}
	json_add_u64(req->js, "partid", route->key.partid);
	json_add_u64(req->js, "groupid", route->key.groupid);

	/* FIXME: some of these fields might not be required for all
	 * payment parts. */
	json_add_string(req->js, "bolt11", payment->invstr);

	if (payment->payment_metadata)
		json_add_hex_talarr(req->js, "payment_metadata",
				    payment->payment_metadata);
	if (payment->label)
		json_add_string(req->js, "label", payment->label);
	if (payment->description)
		json_add_string(req->js, "description", payment->description);

	route_sent(route);
	return send_outreq(pay_plugin->plugin, req);
}

struct command_result *notification_sendpay_failure(struct command *cmd,
						    const char *buf,
						    const jsmntok_t *params)
{
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

	assert(payment->routetracker);
	struct route *route =
	    route_map_get(payment->routetracker->pending_routes, key);
	if (!route)
		plugin_err(pay_plugin->plugin,
			   "%s: key %s is not found in pending_routes",
			   __PRETTY_FUNCTION__, fmt_routekey(tmpctx, key));

	route->result = tal_sendpay_result_from_json(route, buf, sub);
	if (route->result == NULL)
		plugin_err(pay_plugin->plugin,
			   "Unable to parse sendpay_failure: %.*s",
			   json_tok_full_len(sub), json_tok_full(buf, sub));

	assert(route->result->status == SENDPAY_COMPLETE);
	routefail_start(route, route, cmd);
	return notification_handled(cmd);
}

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

	struct payment *payment =
	    payment_map_get(pay_plugin->payment_map, key->payment_hash);

	if (!payment) {
		/* This sendpay is not linked to any route in our database, we
		 * skip it. */
		return notification_handled(cmd);
	}

	assert(payment->routetracker);
	struct route *route =
	    route_map_get(payment->routetracker->pending_routes, key);
	if (!route)
		plugin_err(pay_plugin->plugin,
			   "%s: key %s is not found in pending_routes",
			   __PRETTY_FUNCTION__, fmt_routekey(tmpctx, key));

	route->result = tal_sendpay_result_from_json(route, buf, sub);
	if (route->result == NULL)
		plugin_err(pay_plugin->plugin,
			   "Unable to parse sendpay_success: %.*s",
			   json_tok_full_len(sub), json_tok_full(buf, sub));

	assert(route->result->status == SENDPAY_COMPLETE);
	route_is_success(route);
	return notification_handled(cmd);
}
