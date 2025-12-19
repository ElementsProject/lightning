#include "config.h"
#include <common/json_stream.h>
#include <common/onion_encode.h>
#include <common/sphinx.h>
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
	rt->finalized_routes = tal_arr(rt, struct route *, 0);

	if (!rt->computed_routes || !rt->finalized_routes)
		/* bad allocation */
		return tal_free(rt);

	return rt;
}

bool routetracker_have_results(struct routetracker *routetracker)
{
	return tal_count(routetracker->finalized_routes) > 0;
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

static void route_success_register(struct routetracker *routetracker,
				   struct route *route)
{
	if(route->hops){
		uncertainty_route_success(pay_plugin->uncertainty, route);
	}
	routetracker_add_to_final(routetracker, route);
}
void route_failure_register(struct routetracker *routetracker,
			    struct route *route)
{
	struct payment_result *result = route->result;
	assert(result);

	/* Update the knowledge in the uncertaity network. */
	if (route->hops && result->failcode) {
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

		if (*result->failcode == WIRE_TEMPORARY_CHANNEL_FAILURE &&
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
	}
	routetracker_add_to_final(routetracker, route);
}

static void remove_route(struct route *route, struct route_map *map)
{
	route_map_del(map, route);
	uncertainty_remove_htlcs(pay_plugin->uncertainty, route);
}

/* This route is pending, ie. locked in HTLCs.
 * Called either:
 *	- after a sendpay is accepted,
 *	- or after listsendpays reveals some pending route that we didn't
 *	previously know about. */
static void route_pending_register(struct routetracker *routetracker,
				   struct route *route TAKES)
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

	uncertainty_commit_htlcs(pay_plugin->uncertainty, route);

	if (taken(route))
		tal_steal(pay_plugin->pending_routes, route);

	if (!route_map_add(pay_plugin->pending_routes, route) ||
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

		if (!amount_msat_deduct(&payment->total_delivering,
					route_delivers(r)) ||
		    !amount_msat_deduct(&payment->total_sent,
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

static void sphinx_append_blinded_path(const tal_t *ctx,
				       struct sphinx_path *sp,
				       const struct blinded_path *blinded_path,
				       const struct amount_msat deliver,
				       const struct amount_msat total,
				       const u32 final_cltv)
{
	const size_t pathlen = tal_count(blinded_path->path);
	bool ret;

	for (size_t i = 0; i < pathlen; i++) {
		bool first = (i == 0);
		bool final = (i == pathlen - 1);

		const struct blinded_path_hop *bhop = blinded_path->path[i];
		const u8 *payload = onion_blinded_hop(
		    ctx, final ? &deliver : NULL, final ? &total : NULL,
		    final ? &final_cltv : NULL, bhop->encrypted_recipient_data,
		    first ? &blinded_path->first_path_key : NULL);
		// FIXME: better handle error here
		ret = sphinx_add_hop_has_length(
		    sp,
		    first ? &blinded_path->first_node_id.pubkey
			  : &bhop->blinded_node_id,
		    take(payload));
		assert(ret);
	}
}

static void sphinx_append_final_hop(const tal_t *ctx,
				    struct sphinx_path *sp,
				    const struct secret *payment_secret,
				    const struct node_id *node,
				    const struct amount_msat deliver,
				    const struct amount_msat total,
				    const u32 final_cltv,
				    const u8 *payment_metadata)
{
	struct pubkey destination;
	bool ret = pubkey_from_node_id(&destination, node);
	assert(ret);

	const u8 *payload = onion_final_hop(ctx, deliver, final_cltv, total,
					    payment_secret, payment_metadata);
	// FIXME: better handle error here
	ret = sphinx_add_hop_has_length(sp, &destination, take(payload));
	assert(ret);
}

static const u8 *create_onion(
    const tal_t *ctx, const unsigned int blockheight,
    const struct route_hop *route, const struct sha256 *payment_hash,
    const u32 final_cltv_delta, const struct blinded_path *blinded_path,
    const struct secret *payment_secret, const struct amount_msat total_amount,
    const struct amount_msat deliver_amount, const u8 *metadata,
    const struct node_id first_node, const size_t first_index,
    struct secret **shared_secrets)
{
	bool ret;
	const tal_t *this_ctx = tal(ctx, tal_t);
	struct node_id current_node = first_node;
	struct pubkey node;
	const u8 *payload;
	const size_t pathlen = tal_count(route);

	struct sphinx_path *sp = sphinx_path_new(this_ctx, payment_hash->u.u8,
						 sizeof(payment_hash->u.u8));

	for (size_t i = first_index; i < pathlen; i++) {
		/* Encrypted message is for node[i] but the data is hop[i+1],
		 * therein lays the problem with sendpay's API. */
		ret = pubkey_from_node_id(&node, &current_node);
		assert(ret);

		const struct route_hop *hop = &route[i];
		payload = onion_nonfinal_hop(this_ctx, &hop->scid, hop->amount,
					     hop->delay + blockheight);
		// FIXME: better handle error here
		ret = sphinx_add_hop_has_length(sp, &node, take(payload));
		assert(ret);
		current_node = route[i].node_id;
	}

	const u32 final_cltv = final_cltv_delta + blockheight;
	if (blinded_path) {
		sphinx_append_blinded_path(this_ctx, sp, blinded_path,
					   deliver_amount, total_amount,
					   final_cltv);
	} else {
		sphinx_append_final_hop(this_ctx, sp, payment_secret,
					&current_node, deliver_amount,
					total_amount, final_cltv, metadata);
	}

	struct onionpacket *packet =
	    create_onionpacket(this_ctx, sp, ROUTING_INFO_SIZE, shared_secrets);
	*shared_secrets = tal_steal(ctx, *shared_secrets);

	const u8 *onion = serialize_onionpacket(ctx, packet);
	tal_free(this_ctx);
	return onion;
}

static u32 initial_cltv_delta(const struct route *route,
			      const struct payment_info *pinfo)
{
	if (tal_count(route->hops) == 0)
		return pinfo->final_cltv;
	return route->hops[0].delay;
}

static struct command_result *sendonion_done(struct command *aux_cmd,
					     const char *method UNUSED,
					     const char *buffer UNUSED,
					     const jsmntok_t *toks UNUSED,
					     struct payment *payment UNUSED)
{
	return aux_command_done(aux_cmd);
}

static struct command_result *
sendonion_fail(struct command *aux_cmd, const char *method, const char *buffer,
	       const jsmntok_t *toks, struct payment *payment UNUSED)
{
	plugin_log(aux_cmd->plugin, LOG_DBG, "%s failed with: %.*s", method,
		   json_tok_full_len(toks), json_tok_full(buffer, toks));
	return aux_command_done(aux_cmd);
}

struct command_result *route_sendpay_request(struct command *cmd,
					     struct route *route TAKES,
					     struct payment *payment)
{
	// build onion
	const u8 *onion;
	const struct payment_info *pinfo;
	const struct blinded_path *blinded_path = NULL;
	struct out_req *req;

	pinfo = &payment->payment_info;
	if (tal_count(pinfo->blinded_paths) > 0) {
		assert(route->path_num < tal_count(pinfo->blinded_paths));
		blinded_path = pinfo->blinded_paths[route->path_num];
	}

	if (tal_count(route->hops) > 0) {
		onion = create_onion(
		    route, payment->blockheight, route->hops,
		    &pinfo->payment_hash, pinfo->final_cltv, blinded_path,
		    pinfo->payment_secret, pinfo->amount, route->amount_deliver,
		    /* metadata = */ NULL, route->hops[0].node_id, 1,
		    &route->shared_secrets);
	} else {
		/* This is either a self-payment or a payment through a blinded
		 * path that starts at our node. */
		onion = create_onion(route, payment->blockheight, route->hops,
				     &pinfo->payment_hash, pinfo->final_cltv,
				     blinded_path, pinfo->payment_secret,
				     pinfo->amount, route->amount_deliver,
				     /* metadata = */ NULL, pay_plugin->my_id,
				     0, &route->shared_secrets);
	}

	// send onion
	// FIXME: use injectpaymentonion in both cases
	if (tal_count(route->hops) > 0) {
		req = jsonrpc_request_start(cmd, "sendonion", sendonion_done,
					    sendonion_fail, payment);
		json_add_hex_talarr(req->js, "onion", onion);
		json_add_sha256(req->js, "payment_hash", &pinfo->payment_hash);
		json_add_u64(req->js, "partid", route->key.partid);
		json_add_u64(req->js, "groupid", route->key.groupid);
		json_add_amount_msat(req->js, "amount_msat",
				     route->amount_deliver);
		if (pinfo->label)
			json_add_string(req->js, "label", pinfo->label);
		if (pinfo->invstr)
			json_add_string(req->js, "bolt11", pinfo->invstr);
		if (pinfo->description)
			json_add_string(req->js, "description",
					pinfo->description);
		json_add_node_id(req->js, "destination", &pinfo->destination);
		json_add_amount_msat(req->js, "total_amount_msat",
				     pinfo->amount);

		json_array_start(req->js, "shared_secrets");
		for (size_t i = 0; i < tal_count(route->shared_secrets); i++) {
			json_add_secret(req->js, NULL,
					&route->shared_secrets[i]);
		}
		json_array_end(req->js);

		const struct route_hop *hop = &route->hops[0];
		json_object_start(req->js, "first_hop");
		json_add_amount_msat(req->js, "amount_msat", hop->amount);
		json_add_node_id(req->js, "id", &hop->node_id);
		json_add_short_channel_id(req->js, "channel", hop->scid);
		json_add_num(req->js, "delay",
			     hop->delay + payment->blockheight);
		json_object_end(req->js);

		// FIXME: No localinvreqid is provided
	} else {
		req = jsonrpc_request_start(cmd, "injectpaymentonion",
					    sendonion_done, sendonion_fail,
					    payment);
		json_add_hex_talarr(req->js, "onion", onion);
		json_add_sha256(req->js, "payment_hash", &pinfo->payment_hash);
		json_add_u64(req->js, "partid", route->key.partid);
		json_add_u64(req->js, "groupid", route->key.groupid);
		json_add_amount_msat(req->js, "amount_msat",
				     route->amount_sent);
		if (pinfo->label)
			json_add_string(req->js, "label", pinfo->label);
		if (pinfo->invstr)
			json_add_string(req->js, "invstring", pinfo->invstr);
		json_add_amount_msat(req->js, "destination_msat",
				     route->amount_deliver);
		json_add_u32(req->js, "cltv_expiry",
			     initial_cltv_delta(route, pinfo) +
				 payment->blockheight);
		// FIXME: No localinvreqid is provided
	}
	route_pending_register(payment->routetracker, route);
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
	route_success_register(payment->routetracker, route);
	return notification_handled(cmd);
}
