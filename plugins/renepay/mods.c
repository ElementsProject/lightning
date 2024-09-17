#include "config.h"
#include <ccan/bitmap/bitmap.h>
#include <common/amount.h>
#include <common/bolt11.h>
#include <common/gossmods_listpeerchannels.h>
#include <common/json_stream.h>
#include <plugins/renepay/json.h>
#include <plugins/renepay/mcf.h>
#include <plugins/renepay/mods.h>
#include <plugins/renepay/payplugin.h>
#include <plugins/renepay/renepayconfig.h>
#include <plugins/renepay/route.h>
#include <plugins/renepay/routebuilder.h>
#include <plugins/renepay/routetracker.h>
#include <unistd.h>

#define INVALID_ID UINT32_MAX

#define OP_NULL NULL
#define OP_CALL (void *)1
#define OP_IF (void *)2

void *payment_virtual_program[];

/* Advance the payment virtual machine */
struct command_result *payment_continue(struct payment *payment)
{
	assert(payment->exec_state != INVALID_STATE);
	void *op = payment_virtual_program[payment->exec_state++];

	if (op == OP_NULL) {
		plugin_err(pay_plugin->plugin,
			   "payment_continue reached the end of the virtual "
			   "machine execution.");
	} else if (op == OP_CALL) {
		const struct payment_modifier *mod =
		    (const struct payment_modifier *)
			payment_virtual_program[payment->exec_state++];

		if (mod == NULL)
			plugin_err(pay_plugin->plugin,
				   "payment_continue expected payment_modifier "
				   "but NULL found");

		plugin_log(pay_plugin->plugin, LOG_DBG, "Calling modifier %s",
			   mod->name);
		return mod->step_cb(payment);
	} else if (op == OP_IF) {
		const struct payment_condition *cond =
		    (const struct payment_condition *)
			payment_virtual_program[payment->exec_state++];

		if (cond == NULL)
			plugin_err(pay_plugin->plugin,
				   "payment_continue expected pointer to "
				   "condition but NULL found");

		plugin_log(pay_plugin->plugin, LOG_DBG,
			   "Calling payment condition %s", cond->name);

		const u64 position_iftrue =
			(intptr_t)payment_virtual_program[payment->exec_state++];

		if (cond->condition_cb(payment))
			payment->exec_state = position_iftrue;

		return payment_continue(payment);
	}
	plugin_err(pay_plugin->plugin, "payment_continue op code not defined");
	return NULL;
}


/* Generic handler for RPC failures that should end up failing the payment. */
static struct command_result *payment_rpc_failure(struct command *cmd,
						  const char *buffer,
						  const jsmntok_t *toks,
						  struct payment *payment)
{
	const jsmntok_t *codetok = json_get_member(buffer, toks, "code");
	u32 errcode;
	if (codetok != NULL)
		json_to_u32(buffer, codetok, &errcode);
	else
		errcode = LIGHTNINGD;

	return payment_fail(
	    payment, errcode,
	    "Failing a partial payment due to a failed RPC call: %.*s",
	    json_tok_full_len(toks), json_tok_full(buffer, toks));
}

/*****************************************************************************
 * previoussuccess
 *
 * Obtain a list of previous sendpay requests and check if
 * the current payment hash has already succeed.
 */

struct success_data {
	u32 parts, created_at, groupid;
	struct amount_msat deliver_msat, sent_msat;
	struct preimage preimage;
};

/* Extracts success data from listsendpays. */
static bool success_data_from_listsendpays(const char *buf,
					   const jsmntok_t *arr,
					   struct success_data *success)
{
	assert(success);

	size_t i;
	const char *err;
	const jsmntok_t *t;
	assert(arr && arr->type == JSMN_ARRAY);

	success->parts = 0;
	success->deliver_msat = AMOUNT_MSAT(0);
	success->sent_msat = AMOUNT_MSAT(0);

	json_for_each_arr(i, t, arr)
	{
		u32 groupid;
		struct amount_msat this_msat, this_sent;

		const jsmntok_t *status_tok = json_get_member(buf, t, "status");
		if (!status_tok)
			plugin_err(
			    pay_plugin->plugin,
			    "%s (line %d) missing status token from json.",
			    __func__, __LINE__);
		const char *status = json_strdup(tmpctx, buf, status_tok);
		if (!status)
			plugin_err(
			    pay_plugin->plugin,
			    "%s (line %d) failed to allocate status string.",
			    __func__, __LINE__);

		if (streq(status, "complete")) {
			/* FIXME we assume amount_msat is always present, but
			 * according to the documentation this field is
			 * optional. How do I interpret if amount_msat is
			 * missing? */
			err = json_scan(
			    tmpctx, buf, t,
			    "{groupid:%"
			    ",amount_msat:%"
			    ",amount_sent_msat:%"
			    ",created_at:%"
			    ",payment_preimage:%}",
			    JSON_SCAN(json_to_u32, &groupid),
			    JSON_SCAN(json_to_msat, &this_msat),
			    JSON_SCAN(json_to_msat, &this_sent),
			    JSON_SCAN(json_to_u32, &success->created_at),
			    JSON_SCAN(json_to_preimage, &success->preimage));

			if (err)
				plugin_err(pay_plugin->plugin,
					   "%s (line %d) json_scan of "
					   "listsendpay returns the "
					   "following error: %s",
					   __func__, __LINE__, err);
			success->groupid = groupid;
			/* Now we know the payment completed. */
			if (!amount_msat_add(&success->deliver_msat,
					     success->deliver_msat,
					     this_msat) ||
			    !amount_msat_add(&success->sent_msat,
					     success->sent_msat, this_sent))
				plugin_err(pay_plugin->plugin,
					   "%s (line %d) amount_msat overflow.",
					   __func__, __LINE__);

			success->parts++;
		}
	}

	return success->parts > 0;
}

static struct command_result *previoussuccess_done(struct command *cmd,
						   const char *buf,
						   const jsmntok_t *result,
						   struct payment *payment)
{
	const jsmntok_t *arr = json_get_member(buf, result, "payments");
	if (!arr || arr->type != JSMN_ARRAY) {
		return payment_fail(
		    payment, LIGHTNINGD,
		    "Unexpected non-array result from listsendpays: %.*s",
		    json_tok_full_len(result), json_tok_full(buf, result));
	}

	struct success_data success;
	if (!success_data_from_listsendpays(buf, arr, &success)) {
		/* There are no success sendpays. */
		return payment_continue(payment);
	}

	payment->payment_info.start_time.ts.tv_sec = success.created_at;
	payment->payment_info.start_time.ts.tv_nsec = 0;
	payment->total_delivering = success.deliver_msat;
	payment->total_sent = success.sent_msat;
	payment->next_partid = success.parts + 1;
	payment->groupid = success.groupid;

	payment_note(payment, LOG_DBG,
		     "Payment completed by a previous sendpay.");
	return payment_success(payment, &success.preimage);
}

static struct command_result *previoussuccess_cb(struct payment *payment)
{
	struct command *cmd = payment_command(payment);
	assert(cmd);

	struct out_req *req = jsonrpc_request_start(
	    cmd->plugin, cmd, "listsendpays", previoussuccess_done,
	    payment_rpc_failure, payment);

	json_add_sha256(req->js, "payment_hash",
			&payment->payment_info.payment_hash);
	json_add_string(req->js, "status", "complete");
	return send_outreq(cmd->plugin, req);
}

REGISTER_PAYMENT_MODIFIER(previoussuccess, previoussuccess_cb);

/*****************************************************************************
 * initial_sanity_checks
 *
 * Some checks on a payment about to start.
 */
static struct command_result *initial_sanity_checks_cb(struct payment *payment)
{
	assert(amount_msat_is_zero(payment->total_sent));
	assert(amount_msat_is_zero(payment->total_delivering));
	assert(!payment->preimage);
	assert(tal_count(payment->cmd_array) == 1);

	return payment_continue(payment);
}

REGISTER_PAYMENT_MODIFIER(initial_sanity_checks, initial_sanity_checks_cb);

/*****************************************************************************
 * selfpay
 *
 * Checks if the payment destination is the sender's node and perform a self
 * payment.
 */

static struct command_result *selfpay_success(struct command *cmd,
					      const char *buf,
					      const jsmntok_t *tok,
					      struct route *route)
{
	tal_steal(tmpctx, route); // discard this route when tmpctx clears
	struct payment *payment =
		    payment_map_get(pay_plugin->payment_map, route->key.payment_hash);
	assert(payment);

	struct preimage preimage;
	const char *err;
	err = json_scan(tmpctx, buf, tok, "{payment_preimage:%}",
			JSON_SCAN(json_to_preimage, &preimage));
	if (err)
		plugin_err(
		    cmd->plugin, "selfpay didn't have payment_preimage: %.*s",
		    json_tok_full_len(tok), json_tok_full(buf, tok));


	payment_note(payment, LOG_DBG, "Paid with self-pay.");
	return payment_success(payment, &preimage);
}
static struct command_result *selfpay_failure(struct command *cmd,
					      const char *buf,
					      const jsmntok_t *tok,
					      struct route *route)
{
	tal_steal(tmpctx, route); // discard this route when tmpctx clears
	struct payment *payment =
		    payment_map_get(pay_plugin->payment_map, route->key.payment_hash);
	assert(payment);
	struct payment_result *result = tal_sendpay_result_from_json(tmpctx, buf, tok);
	if (result == NULL)
		plugin_err(pay_plugin->plugin,
			   "Unable to parse sendpay failure: %.*s",
			   json_tok_full_len(tok), json_tok_full(buf, tok));

	return payment_fail(payment, result->code, "%s", result->message);
}

static struct command_result *selfpay_cb(struct payment *payment)
{
	if (!node_id_eq(&pay_plugin->my_id,
			&payment->payment_info.destination)) {
		return payment_continue(payment);
	}

	struct command *cmd = payment_command(payment);
	if (!cmd)
		plugin_err(pay_plugin->plugin,
			   "Selfpay: cannot get a valid cmd.");

	struct payment_info *pinfo = &payment->payment_info;
	/* Self-payment routes are not part of the routetracker, we build them
	 * on-the-fly here and release them on success or failure. */
	struct route *route =
	    new_route(payment, payment->groupid,
		      /*partid=*/0, pinfo->payment_hash,
		      pinfo->amount, pinfo->amount);
	struct out_req *req;
	req = jsonrpc_request_start(cmd->plugin, cmd, "sendpay",
				    selfpay_success, selfpay_failure, route);
	route->hops = tal_arr(route, struct route_hop, 0);
	json_add_route(req->js, route, payment);
	return send_outreq(cmd->plugin, req);
}

REGISTER_PAYMENT_MODIFIER(selfpay, selfpay_cb);

/*****************************************************************************
 * refreshgossmap
 *
 * Update the gossmap.
 */

static struct command_result *refreshgossmap_cb(struct payment *payment)
{
	assert(pay_plugin->gossmap); // gossmap must be already initialized
	assert(payment);
	assert(payment->local_gossmods);

	size_t num_channel_updates_rejected = 0;
	bool gossmap_changed =
	    gossmap_refresh(pay_plugin->gossmap, &num_channel_updates_rejected);

	if (gossmap_changed && num_channel_updates_rejected)
		plugin_log(pay_plugin->plugin, LOG_DBG,
			   "gossmap ignored %zu channel updates",
			   num_channel_updates_rejected);

	return payment_continue(payment);
}

REGISTER_PAYMENT_MODIFIER(refreshgossmap, refreshgossmap_cb);

/*****************************************************************************
 * routehints
 *
 * Use route hints from the invoice to update the local gossmods and uncertainty
 * network.
 */

struct routehints_batch {
	size_t num_elements;
	struct payment *payment;
};

static struct command_result *add_one_hint_done(struct command *cmd,
						const char *buf UNUSED,
						const jsmntok_t *result UNUSED,
						struct routehints_batch *batch)
{
	assert(batch->num_elements);
	assert(batch->payment);
	batch->num_elements--;

	if (!batch->num_elements)
		return payment_continue(batch->payment);

	return command_still_pending(cmd);
}

static struct command_result *
add_one_hint_failed(struct command *cmd, const char *buf,
		    const jsmntok_t *result, struct routehints_batch *batch)
{
	plugin_log(cmd->plugin, LOG_UNUSUAL,
		   "failed to create channel hint: %.*s",
		   json_tok_full_len(result), json_tok_full(buf, result));
	return add_one_hint_done(cmd, buf, result, batch);
}

static struct command_result *routehints_cb(struct payment *payment)
{
	struct command *cmd = payment_command(payment);
	assert(cmd);

	/* For each channel hint, if not in gossmap make a request to
	 * askrene-create-channel
	 * */
	size_t num_channel_updates_rejected = 0;
	bool gossmap_changed =
	    gossmap_refresh(pay_plugin->gossmap, &num_channel_updates_rejected);
	if (gossmap_changed && num_channel_updates_rejected)
		plugin_log(pay_plugin->plugin, LOG_DBG,
			   "gossmap ignored %zu channel updates",
			   num_channel_updates_rejected);

	const struct route_info **routehints = payment->payment_info.routehints;
	if (!routehints)
		return payment_continue(payment);

	const struct node_id *destination = &payment->payment_info.destination;
	const size_t nhints = tal_count(routehints);
	struct routehints_batch *batch = tal(cmd, struct routehints_batch);
	batch->num_elements = 0;
	batch->payment = payment;

	for (size_t i = 0; i < nhints; i++) {
		/* Each one, presumably, leads to the destination */
		const struct route_info *r = routehints[i];
		const struct node_id *end = destination;

		for (int j = tal_count(r) - 1; j >= 0; j--) {
			struct gossmap_chan *chan = gossmap_find_chan(
			    pay_plugin->gossmap, &r[j].short_channel_id);

			if (chan)
				/* this channel is public, don't add a hint */
				continue;

			/* FIXME: what if the channel is local? can askrene
			 * handle trying to add the same channel twice? */

			struct out_req *req = jsonrpc_request_start(
			    cmd->plugin, cmd, "askrene-create-channel",
			    add_one_hint_done, add_one_hint_failed, batch);

			json_add_string(req->js, "layer",
					payment->private_layer);
			json_add_node_id(req->js, "source", &r[j].pubkey);
			json_add_node_id(req->js, "destination", end);
			json_add_short_channel_id(req->js, "short_channel_id",
						  r[j].short_channel_id);
			json_add_u32(req->js, "fee_base_msat",
				     r[j].fee_base_msat);
			json_add_u32(req->js, "fee_proportional_millionths",
				     r[j].fee_proportional_millionths);
			json_add_u32(req->js, "delay", r[j].cltv_expiry_delta);

			/* we don't have this information, we try to guess */
			json_add_amount_msat(req->js, "htlc_minimum_msat",
					     AMOUNT_MSAT(0));
			json_add_amount_msat(req->js, "htlc_maximum_msat",
					     MAX_CAPACITY);
			json_add_amount_msat(req->js, "capacity_msat",
					     MAX_CAPACITY);

			send_outreq(cmd->plugin, req);

			batch->num_elements++;
			end = &r[j].pubkey;
		}
	}
	return command_still_pending(cmd);
}

REGISTER_PAYMENT_MODIFIER(routehints, routehints_cb);

/*****************************************************************************
 * compute_routes
 *
 * Compute the payment routes.
 */

static bool json_to_myroute(const char *buf, const jsmntok_t *tok,
			    struct route *route)
{
	u64 probability_ppm;
	const char *err =
	    json_scan(tmpctx, buf, tok, "{probability_ppm:%,amount_msat:%}",
		      JSON_SCAN(json_to_u64, &probability_ppm),
		      JSON_SCAN(json_to_msat, &route->amount));
	if (err)
		return false;
	route->success_prob = probability_ppm * 1e-6;
	const jsmntok_t *path_tok = json_get_member(buf, tok, "path");
	if (!path_tok || path_tok->type != JSMN_ARRAY)
		return false;

	route->hops = tal_arr(route, struct route_hop, path_tok->size);
	if (!route->hops)
		return false;

	size_t i;
	const jsmntok_t *hop_tok;
	json_for_each_arr(i, hop_tok, path_tok)
	{
		struct route_hop *hop = &route->hops[i];
		err = json_scan(tmpctx, buf, hop_tok,
				"{short_channel_id:%,direction:%,next_node_id:%"
				",amount_msat:%,delay:%}",
				JSON_SCAN(json_to_short_channel_id, &hop->scid),
				JSON_SCAN(json_to_int, &hop->direction),
				JSON_SCAN(json_to_node_id, &hop->node_id),
				JSON_SCAN(json_to_msat, &hop->amount),
				JSON_SCAN(json_to_u32, &hop->delay));
		if (err) {
			route->hops = tal_free(route->hops);
			return false;
		}
	}
	route->amount_sent = route->hops[0].amount;
	return true;
}

static struct command_result *getroutes_done(struct command *cmd UNUSED,
					     const char *buf,
					     const jsmntok_t *result,
					     struct payment *payment)
{
	struct routetracker *routetracker = payment->routetracker;
	assert(routetracker);

	if (routetracker->computed_routes &&
	    tal_count(routetracker->computed_routes))
		plugin_err(pay_plugin->plugin,
			   "%s: no previously computed routes expected.",
			   __func__);
	routetracker->computed_routes = tal_free(routetracker->computed_routes);

	const jsmntok_t *routes_tok = json_get_member(buf, result, "routes");
	assert(routes_tok && routes_tok->type == JSMN_ARRAY);

	routetracker->computed_routes =
	    tal_arr(routetracker, struct route *, 0);

	size_t i;
	const jsmntok_t *r;
	json_for_each_arr(i, r, routes_tok)
	{
		struct route *route = new_route(
		    routetracker->computed_routes, payment->groupid,
		    payment->next_partid++, payment->payment_info.payment_hash,
		    AMOUNT_MSAT(0), AMOUNT_MSAT(0));
		assert(route);
		tal_arr_expand(&routetracker->computed_routes, route);
		bool success = json_to_myroute(buf, r, route);
		if (!success)
			plugin_err(pay_plugin->plugin,
				   "%s: failed to parse route from json: %.*s",
				   __func__, json_tok_full_len(r),
				   json_tok_full(buf, r));
		const size_t pathlen = tal_count(route->hops);
		if (!amount_msat_eq(route->amount,
				    route->hops[pathlen - 1].amount))
			plugin_log(pay_plugin->plugin, LOG_UNUSUAL,
				   "%s: route partid=%" PRIu64
				   " delivers %s which is different from what "
				   "it claims to "
				   "deliver %s",
				   __func__, route->key.partid,
				   fmt_amount_msat(
				       tmpctx, route->hops[pathlen - 1].amount),
				   fmt_amount_msat(tmpctx, route->amount));
		/* FIXME: it seems that the route we get in response claims to
		 * deliver an amount which is different to the amount in the
		 * last hop. */
		route->amount = route->hops[pathlen - 1].amount;
	}
	return payment_continue(payment);
}

static struct command_result *compute_routes_cb(struct payment *payment)
{
	assert(payment->status == PAYMENT_PENDING);
	struct amount_msat feebudget, fees_spent, remaining;

	/* Total feebudget  */
	if (!amount_msat_sub(&feebudget, payment->payment_info.maxspend,
			     payment->payment_info.amount))
		plugin_err(pay_plugin->plugin, "%s: fee budget is negative?",
			   __func__);

	/* Fees spent so far */
	if (!amount_msat_sub(&fees_spent, payment->total_sent,
			     payment->total_delivering))
		plugin_err(pay_plugin->plugin,
			   "%s: total_delivering is greater than total_sent?",
			   __func__);

	/* Remaining fee budget. */
	if (!amount_msat_sub(&feebudget, feebudget, fees_spent))
		feebudget = AMOUNT_MSAT(0);

	/* How much are we still trying to send? */
	if (!amount_msat_sub(&remaining, payment->payment_info.amount,
			     payment->total_delivering) ||
	    amount_msat_is_zero(remaining)) {
		plugin_log(pay_plugin->plugin, LOG_UNUSUAL,
			   "%s: Payment is pending with full amount already "
			   "committed. We skip the computation of new routes.",
			   __func__);
		return payment_continue(payment);
	}

	struct command *cmd = payment_command(payment);
	assert(cmd);
	struct out_req *req =
	    jsonrpc_request_start(cmd->plugin, cmd, "getroutes", getroutes_done,
				  payment_rpc_failure, payment);
	// FIXME: when multi-destination is needed to fully support blinded path
	// FIXME: we could have more than one algorithm to compute routes:
	// Minimum Cost Flows or the Max-Expected-Value (recently discussed with
	// Rene) or Dijkstra
	json_add_node_id(req->js, "source", &pay_plugin->my_id);
	json_add_node_id(req->js, "destination",
			 &payment->payment_info.destination);
	json_add_amount_msat(req->js, "amount_msat", remaining);
	json_array_start(req->js, "layers");
	// FIXME: put here the layers that we use
	json_add_string(req->js, NULL, "auto.sourcefree");
	json_add_string(req->js, NULL, "auto.localchans");
	json_add_string(req->js, NULL, RENEPAY_LAYER);
	json_add_string(req->js, NULL, payment->private_layer);
	json_array_end(req->js);
	json_add_amount_msat(req->js, "maxfee_msat", feebudget);
	json_add_u32(req->js, "final_cltv", payment->payment_info.final_cltv);
	return send_outreq(cmd->plugin, req);
}

REGISTER_PAYMENT_MODIFIER(compute_routes, compute_routes_cb);

/*****************************************************************************
 * send_routes
 *
 * This payment modifier takes the payment routes and starts the payment
 * request calling sendpay.
 */

static struct command_result *send_routes_cb(struct payment *payment)
{
	assert(payment);
	struct routetracker *routetracker = payment->routetracker;
	assert(routetracker);
	if (!routetracker->computed_routes ||
	    tal_count(routetracker->computed_routes) == 0) {
		plugin_log(pay_plugin->plugin, LOG_UNUSUAL,
			   "%s: there are no routes to send, skipping.",
			   __func__);
		return payment_continue(payment);
	}
	struct command *cmd = payment_command(payment);
	assert(cmd);
	for (size_t i = 0; i < tal_count(routetracker->computed_routes); i++) {
		struct route *route = routetracker->computed_routes[i];

		route_sendpay_request(cmd, take(route), payment);

		payment_note(payment, LOG_INFORM,
			     "Sent route request: partid=%" PRIu64
			     " amount=%s prob=%.3lf fees=%s delay=%u path=%s",
			     route->key.partid,
			     fmt_amount_msat(tmpctx, route_delivers(route)),
			     route->success_prob,
			     fmt_amount_msat(tmpctx, route_fees(route)),
			     route_delay(route), fmt_route_path(tmpctx, route));
	}
	tal_resize(&routetracker->computed_routes, 0);
	return payment_continue(payment);
}

REGISTER_PAYMENT_MODIFIER(send_routes, send_routes_cb);

/*****************************************************************************
 * sleep
 *
 * The payment main thread sleeps for some time.
 */

static void sleep_done(struct payment *payment)
{
	payment->waitresult_timer = NULL;
	// TODO: is this compulsory?
	timer_complete(pay_plugin->plugin);
	payment_continue(payment);
}

static struct command_result *sleep_cb(struct payment *payment)
{
	assert(payment->waitresult_timer == NULL);
	payment->waitresult_timer = plugin_timer(
	    pay_plugin->plugin, time_from_msec(COLLECTOR_TIME_WINDOW_MSEC), sleep_done, payment);
	struct command *cmd = payment_command(payment);
	assert(cmd);
	return command_still_pending(cmd);
}

REGISTER_PAYMENT_MODIFIER(sleep, sleep_cb);

/*****************************************************************************
 * collect_results
 */

static struct command_result *collect_results_cb(struct payment *payment)
{
	assert(payment);
	payment->have_results = false;
	payment->retry = false;

	/* pending sendpay callbacks should be zero */
	if (!routetracker_have_results(payment->routetracker))
		return payment_continue(payment);

	/* all sendpays have been sent, look for success */
	struct preimage *payment_preimage = NULL;
	enum jsonrpc_errcode final_error = LIGHTNINGD;
	const char *final_msg = NULL;

	payment_collect_results(payment, &payment_preimage, &final_error, &final_msg);

	if (payment_preimage) {
		/* If we have the preimage that means one succeed, we
		 * inmediately finish the payment. */
		if (!amount_msat_greater_eq(payment->total_delivering,
					    payment->payment_info.amount)) {
			plugin_log(
			    pay_plugin->plugin, LOG_UNUSUAL,
			    "%s: received a success sendpay for this "
			    "payment but the total delivering amount %s "
			    "is less than the payment amount %s.",
			    __func__,
			    fmt_amount_msat(tmpctx, payment->total_delivering),
			    fmt_amount_msat(tmpctx,
					    payment->payment_info.amount));
		}
		return payment_success(payment, take(payment_preimage));
	}
	if (final_msg) {
		/* We received a sendpay result with a final error message, we
		 * inmediately finish the payment. */
		return payment_fail(payment, final_error, "%s", final_msg);
	}

	if (amount_msat_greater_eq(payment->total_delivering,
				   payment->payment_info.amount)) {
		/* There are no succeeds but we are still pending delivering the
		 * entire payment. We still need to collect more results. */
		payment->have_results = false;
		payment->retry = false;
	} else {
		/* We have some failures so that now we are short of
		 * total_delivering, we may retry. */
		payment->have_results = true;

		// FIXME: we seem to always retry here if we don't fail
		// inmediately. But I am going to leave this variable here,
		// cause we might decide in the future to put some conditions on
		// retries, like a maximum number of retries.
		payment->retry = true;
	}

	return payment_continue(payment);
}

REGISTER_PAYMENT_MODIFIER(collect_results, collect_results_cb);

/*****************************************************************************
 * end
 *
 * The default ending of a payment.
 */
static struct command_result *end_done(struct command *cmd UNUSED,
				       const char *buf UNUSED,
				       const jsmntok_t *result UNUSED,
				       struct payment *payment)
{
	return payment_fail(payment, PAY_STOPPED_RETRYING,
			    "Payment execution ended without success.");
}
static struct command_result *end_cb(struct payment *payment)
{
	struct command *cmd = payment_command(payment);
	assert(cmd);
	struct out_req *req =
	    jsonrpc_request_start(cmd->plugin, cmd, "waitblockheight", end_done,
				  payment_rpc_failure, payment);
	json_add_num(req->js, "blockheight", 0);
	return send_outreq(cmd->plugin, req);
}

REGISTER_PAYMENT_MODIFIER(end, end_cb);

/*****************************************************************************
 * checktimeout
 *
 * Fail the payment if we have exceeded the timeout.
 */

static struct command_result *checktimeout_cb(struct payment *payment)
{
	if (time_after(time_now(), payment->payment_info.stop_time)) {
		return payment_fail(payment, PAY_STOPPED_RETRYING, "Timed out");
	}
	return payment_continue(payment);
}

REGISTER_PAYMENT_MODIFIER(checktimeout, checktimeout_cb);

/*****************************************************************************
 * pendingsendpays
 *
 * Obtain a list of sendpays, add up the amount of those pending and decide
 * which groupid and partid we should use next. If there is a "complete" sendpay
 * we should return payment_success inmediately.
 */

static struct command_result *pendingsendpays_done(struct command *cmd,
						   const char *buf,
						   const jsmntok_t *result,
						   struct payment *payment)
{
	size_t i;
	const char *err;
	const jsmntok_t *t, *arr;
	u32 max_group_id = 0;

	/* Data for pending payments, this will be the one
	 * who's result gets replayed if we end up suspending. */
	u32 pending_group_id = INVALID_ID;
	u32 max_pending_partid = 0;
	struct amount_msat pending_sent = AMOUNT_MSAT(0),
			   pending_msat = AMOUNT_MSAT(0);

	arr = json_get_member(buf, result, "payments");
	if (!arr || arr->type != JSMN_ARRAY) {
		return payment_fail(
		    payment, LIGHTNINGD,
		    "Unexpected non-array result from listsendpays: %.*s",
		    json_tok_full_len(result), json_tok_full(buf, result));
	}

	struct success_data success;
	if (success_data_from_listsendpays(buf, arr, &success)) {
		/* Have success data, hence the payment is complete, we stop. */
		payment->payment_info.start_time.ts.tv_sec = success.created_at;
		payment->payment_info.start_time.ts.tv_nsec = 0;
		payment->total_delivering = success.deliver_msat;
		payment->total_sent = success.sent_msat;
		payment->next_partid = success.parts + 1;
		payment->groupid = success.groupid;

		payment_note(payment, LOG_DBG,
			     "%s: Payment completed before computing the next "
			     "round of routes.",
			     __func__);
		return payment_success(payment, &success.preimage);
	}

	// find if there is one pending group
	json_for_each_arr(i, t, arr)
	{
		u32 groupid;
		const char *status;

		err = json_scan(tmpctx, buf, t,
				"{status:%"
				",groupid:%}",
				JSON_SCAN_TAL(tmpctx, json_strdup, &status),
				JSON_SCAN(json_to_u32, &groupid));

		if (err)
			plugin_err(pay_plugin->plugin,
				   "%s json_scan of listsendpay returns the "
				   "following error: %s",
				   __func__, err);

		if (streq(status, "pending")) {
			pending_group_id = groupid;
			break;
		}
	}

	/* We need two loops to get the highest partid for a groupid that has
	 * pending sendpays. */
	json_for_each_arr(i, t, arr)
	{
		u32 partid = 0, groupid;
		struct amount_msat this_msat, this_sent;
		const char *status;

		// FIXME we assume amount_msat is always present, but according
		// to the documentation this field is optional. How do I
		// interpret if amount_msat is missing?
		err = json_scan(tmpctx, buf, t,
				"{status:%"
				",partid?:%"
				",groupid:%"
				",amount_msat:%"
				",amount_sent_msat:%}",
				JSON_SCAN_TAL(tmpctx, json_strdup, &status),
				JSON_SCAN(json_to_u32, &partid),
				JSON_SCAN(json_to_u32, &groupid),
				JSON_SCAN(json_to_msat, &this_msat),
				JSON_SCAN(json_to_msat, &this_sent));

		if (err)
			plugin_err(pay_plugin->plugin,
				   "%s json_scan of listsendpay returns the "
				   "following error: %s",
				   __func__, err);

		/* If we decide to create a new group, we base it on
		 * max_group_id */
		if (groupid > max_group_id)
			max_group_id = groupid;

		if (groupid == pending_group_id && partid > max_pending_partid)
			max_pending_partid = partid;

		/* status could be completed, pending or failed */
		if (streq(status, "pending")) {
			/* If we have more than one pending group, something
			 * went wrong! */
			if (groupid != pending_group_id)
				return payment_fail(
				    payment, PAY_STATUS_UNEXPECTED,
				    "Multiple pending groups for this "
				    "payment.");

			if (!amount_msat_add(&pending_msat, pending_msat,
					     this_msat) ||
			    !amount_msat_add(&pending_sent, pending_sent,
					     this_sent))
				plugin_err(pay_plugin->plugin,
					   "%s (line %d) amount_msat overflow.",
					   __func__, __LINE__);
		}
		assert(!streq(status, "complete"));
	}

	if (pending_group_id != INVALID_ID) {
		/* Continue where we left off? */
		payment->groupid = pending_group_id;
		payment->next_partid = max_pending_partid + 1;
		payment->total_sent = pending_sent;
		payment->total_delivering = pending_msat;

		plugin_log(pay_plugin->plugin, LOG_DBG,
			   "There are pending sendpays to this invoice. "
			   "groupid = %" PRIu32 " "
			   "delivering = %s, "
			   "last_partid = %" PRIu32,
			   pending_group_id,
			   fmt_amount_msat(tmpctx, payment->total_delivering),
			   max_pending_partid);
	} else {
		/* There are no pending nor completed sendpays, get me the last
		 * sendpay group. */
		payment->groupid = max_group_id + 1;
		payment->next_partid = 1;
		payment->total_sent = AMOUNT_MSAT(0);
		payment->total_delivering = AMOUNT_MSAT(0);
	}

	return payment_continue(payment);
}

static struct command_result *pendingsendpays_cb(struct payment *payment)
{
	struct command *cmd = payment_command(payment);
	assert(cmd);

	struct out_req *req = jsonrpc_request_start(
	    cmd->plugin, cmd, "listsendpays", pendingsendpays_done,
	    payment_rpc_failure, payment);

	json_add_sha256(req->js, "payment_hash",
			&payment->payment_info.payment_hash);
	return send_outreq(cmd->plugin, req);
}

REGISTER_PAYMENT_MODIFIER(pendingsendpays, pendingsendpays_cb);

/*****************************************************************************
 * knowledgerelax
 *
 * Reduce the knowledge of the network as time goes by.
 */

static struct command_result *askreneage_success(struct command *cmd UNUSED,
						 const char *buf UNUSED,
						 const jsmntok_t *result UNUSED,
						 struct payment *payment)
{
	return payment_continue(payment);
}

/* FIXME: we lack an RPC call to request askrene to relax constraints by a
 * smooth amount, instead we will need to forget all knowledge that exceeds a
 * certain date. */
static struct command_result *knowledgerelax_cb(struct payment *payment)
{
	/* Remove all knowledge older than TIMER_FORGET_SEC (number of seconds
	 * in the past). */
	const u64 cutoff = time_now().ts.tv_sec - TIMER_FORGET_SEC;
	struct command *cmd = payment_command(payment);
	assert(cmd);

	struct out_req *req = jsonrpc_request_start(
	    cmd->plugin, cmd, "askrene-age", askreneage_success,
	    payment_rpc_failure, payment);

	json_add_string(req->js, "layer", RENEPAY_LAYER);
	json_add_u64(req->js, "cutoff", cutoff);
	return send_outreq(cmd->plugin, req);
}

REGISTER_PAYMENT_MODIFIER(knowledgerelax, knowledgerelax_cb);

/*****************************************************************************
 * channelfilter
 *
 * Disable some channels. The possible motivations are:
 * - avoid the overhead of unproductive routes that go through channels with
 * very low max_htlc that would lead us to a payment partition with too
 * many HTCLs,
 * - avoid channels with very small capacity as well, for which the probability
 * of success is always small anyways,
 * - discard channels with very high base fee that would break our cost
 * estimation,
 * - avoid high latency tor nodes.
 * All combined should reduce the size of the network we explore hopefully
 * reducing the runtime of the MCF solver (FIXME: I should measure this
 * eventually).
 * FIXME: shall we set these threshold parameters as plugin options?
 */

struct channelfilter_batch {
	size_t num_requests;
	struct payment *payment;
};

static struct command_result *
one_channelfilter_done(struct command *cmd, const char *buf UNUSED,
		       const jsmntok_t *result UNUSED,
		       struct channelfilter_batch *batch)
{
	assert(batch->num_requests);
	assert(batch->payment);
	batch->num_requests--;

	if (!batch->num_requests)
		return payment_continue(batch->payment);

	return command_still_pending(cmd);
}

static struct command_result *
one_channelfilter_failed(struct command *cmd, const char *buf,
			 const jsmntok_t *result,
			 struct channelfilter_batch *batch)
{
	plugin_log(cmd->plugin, LOG_UNUSUAL, "failed to disable channel: %.*s",
		   json_tok_full_len(result), json_tok_full(buf, result));
	return one_channelfilter_done(cmd, buf, result, batch);
}

static struct command_result *channelfilter_cb(struct payment *payment)
{
	assert(payment);
	struct command *cmd = payment_command(payment);
	assert(cmd);
	assert(pay_plugin->gossmap);
	const double HTLC_MAX_FRACTION = 0.01; // 1%
	const struct amount_msat HTLC_MAX_STOP_MSAT =
	    AMOUNT_MSAT(1000000000); // 1M sats
	struct amount_msat htlc_max_threshold;

	if (!amount_msat_scale(&htlc_max_threshold,
			       payment->payment_info.amount, HTLC_MAX_FRACTION))
		plugin_err(cmd->plugin, "%s: error scaling amount_msat",
			   __func__);

	/* Don't exclude channels with htlc_max above HTLC_MAX_STOP_MSAT even if
	 * that represents a fraction of the payment smaller than
	 * HTLC_MAX_FRACTION. */
	htlc_max_threshold =
	    amount_msat_min(htlc_max_threshold, HTLC_MAX_STOP_MSAT);

	struct channelfilter_batch *batch =
	    tal(cmd, struct channelfilter_batch);
	assert(batch);
	batch->num_requests = 0;
	batch->payment = payment;

	for (const struct gossmap_node *node =
		 gossmap_first_node(pay_plugin->gossmap);
	     node; node = gossmap_next_node(pay_plugin->gossmap, node)) {
		for (size_t i = 0; i < node->num_chans; i++) {
			int dir;
			const struct gossmap_chan *chan = gossmap_nth_chan(
			    pay_plugin->gossmap, node, i, &dir);
			if (amount_msat_greater_fp16(
				htlc_max_threshold, chan->half[dir].htlc_max)) {
				struct short_channel_id_dir scidd = {
				    .scid = gossmap_chan_scid(
					pay_plugin->gossmap, chan),
				    .dir = dir};

				/* FIXME: there is no askrene-disable-channel,
				 * we will fake its disabling by setting its
				 * liquidity to 0  */
				struct out_req *req = jsonrpc_request_start(
				    cmd->plugin, cmd, "askrene-inform-channel",
				    one_channelfilter_done,
				    one_channelfilter_failed, batch);

				/* This constraint only applies to this payment
				 */
				json_add_string(req->js, "layer",
						payment->private_layer);
				json_add_short_channel_id(
				    req->js, "short_channel_id", scidd.scid);
				json_add_num(req->js, "direction", scidd.dir);
				json_add_amount_msat(req->js, "maximum_msat",
						     AMOUNT_MSAT(0));
				send_outreq(cmd->plugin, req);

				batch->num_requests++;
			}
		}
	}

	// FIXME: prune the network over other parameters, eg. capacity,
	// fees, ...
	plugin_log(pay_plugin->plugin, LOG_DBG,
		   "channelfilter: disabling %" PRIu64 " channels.",
		   batch->num_requests);
	return payment_continue(payment);
}

REGISTER_PAYMENT_MODIFIER(channelfilter, channelfilter_cb);

/*****************************************************************************
 * alwaystrue
 *
 * A funny payment condition that always returns true.
 */
static bool alwaystrue_cb(const struct payment *payment) { return true; }

REGISTER_PAYMENT_CONDITION(alwaystrue, alwaystrue_cb);

/*****************************************************************************
 * nothaveresults
 *
 * A payment condition that returns true if the payment has not yet
 * collected enough results to decide whether the payment has succeed,
 * failed or need retrying.
 */
static bool nothaveresults_cb(const struct payment *payment)
{
	return !payment->have_results;
}

REGISTER_PAYMENT_CONDITION(nothaveresults, nothaveresults_cb);

/*****************************************************************************
 * retry
 *
 * A payment condition that returns true if we should retry the payment.
 */
static bool retry_cb(const struct payment *payment) { return payment->retry; }

REGISTER_PAYMENT_CONDITION(retry, retry_cb);

/*****************************************************************************
 * Virtual machine
 *
 * The plugin API is based on function calls. This makes is difficult to
 * summarize all payment steps into one function, because the workflow
 * is distributed across multiple functions. The default pay plugin
 * implements a "state machine" for each payment attempt/part and that
 * improves a lot the code readability and modularity. Based on that
 * idea renepay has its own state machine for the whole payment. We go
 * one step further by adding not just function calls (or payment
 * modifiers with OP_CALL) but also conditions with OP_IF that allows
 * for instance to have loops. Renepay's "program" is nicely summarized
 * in the following set of instructions:
 */
// TODO
// add shadow route
// add check pre-approved invoice
void *payment_virtual_program[] = {
    /*0*/ OP_CALL, &previoussuccess_pay_mod,
    /*2*/ OP_CALL, &selfpay_pay_mod,
    /*4*/ OP_CALL, &knowledgerelax_pay_mod,
    /*6*/ OP_CALL, &refreshgossmap_pay_mod,
    /*8*/ OP_CALL, &routehints_pay_mod,
    /*10*/OP_CALL, &channelfilter_pay_mod,
    // TODO shadow_additions
    /* do */
	    /*12*/ OP_CALL, &pendingsendpays_pay_mod,
	    /*14*/ OP_CALL, &checktimeout_pay_mod,
	    /*16*/ OP_CALL, &compute_routes_pay_mod,
	    /*18*/ OP_CALL, &send_routes_pay_mod,
	    /*do*/
		    /*20*/ OP_CALL, &sleep_pay_mod,
		    /*22*/ OP_CALL, &collect_results_pay_mod,
	    /*while*/
	    /*24*/ OP_IF, &nothaveresults_pay_cond, (void *)20,
    /* while */
    /*27*/ OP_IF, &retry_pay_cond, (void *)12,
    /*30*/ OP_CALL, &end_pay_mod, /* safety net, default failure if reached */
    /*32*/ NULL};
