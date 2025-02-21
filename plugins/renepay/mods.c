#include "config.h"
#include <ccan/asort/asort.h>
#include <ccan/bitmap/bitmap.h>
#include <common/amount.h>
#include <common/bolt11.h>
#include <common/gossmods_listpeerchannels.h>
#include <common/json_stream.h>
#include <common/memleak.h>
#include <plugins/renepay/json.h>
#include <plugins/renepay/mods.h>
#include <plugins/renepay/renepay.h>
#include <plugins/renepay/renepayconfig.h>
#include <plugins/renepay/route.h>
#include <plugins/renepay/routetracker.h>
#include <plugins/renepay/utils.h>
#include <unistd.h>
#include <wire/bolt12_wiregen.h>

#define MAX(x, y) (((x) > (y)) ? (x) : (y))
#define MIN(x, y) (((x) < (y)) ? (x) : (y))
#define MAX_CAPACITY (AMOUNT_MSAT(21000000 * MSAT_PER_BTC))

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
		plugin_err(payment->plugin,
			   "payment_continue reached the end of the virtual "
			   "machine execution.");
	} else if (op == OP_CALL) {
		const struct payment_modifier *mod =
		    (const struct payment_modifier *)
			payment_virtual_program[payment->exec_state++];

		if (mod == NULL)
			plugin_err(payment->plugin,
				   "payment_continue expected payment_modifier "
				   "but NULL found");

		plugin_log(payment->plugin, LOG_DBG, "Calling modifier %s",
			   mod->name);
		return mod->step_cb(payment);
	} else if (op == OP_IF) {
		const struct payment_condition *cond =
		    (const struct payment_condition *)
			payment_virtual_program[payment->exec_state++];

		if (cond == NULL)
			plugin_err(payment->plugin,
				   "payment_continue expected pointer to "
				   "condition but NULL found");

		plugin_log(payment->plugin, LOG_DBG,
			   "Calling payment condition %s", cond->name);

		const u64 position_iftrue =
			(intptr_t)payment_virtual_program[payment->exec_state++];

		if (cond->condition_cb(payment))
			payment->exec_state = position_iftrue;

		return payment_continue(payment);
	}
	plugin_err(payment->plugin, "payment_continue op code not defined");
	return NULL;
}


/* Generic handler for RPC failures that should end up failing the payment. */
static struct command_result *payment_rpc_failure(struct command *cmd,
						  const char *method UNUSED,
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

/* Use this function to log failures in batch requests. */
static struct command_result *log_payment_err(struct command *cmd,
					      const char *method,
					      const char *buf,
					      const jsmntok_t *tok,
					      struct payment *payment)
{
	plugin_log(cmd->plugin, LOG_UNUSUAL, "%s failed: '%.*s'", method,
		   json_tok_full_len(tok), json_tok_full(buf, tok));
	return command_still_pending(cmd);
}


/*****************************************************************************
 * previoussuccess
 *
 * Obtain a list of previous sendpay requests and check if
 * the current payment hash has already succeed.
 */

struct success_data {
	u64 parts, created_at, groupid;
	struct amount_msat deliver_msat, sent_msat;
	struct preimage preimage;
};

/* Extracts success data from listsendpays. */
static bool success_data_from_listsendpays(struct command *cmd, const char *buf,
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
		u64 groupid;
		struct amount_msat this_msat, this_sent;

		const jsmntok_t *status_tok = json_get_member(buf, t, "status");
		if (!status_tok)
			plugin_err(
			    cmd->plugin,
			    "%s (line %d) missing status token from json.",
			    __func__, __LINE__);
		const char *status = json_strdup(tmpctx, buf, status_tok);
		if (!status)
			plugin_err(
			    cmd->plugin,
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
			    JSON_SCAN(json_to_u64, &groupid),
			    JSON_SCAN(json_to_msat, &this_msat),
			    JSON_SCAN(json_to_msat, &this_sent),
			    JSON_SCAN(json_to_u64, &success->created_at),
			    JSON_SCAN(json_to_preimage, &success->preimage));

			if (err)
				plugin_err(cmd->plugin,
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
				plugin_err(cmd->plugin,
					   "%s (line %d) amount_msat overflow.",
					   __func__, __LINE__);

			success->parts++;
		}
	}

	return success->parts > 0;
}

static struct command_result *previoussuccess_done(struct command *cmd,
						   const char *method UNUSED,
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
	if (!success_data_from_listsendpays(cmd, buf, arr, &success)) {
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
	    cmd, "listsendpays", previoussuccess_done,
	    payment_rpc_failure, payment);

	json_add_sha256(req->js, "payment_hash",
			&payment->payment_info.payment_hash);
	json_add_string(req->js, "status", "complete");
	return send_outreq(req);
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
 * refreshgossmap
 *
 * Update the gossmap.
 */

static struct command_result *refreshgossmap_cb(struct payment *payment)
{
	assert(payment);
	struct renepay *renepay = get_renepay(payment->plugin);
	assert(renepay->gossmap); // gossmap must be already initialized
	gossmap_refresh(renepay->gossmap);
	return payment_continue(payment);
}

REGISTER_PAYMENT_MODIFIER(refreshgossmap, refreshgossmap_cb);

/*****************************************************************************
 * routehints
 *
 * Use route hints from the invoice to update the local gossmods and uncertainty
 * network.
 */

static struct command_result *hints_done(struct command *cmd,
					 struct payment *payment)
{
	return payment_continue(payment);
}


static void add_hintchan(struct command *cmd,
			 struct request_batch *batch,
			 struct payment *payment,
			 const struct node_id *src,
			 const struct node_id *dst,
			 u16 cltv_expiry_delta,
			 const struct short_channel_id scid,
			 u32 fee_base_msat,
			 u32 fee_proportional_millionths,
			 const struct amount_msat *chan_capacity,
			 const struct amount_msat *chan_htlc_min,
			 const struct amount_msat *chan_htlc_max)
{
	struct amount_msat htlc_min = AMOUNT_MSAT(0), htlc_max = MAX_CAPACITY,
			   capacity = MAX_CAPACITY;

	if (chan_capacity)
		capacity = *chan_capacity;
	if (chan_htlc_min)
		htlc_min = *chan_htlc_min;
	if (chan_htlc_max)
		htlc_max = *chan_htlc_max;
	htlc_max = amount_msat_min(htlc_max, capacity);
	htlc_min = amount_msat_min(htlc_min, htlc_max);

	assert(payment);
	struct out_req *req;
	struct short_channel_id_dir scidd = {.scid = scid,
					     .dir = node_id_idx(src, dst)};

	req = add_to_batch(cmd, batch, "askrene-create-channel");
	json_add_string(req->js, "layer", payment->payment_layer);
	json_add_node_id(req->js, "source", src);
	json_add_node_id(req->js, "destination", dst);
	json_add_short_channel_id(req->js, "short_channel_id", scidd.scid);
	json_add_amount_msat(req->js, "capacity_msat", capacity);
	send_outreq(req);

	req = add_to_batch(cmd, batch, "askrene-update-channel");
	json_add_string(req->js, "layer", payment->payment_layer);
	json_add_short_channel_id_dir(req->js, "short_channel_id_dir", scidd);
	json_add_bool(req->js, "enabled", true);
	json_add_amount_msat(req->js, "htlc_minimum_msat", htlc_min);
	json_add_amount_msat(req->js, "htlc_maximum_msat", htlc_max);
	json_add_u32(req->js, "fee_base_msat", fee_base_msat);
	json_add_u32(req->js, "fee_proportional_millionths",
		     fee_proportional_millionths);
	json_add_u32(req->js, "cltv_expiry_delta", cltv_expiry_delta);
	send_outreq(req);
}

static struct command_result *routehints_cb(struct payment *payment)
{
	assert(payment);
	struct command *cmd = payment_command(payment);
	const struct node_id *destination = &payment->payment_info.destination;
	struct route_info **routehints = payment->payment_info.routehints;
	if (!routehints)
		return payment_continue(payment);
	const size_t nhints = tal_count(routehints);
	struct request_batch *batch =
	    request_batch_new(cmd, NULL, log_payment_err, hints_done, payment);
	/* Hints are added to the local_gossmods. */
	for (size_t i = 0; i < nhints; i++) {
		/* Each one, presumably, leads to the destination */
		const struct route_info *r = routehints[i];
		const struct node_id *end = destination;

		for (int j = tal_count(r) - 1; j >= 0; j--) {
			add_hintchan(cmd, batch, payment, &r[j].pubkey, end,
				     r[j].cltv_expiry_delta,
				     r[j].short_channel_id, r[j].fee_base_msat,
				     r[j].fee_proportional_millionths,
				     NULL, NULL, NULL);
			end = &r[j].pubkey;
		}
	}
	return batch_done(cmd, batch);
}

REGISTER_PAYMENT_MODIFIER(routehints, routehints_cb);


/*****************************************************************************
 * blindedhints
 *
 * Similar to routehints but for bolt12 invoices: create fake channel that
 * connect the blinded path entry point to the destination node.
 */

static struct command_result *blindedhints_cb(struct payment *payment)
{
	struct command *cmd = payment_command(payment);
	struct payment_info *pinfo = &payment->payment_info;
	struct request_batch *batch =
	    request_batch_new(cmd, NULL, log_payment_err, hints_done, payment);

	if (payment->payment_info.blinded_paths == NULL){
		/* a BOLT11 invoice, we add only one fake channel */
		struct amount_msat htlc_min = AMOUNT_MSAT(0);
		struct amount_msat htlc_max = AMOUNT_MSAT((u64)1000*100000000);
		struct short_channel_id scid = {.u64 = 0};
		add_hintchan(cmd, batch, payment, &pinfo->destination,
			     payment->routing_destination,
			     /* cltv delta = */ 0, scid,
			     /* base fee = */ 0,
			     /* ppm = */ 0,
			     /* capacity = ? */ NULL,
			     &htlc_min, &htlc_max);
	} else {
		struct short_channel_id scid;
		struct node_id src;
		for (size_t i = 0; i < tal_count(pinfo->blinded_paths); i++) {
			const struct blinded_payinfo *payinfo =
			    pinfo->blinded_payinfos[i];
			const struct blinded_path *path =
			    pinfo->blinded_paths[i];

			scid.u64 = i; // a fake scid
			node_id_from_pubkey(&src, &path->first_node_id.pubkey);

			add_hintchan(cmd, batch, payment, &src,
				     payment->routing_destination,
				     payinfo->cltv_expiry_delta, scid,
				     payinfo->fee_base_msat,
				     payinfo->fee_proportional_millionths,
				     NULL,
				     &payinfo->htlc_minimum_msat,
				     &payinfo->htlc_maximum_msat);
		}
	}
	return batch_done(cmd, batch);
}

REGISTER_PAYMENT_MODIFIER(blindedhints, blindedhints_cb);


/*****************************************************************************
 * getroutes
 *
 * Call askrene-getroutes
 */

/* The last hop is an artifact for handling self-payments and blinded paths. */
static void prune_last_hop(struct route *route)
{
	const size_t pathlen = tal_count(route->hops);
	assert(pathlen > 0);
	route->path_num = route->hops[pathlen - 1].scid.u64;
	tal_arr_remove(&route->hops, pathlen - 1);
}

static struct command_result *getroutes_done(struct command *cmd,
					     const char *method,
					     const char *buf,
					     const jsmntok_t *tok,
					     struct payment *payment)
{
	struct routetracker *routetracker = payment->routetracker;
	assert(routetracker);

	if (tal_count(routetracker->computed_routes) > 0)
		plugin_err(cmd->plugin,
			   "%s: no previously computed routes expected.",
			   __func__);

	routetracker->computed_routes = tal_free(routetracker->computed_routes);
	const jsmntok_t *routestok = json_get_member(buf, tok, "routes");
	assert(routestok && routestok->type == JSMN_ARRAY);
	routetracker->computed_routes =
	    tal_arr(routetracker, struct route *, 0);

	size_t i;
	const jsmntok_t *r;
	json_for_each_arr(i, r, routestok)
	{
		struct route *route = new_route(
		    routetracker->computed_routes, payment->groupid,
		    payment->next_partid++, payment->payment_info.payment_hash,
		    AMOUNT_MSAT(0), AMOUNT_MSAT(0));
		tal_arr_expand(&routetracker->computed_routes, route);
		bool success = json_to_myroute(buf, r, route);
		if (!success) {
			plugin_err(
			    cmd->plugin,
			    "%s: failed to parse route from getroutes, %.*s",
			    __func__, json_tok_full_len(r),
			    json_tok_full(buf, r));
		}
		prune_last_hop(route);
		assert(success);
	}
	return payment_continue(payment);
}

static struct command_result *getroutes_fail(struct command *cmd,
					     const char *method,
					     const char *buf,
					     const jsmntok_t *tok,
					     struct payment *payment)
{
	// FIXME: read the response
	// if can we do something about his failure:
	// 	disable channels or add biases
	// 	return payment_continue(payment);
	// else:
	// 	return payment_fail(payment, PAY_STOPPED_RETRYING, "getroutes
	// 	failed to find a feasible solution %s", explain_error(buf,
	// tok));
	const jsmntok_t *messtok = json_get_member(buf, tok, "message");
	assert(messtok);
	return payment_fail(
	    payment, PAYMENT_PENDING,
	    "getroutes failed to find a feasible solution: %.*s",
	    json_tok_full_len(messtok), json_tok_full(buf, messtok));
}

static struct command_result *getroutes_cb(struct payment *payment)
{
	struct renepay *renepay = get_renepay(payment->plugin);
	assert(payment->status == PAYMENT_PENDING);
	struct amount_msat feebudget, fees_spent, remaining;

	/* Total feebudget  */
	if (!amount_msat_sub(&feebudget, payment->payment_info.maxspend,
			     payment->payment_info.amount))
		plugin_err(payment->plugin, "%s: fee budget is negative?",
			   __func__);

	/* Fees spent so far */
	if (!amount_msat_sub(&fees_spent, payment->total_sent,
			     payment->total_delivering))
		plugin_err(payment->plugin,
			   "%s: total_delivering is greater than total_sent?",
			   __func__);

	/* Remaining fee budget. */
	if (!amount_msat_sub(&feebudget, feebudget, fees_spent))
		feebudget = AMOUNT_MSAT(0);

	/* How much are we still trying to send? */
	if (!amount_msat_sub(&remaining, payment->payment_info.amount,
			     payment->total_delivering) ||
	    amount_msat_is_zero(remaining)) {
		plugin_log(payment->plugin, LOG_UNUSUAL,
			   "%s: Payment is pending with full amount already "
			   "committed. We skip the computation of new routes.",
			   __func__);
		return payment_continue(payment);
	}

	/* FIXME:
	 * call getroutes:
	 * 	input: source, destination, amount, maxfee, final_cltv,
	 * 	maxdelay, layers: [auto.localchans, auto.sourcefree,
	 * 	thispaymenthints, thispaymentexclude, renepayknowledge]
	 *
	 * possible outcomes:
	 * 	success: then continue
	 * 	fail with hint: try to fix and retry or fail payment
	 * */
	struct command *cmd = payment_command(payment);
	struct out_req *req = jsonrpc_request_start(
	    cmd, "getroutes", getroutes_done, getroutes_fail, payment);

	// FIXME: add an algorithm selection in askrene such that we could
	// retrieve a single path route if necessary, see issue 8042
	// FIXME: register layers before using then:
	// 	-> register RENEPAY_LAYER on plugin startup
	// 	-> register payment->payment_layer when payment is created
	// 	-> payment_layer should auto clean
	// 	-> register payment->command_layer when the payment execution
	// 	starts
	// 	-> command_layer should auto clean

	json_add_node_id(req->js, "source", &renepay->my_id);
	json_add_node_id(req->js, "destination", payment->routing_destination);
	json_add_amount_msat(req->js, "amount_msat", remaining);
	json_add_amount_msat(req->js, "maxfee_msat", feebudget);
	json_add_u32(req->js, "final_cltv", payment->payment_info.final_cltv);
	json_array_start(req->js, "layers");
	json_add_string(req->js, NULL, "auto.localchans");
	json_add_string(req->js, NULL, "auto.sourcefree");
	json_add_string(req->js, NULL, payment->payment_layer);
	json_add_string(req->js, NULL, RENEPAY_LAYER);
	json_array_end(req->js);
	// FIXME: add further constraints here if necessary when they become
	// available in getroutes
	// eg. json_add_u32(req->js, "maxdelay", payment->payment_info.maxdelay);
	return send_outreq(req);
}

REGISTER_PAYMENT_MODIFIER(getroutes, getroutes_cb);

/*****************************************************************************
 * send_routes
 *
 * This payment modifier takes the payment routes and starts the payment
 * request calling sendpay.
 */

static struct command_result *sendroutes_done(struct command *cmd,
					      struct payment *payment)
{
	return payment_continue(payment);
}

/* Callback function for sendpay request success. */
static struct command_result *
renesendpay_done(struct command *cmd, const char *method UNUSED,
		 const char *buf, const jsmntok_t *result, struct route *route)
{
	assert(route);
	struct renepay *renepay = get_renepay(cmd->plugin);
	struct payment *payment = route_get_payment_verify(renepay, route);
	route_pending_register(payment, payment->routetracker, route);

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

/* FIXME: check when will renesendpay fail */
static struct command_result *
renesendpay_fail(struct command *cmd, const char *method UNUSED,
		 const char *buf, const jsmntok_t *tok, struct route *route)
{
	assert(route);
	struct renepay *renepay = get_renepay(cmd->plugin);
	struct payment *payment = route_get_payment_verify(renepay, route);
	struct routetracker *routetracker = payment->routetracker;
	assert(routetracker);

	enum jsonrpc_errcode errcode;
	const char *msg;
	const char *err;

	err = json_scan(tmpctx, buf, tok, "{code:%,message:%}",
			JSON_SCAN(json_to_jsonrpc_errcode, &errcode),
			JSON_SCAN_TAL(tmpctx, json_strdup, &msg));
	if (err)
		plugin_err(cmd->plugin,
			   "Unable to parse sendpay error: %s, json: %.*s", err,
			   json_tok_full_len(tok), json_tok_full(buf, tok));

	payment_note(payment, LOG_INFORM,
		     "Sendpay failed: partid=%" PRIu64
		     " errorcode:%d message=%s",
		     route->key.partid, errcode, msg);

	if (errcode != PAY_TRY_OTHER_ROUTE) {
		plugin_log(cmd->plugin, LOG_UNUSUAL,
			   "Strange error from sendpay: %.*s",
			   json_tok_full_len(tok), json_tok_full(buf, tok));
	}

	/* There is no new knowledge from this kind of failure.
	 * We just disable this scid. */
	// FIXME: askrene disable this channel
	struct short_channel_id_dir scidd_disable = {
	    .scid = route->hops[0].scid, .dir = route->hops[0].direction};
	payment_disable_chan(payment, scidd_disable, LOG_INFORM,
			     "sendpay didn't like first hop: %s", msg);

	if (!route_map_del(routetracker->sent_routes, route))
		plugin_err(cmd->plugin, "%s: route (%s) is not marked as sent",
			   __func__, fmt_routekey(tmpctx, &route->key));
	tal_free(route);
	return command_still_pending(cmd);
}

static void add_sendpay_request(struct rpcbatch *batch, struct route *route,
				struct payment *payment)
{
	struct payment_info *pinfo = &payment->payment_info;
	struct out_req *req = add_to_rpcbatch(
	    batch, "renesendpay", renesendpay_done, renesendpay_fail, route);
	const size_t pathlen = tal_count(route->hops);
	json_add_sha256(req->js, "payment_hash", &route->key.payment_hash);
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
		json_add_secret(req->js, "payment_secret",
				pinfo->payment_secret);
	else {
		assert(pinfo->blinded_paths);
		const struct blinded_path *bpath =
		    pinfo->blinded_paths[route->path_num];
		json_myadd_blinded_path(req->js, "blinded_path", bpath);
	}
	send_outreq(req);
	route_map_add(payment->routetracker->sent_routes, route);
	if (taken(route))
		tal_steal(payment->routetracker->sent_routes, route);
}

static struct command_result *send_routes_cb(struct payment *payment)
{
	assert(payment);
	struct routetracker *routetracker = payment->routetracker;
	assert(routetracker);
	if (!routetracker->computed_routes ||
	    tal_count(routetracker->computed_routes) == 0) {
		plugin_log(payment->plugin, LOG_UNUSUAL,
			   "%s: there are no routes to send, skipping.",
			   __func__);
		return payment_continue(payment);
	}
	struct command *cmd = payment_command(payment);
	assert(cmd);
	struct rpcbatch *batch = rpcbatch_new(cmd, sendroutes_done, payment);

	for (size_t i = 0; i < tal_count(routetracker->computed_routes); i++) {
		struct route *route = routetracker->computed_routes[i];
		add_sendpay_request(batch, take(route), payment);
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
	return rpcbatch_done(batch);
}

REGISTER_PAYMENT_MODIFIER(send_routes, send_routes_cb);

/*****************************************************************************
 * sleep
 *
 * The payment main thread sleeps for some time.
 */

static struct command_result *sleep_done(struct command *cmd, struct payment *payment)
{
	struct command_result *ret;
	payment->waitresult_timer = NULL;
	ret = timer_complete(cmd);
	payment_continue(payment);
	return ret;
}

static struct command_result *sleep_cb(struct payment *payment)
{
	struct command *cmd = payment_command(payment);
	assert(cmd);
	assert(payment->waitresult_timer == NULL);
	payment->waitresult_timer
		= command_timer(cmd,
				time_from_msec(COLLECTOR_TIME_WINDOW_MSEC),
				sleep_done, payment);
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
			    payment->plugin, LOG_UNUSUAL,
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
static struct command_result *end_cb(struct payment *payment)
{
	return payment_fail(payment, PAY_STOPPED_RETRYING,
			    "Payment execution ended without success.");
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

static int cmp_u64(const u64 *a, const u64 *b, void *unused)
{
	if (*a < *b)
		return -1;
	if (*a > *b)
		return 1;
	return 0;
}

static struct command_result *pendingsendpays_done(struct command *cmd,
						   const char *method UNUSED,
						   const char *buf,
						   const jsmntok_t *result,
						   struct payment *payment)
{
	size_t i;
	const char *err;
	const jsmntok_t *t, *arr;

	/* Data for pending payments, this will be the one
	 * who's result gets replayed if we end up suspending. */
	bool has_pending = false;
	u64 unused_groupid;
	u64 pending_group_id COMPILER_WANTS_INIT("12.3.0-17ubuntu1 -O3");
	u64 max_pending_partid = 0;
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
	if (success_data_from_listsendpays(cmd, buf, arr, &success)) {
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

	u64 *groupid_arr = tal_arr(tmpctx, u64, 0);

	// find if there is one pending group
	json_for_each_arr(i, t, arr)
	{
		u64 groupid;
		const char *status;

		err = json_scan(tmpctx, buf, t,
				"{status:%"
				",groupid:%}",
				JSON_SCAN_TAL(tmpctx, json_strdup, &status),
				JSON_SCAN(json_to_u64, &groupid));

		if (err)
			plugin_err(cmd->plugin,
				   "%s json_scan of listsendpay returns the "
				   "following error: %s",
				   __func__, err);

		if (streq(status, "pending")) {
			has_pending = true;
			pending_group_id = groupid;
		}
		tal_arr_expand(&groupid_arr, groupid);
	}
	assert(tal_count(groupid_arr) == arr->size);

	/* We need two loops to get the highest partid for a groupid that has
	 * pending sendpays. */
	json_for_each_arr(i, t, arr)
	{
		u64 partid = 0, groupid;
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
				JSON_SCAN(json_to_u64, &partid),
				JSON_SCAN(json_to_u64, &groupid),
				JSON_SCAN(json_to_msat, &this_msat),
				JSON_SCAN(json_to_msat, &this_sent));

		if (err)
			plugin_err(cmd->plugin,
				   "%s json_scan of listsendpay returns the "
				   "following error: %s",
				   __func__, err);

		if (has_pending && groupid == pending_group_id &&
		    partid > max_pending_partid)
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
				plugin_err(cmd->plugin,
					   "%s (line %d) amount_msat overflow.",
					   __func__, __LINE__);
		}
		assert(!streq(status, "complete"));
	}

	/* find the first unused groupid */
	unused_groupid = 1;
	asort(groupid_arr, tal_count(groupid_arr), cmp_u64, NULL);
	for (i = 0; i < tal_count(groupid_arr); i++) {
		if (unused_groupid < groupid_arr[i])
			break;
		if (unused_groupid == groupid_arr[i])
			unused_groupid++;
	}

	if (has_pending) {
		/* Continue where we left off? */
		payment->groupid = pending_group_id;
		payment->next_partid = max_pending_partid + 1;
		payment->total_sent = pending_sent;
		payment->total_delivering = pending_msat;

		plugin_log(cmd->plugin, LOG_DBG,
			   "There are pending sendpays to this invoice. "
			   "groupid = %" PRIu64 " "
			   "delivering = %s, "
			   "last_partid = %" PRIu64,
			   pending_group_id,
			   fmt_amount_msat(tmpctx, payment->total_delivering),
			   max_pending_partid);
	} else {
		/* There are no pending nor completed sendpays, get me the last
		 * sendpay group. */
		payment->groupid = unused_groupid;
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
	    cmd, "listsendpays", pendingsendpays_done,
	    payment_rpc_failure, payment);

	json_add_sha256(req->js, "payment_hash",
			&payment->payment_info.payment_hash);
	return send_outreq(req);
}

REGISTER_PAYMENT_MODIFIER(pendingsendpays, pendingsendpays_cb);

/*****************************************************************************
 * knowledgerelax
 *
 * Reduce the knowledge of the network as time goes by.
 */

static struct command_result *age_done(struct command *cmd,
				       const char *method UNUSED,
				       const char *buf UNUSED,
				       const jsmntok_t *result UNUSED,
				       struct payment *payment)
{
	return payment_continue(payment);
}

static struct command_result *knowledgerelax_cb(struct payment *payment)
{
	struct renepay *renepay = get_renepay(payment->plugin);
	const u64 now_sec = time_now().ts.tv_sec;
	// const u64 time_delta = now_sec - renepay->last_time;
	renepay->last_time = now_sec;
	/* FIXME: implement a Markovian state relaxation, the time delta is all
	 * we need to provide. */
	struct command *cmd = payment_command(payment);
	assert(cmd);
	struct out_req *req = jsonrpc_request_start(
	    cmd, "askrene-age", age_done, payment_rpc_failure, payment);
	json_add_string(req->js, "layer", RENEPAY_LAYER);
	json_add_u64(req->js, "cutoff", now_sec - TIMER_FORGET_SEC);
	return send_outreq(req);
}

REGISTER_PAYMENT_MODIFIER(knowledgerelax, knowledgerelax_cb);

/*****************************************************************************
 * initpaymentlayer
 *
 * Initialize a layer in askrene to handle private information regarding this
 * payment.
 */

static struct command_result *createlayer_done(struct command *cmd UNUSED,
					       const char *method UNUSED,
					       const char *buf UNUSED,
					       const jsmntok_t *tok UNUSED,
					       struct payment *payment)
{
	return payment_continue(payment);
}

static struct command_result *createlayer_fail(struct command *cmd,
					       const char *method UNUSED,
					       const char *buf,
					       const jsmntok_t *tok,
					       struct payment *payment)
{
	/* failure means layer already exists.
	 * FIXME: how do we prevent a layer from expiring before the payment
	 * finishes? */
	const jsmntok_t *messtok = json_get_member(buf, tok, "message");
	plugin_log(cmd->plugin, LOG_UNUSUAL,
		   "%s: create-layer failed with error: %.*s", __func__,
		   json_tok_full_len(messtok), json_tok_full(buf, messtok));
	return payment_continue(payment);
}

static struct command_result *remove_layer_done(struct command *cmd,
						const char *method UNUSED,
						const char *buf UNUSED,
						const jsmntok_t *tok UNUSED,
						struct payment *payment UNUSED)
{
	return timer_complete(cmd);
}
static struct command_result *remove_layer_fail(struct command *cmd,
						const char *method,
						const char *buf,
						const jsmntok_t *tok,
						struct payment *payment)
{
	plugin_log(cmd->plugin, LOG_UNUSUAL, "%s failed: '%.*s'", method,
		   json_tok_full_len(tok), json_tok_full(buf, tok));
	return remove_layer_done(cmd, method, buf, tok, payment);
}

static struct command_result *remove_payment_layer(struct command *cmd,
						   struct payment *payment)
{

	struct out_req *req = jsonrpc_request_start(cmd, "askrene-remove-layer",
						    remove_layer_done,
						    remove_layer_fail, payment);
	json_add_string(req->js, "layer", payment->payment_layer);
	plugin_log(cmd->plugin, LOG_DBG, "removing payment layer: %s",
		   payment->payment_layer);
	return send_outreq(req);
}

static struct command_result *initpaymentlayer_cb(struct payment *payment)
{
	struct command *cmd = payment_command(payment);
	assert(cmd);
	struct out_req *req = jsonrpc_request_start(cmd, "askrene-create-layer",
		createlayer_done, createlayer_fail, payment);
	json_add_string(req->js, "layer", payment->payment_layer);
	json_add_bool(req->js, "persistent", false);
	/* Remove this payment layer after one hour. If the plugin crashes
	 * unexpectedly, we might "leak" by forgetting to remove the layer, but
	 * the layer is not persistent anyways, therefore restarting CLN will
	 * remove it. */
	notleak(global_timer(cmd->plugin, time_from_sec(3600),
			     remove_payment_layer, payment));
	return send_outreq(req);
}

REGISTER_PAYMENT_MODIFIER(initpaymentlayer, initpaymentlayer_cb);

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

static struct command_result *channelfilter_done(struct command *cmd,
						 struct payment *payment)
{
	return payment_continue(payment);
}

static struct command_result *channelfilter_cb(struct payment *payment)
{
	assert(payment);
	struct renepay *renepay = get_renepay(payment->plugin);
	assert(renepay->gossmap);
	const double HTLC_MAX_FRACTION = 0.01; // 1%
	const u64 HTLC_MAX_STOP_MSAT = 1000000000; // 1M sats
	u64 disabled_count = 0;
	u64 htlc_max_threshold = HTLC_MAX_FRACTION * payment->payment_info
		.amount.millisatoshis; /* Raw: a fraction of this amount. */
	/* Don't exclude channels with htlc_max above HTLC_MAX_STOP_MSAT even if
	 * that represents a fraction of the payment smaller than
	 * HTLC_MAX_FRACTION. */
	htlc_max_threshold = MIN(htlc_max_threshold, HTLC_MAX_STOP_MSAT);

	struct command *cmd = payment_command(payment);
	struct request_batch *batch = request_batch_new(
	    cmd, NULL, log_payment_err, channelfilter_done, payment);
	struct out_req *req;

	for (const struct gossmap_node *node =
		 gossmap_first_node(renepay->gossmap);
	     node; node = gossmap_next_node(renepay->gossmap, node)) {
		for (size_t i = 0; i < node->num_chans; i++) {
			int dir;
			const struct gossmap_chan *chan = gossmap_nth_chan(
			    renepay->gossmap, node, i, &dir);
			const u64 htlc_max =
			    fp16_to_u64(chan->half[dir].htlc_max);
			if (htlc_max < htlc_max_threshold) {
				struct short_channel_id_dir scidd = {
				    .scid = gossmap_chan_scid(
					renepay->gossmap, chan),
				    .dir = dir};
				req = add_to_batch(cmd, batch,
						   "askrene-update-channel");
				json_add_string(req->js, "layer",
						payment->payment_layer);
				json_add_short_channel_id_dir(
				    req->js, "short_channel_id_dir", scidd);
				json_add_bool(req->js, "enabled", false);
				send_outreq(req);
				disabled_count++;
			}
		}
	}
	// FIXME: prune the network over other parameters, eg. capacity,
	// fees, ...
	plugin_log(payment->plugin, LOG_DBG,
		   "channelfilter: disabling %" PRIu64 " channels.",
		   disabled_count);
	return batch_done(cmd, batch);
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
    /*2*/ OP_CALL, &initpaymentlayer_pay_mod,
    /*4*/ OP_CALL, &knowledgerelax_pay_mod,
    /*6*/ OP_CALL, &refreshgossmap_pay_mod,
    /*8*/ OP_CALL, &routehints_pay_mod,
    /*10*/ OP_CALL, &blindedhints_pay_mod,
    /*12*/OP_CALL, &channelfilter_pay_mod,
    // TODO shadow_additions
    /* do */
	    /*14*/ OP_CALL, &pendingsendpays_pay_mod,
	    /*16*/ OP_CALL, &checktimeout_pay_mod,
	    /*18*/ OP_CALL, &refreshgossmap_pay_mod,
	    /*20*/ OP_CALL, &getroutes_pay_mod,
	    /*22*/ OP_CALL, &send_routes_pay_mod,
	    /*do*/
		    /*24*/ OP_CALL, &sleep_pay_mod,
		    /*26*/ OP_CALL, &collect_results_pay_mod,
	    /*while*/
	    /*28*/ OP_IF, &nothaveresults_pay_cond, (void *)24,
    /* while */
    /*31*/ OP_IF, &retry_pay_cond, (void *)14,
    /*34*/ OP_CALL, &end_pay_mod, /* safety net, default failure if reached */
    /*36*/ NULL};
