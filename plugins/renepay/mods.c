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
			    __PRETTY_FUNCTION__, __LINE__);
		const char *status = json_strdup(tmpctx, buf, status_tok);
		if (!status)
			plugin_err(
			    pay_plugin->plugin,
			    "%s (line %d) failed to allocate status string.",
			    __PRETTY_FUNCTION__, __LINE__);

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
					   __PRETTY_FUNCTION__, __LINE__, err);
			success->groupid = groupid;
			/* Now we know the payment completed. */
			if (!amount_msat_add(&success->deliver_msat,
					     success->deliver_msat,
					     this_msat) ||
			    !amount_msat_add(&success->sent_msat,
					     success->sent_msat, this_sent))
				plugin_err(pay_plugin->plugin,
					   "%s (line %d) amount_msat overflow.",
					   __PRETTY_FUNCTION__, __LINE__);

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
	assert(amount_msat_zero(payment->total_sent));
	assert(amount_msat_zero(payment->total_delivering));
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
 * getmychannels
 *
 * Calls listpeerchannels to get and updated state of the local channels.
 */

static void
uncertainty_update_from_listpeerchannels(struct uncertainty *uncertainty,
				      const struct short_channel_id_dir *scidd,
				      struct amount_msat max, bool enabled,
				      const char *buf, const jsmntok_t *chantok)
{
	if (!enabled)
		return;

	struct amount_msat capacity;
	const char *errmsg = json_scan(tmpctx, buf, chantok, "{total_msat:%}",
				       JSON_SCAN(json_to_msat, &capacity));
	if (errmsg)
		goto error;

	if (!uncertainty_add_channel(pay_plugin->uncertainty, scidd->scid,
				  capacity)) {
		errmsg = tal_fmt(
		    tmpctx,
		    "Unable to find/add scid=%s in the uncertainty network",
		    fmt_short_channel_id(tmpctx, scidd->scid));
		goto error;
	}
	// FIXME this does not include pending HTLC of ongoing payments!
	if (!uncertainty_set_liquidity(pay_plugin->uncertainty, scidd, max)) {
		errmsg = tal_fmt(
		    tmpctx,
		    "Unable to set liquidity to channel scidd=%s in the "
		    "uncertainty network.",
		    fmt_short_channel_id_dir(tmpctx, scidd));
		goto error;
	}
	return;

error:
	plugin_log(
	    pay_plugin->plugin, LOG_UNUSUAL,
	    "Failed to update local channel %s from listpeerchannels rpc: %s",
	    fmt_short_channel_id(tmpctx, scidd->scid),
	    errmsg);
}

static void gossmod_cb(struct gossmap_localmods *mods,
		       const struct node_id *self,
		       const struct node_id *peer,
		       const struct short_channel_id_dir *scidd,
		       struct amount_msat htlcmin,
		       struct amount_msat htlcmax,
		       struct amount_msat spendable,
		       struct amount_msat fee_base,
		       u32 fee_proportional,
		       u32 cltv_delta,
		       bool enabled,
		       const char *buf,
		       const jsmntok_t *chantok,
		       struct payment *payment)
{
	struct amount_msat min, max;

	if (scidd->dir == node_id_idx(self, peer)) {
		/* local channels can send up to what's spendable */
		min = AMOUNT_MSAT(0);
		max = spendable;
	} else {
		/* remote channels can send up no more than spendable */
		min = htlcmin;
		max = amount_msat_min(spendable, htlcmax);
	}

	/* FIXME: features? */
	gossmap_local_addchan(mods, self, peer, scidd->scid, NULL);

	gossmap_local_updatechan(mods, scidd->scid, min, max,
				 fee_base.millisatoshis, /* Raw: gossmap */
				 fee_proportional,
				 cltv_delta,
				 enabled,
				 scidd->dir);

	/* Is it disabled? */
	if (!enabled)
		payment_disable_chan(payment, scidd->scid, LOG_DBG,
				     "listpeerchannels says not enabled");

	/* Also update the uncertainty network by fixing the liquidity of the
	 * outgoing channel. If we try to set the liquidity of the incoming
	 * channel as well we would have conflicting information because our
	 * knowledge model does not take into account channel reserves. */
	if (scidd->dir == node_id_idx(self, peer))
		uncertainty_update_from_listpeerchannels(
		    pay_plugin->uncertainty, scidd, max, enabled, buf, chantok);
}

static struct command_result *getmychannels_done(struct command *cmd,
						 const char *buf,
						 const jsmntok_t *result,
						 struct payment *payment)
{
	// FIXME: should local gossmods be global (ie. member of pay_plugin) or
	// local (ie. member of payment)?
	payment->local_gossmods = gossmods_from_listpeerchannels(
	    payment, &pay_plugin->my_id, buf, result, /* zero_rates = */ true,
	    gossmod_cb, payment);

	return payment_continue(payment);
}

static struct command_result *getmychannels_cb(struct payment *payment)
{
	struct command *cmd = payment_command(payment);
	if (!cmd)
		plugin_err(pay_plugin->plugin,
			   "getmychannels_pay_mod: cannot get a valid cmd.");

	struct out_req *req = jsonrpc_request_start(
	    cmd->plugin, cmd, "listpeerchannels", getmychannels_done,
	    payment_rpc_failure, payment);
	return send_outreq(cmd->plugin, req);
}

REGISTER_PAYMENT_MODIFIER(getmychannels, getmychannels_cb);

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

	size_t num_channel_updates_rejected;
	bool gossmap_changed =
	    gossmap_refresh(pay_plugin->gossmap, &num_channel_updates_rejected);

	if (gossmap_changed && num_channel_updates_rejected)
		plugin_log(pay_plugin->plugin, LOG_DBG,
			   "gossmap ignored %zu channel updates",
			   num_channel_updates_rejected);

	if (gossmap_changed) {
		gossmap_apply_localmods(pay_plugin->gossmap,
					payment->local_gossmods);
		int skipped_count = uncertainty_update(pay_plugin->uncertainty,
						       pay_plugin->gossmap);
		gossmap_remove_localmods(pay_plugin->gossmap,
					 payment->local_gossmods);
		if (skipped_count)
			plugin_log(
			    pay_plugin->plugin, LOG_UNUSUAL,
			    "%s: uncertainty was updated but %d channels have "
			    "been ignored.",
			    __PRETTY_FUNCTION__, skipped_count);
	}
	return payment_continue(payment);
}

REGISTER_PAYMENT_MODIFIER(refreshgossmap, refreshgossmap_cb);

/*****************************************************************************
 * routehints
 *
 * Use route hints from the invoice to update the local gossmods and uncertainty
 * network.
 */
// TODO check how this is done in pay.c

static void add_hintchan(struct payment *payment, const struct node_id *src,
			 const struct node_id *dst, u16 cltv_expiry_delta,
			 const struct short_channel_id scid, u32 fee_base_msat,
			 u32 fee_proportional_millionths)
{
	assert(payment);
	assert(payment->local_gossmods);

	int dir = node_id_idx(src, dst);

	const char *errmsg;
	const struct chan_extra *ce =
	    uncertainty_find_channel(pay_plugin->uncertainty, scid);

	if (!ce) {
		/* This channel is not public, we don't know his capacity
		 One possible solution is set the capacity to
		 MAX_CAP and the state to [0,MAX_CAP]. Alternatively we could
		 the capacity to amount and state to [amount,amount], but that
		 wouldn't work if the recepient provides more than one hints
		 telling us to partition the payment in multiple routes. */
		ce = uncertainty_add_channel(pay_plugin->uncertainty, scid,
					  MAX_CAPACITY);
		if (!ce) {
			errmsg = tal_fmt(tmpctx,
					 "Unable to find/add scid=%s in the "
					 "local uncertainty network",
					 fmt_short_channel_id(tmpctx, scid));
			goto function_error;
		}
		/* FIXME: features? */
		if (!gossmap_local_addchan(payment->local_gossmods, src, dst,
					   scid, NULL) ||
		    !gossmap_local_updatechan(
			payment->local_gossmods, scid,
			/* We assume any HTLC is allowed */
			AMOUNT_MSAT(0), MAX_CAPACITY, fee_base_msat,
			fee_proportional_millionths, cltv_expiry_delta, true,
			dir)) {
			errmsg = tal_fmt(
			    tmpctx,
			    "Failed to update scid=%s in the local_gossmods.",
			    fmt_short_channel_id(tmpctx, scid));
			goto function_error;
		}
	} else {
		/* The channel is pubic and we already keep track of it in the
		 * gossmap and uncertainty network. It would be wrong to assume
		 * that this channel has sufficient capacity to forward the
		 * entire payment! Doing so leads to knowledge updates in which
		 * the known min liquidity is greater than the channel's
		 * capacity. */
	}

	return;

function_error:
	plugin_log(pay_plugin->plugin, LOG_UNUSUAL,
		   "Failed to update hint channel %s: %s",
		   fmt_short_channel_id(tmpctx, scid),
		   errmsg);
}

static struct command_result *routehints_done(struct command *cmd UNUSED,
					      const char *buf UNUSED,
					      const jsmntok_t *result UNUSED,
					      struct payment *payment)
{
	// FIXME are there route hints for B12?
	assert(payment);
	assert(payment->local_gossmods);

	const struct node_id *destination = &payment->payment_info.destination;
	const struct route_info **routehints = payment->payment_info.routehints;
	assert(routehints);
	const size_t nhints = tal_count(routehints);
	/* Hints are added to the local_gossmods. */
	for (size_t i = 0; i < nhints; i++) {
		/* Each one, presumably, leads to the destination */
		const struct route_info *r = routehints[i];
		const struct node_id *end = destination;

		for (int j = tal_count(r) - 1; j >= 0; j--) {
			add_hintchan(payment, &r[j].pubkey, end,
				     r[j].cltv_expiry_delta,
				     r[j].short_channel_id, r[j].fee_base_msat,
				     r[j].fee_proportional_millionths);
			end = &r[j].pubkey;
		}
	}

	/* Add hints to the uncertainty network. */
	gossmap_apply_localmods(pay_plugin->gossmap, payment->local_gossmods);
	int skipped_count =
	    uncertainty_update(pay_plugin->uncertainty, pay_plugin->gossmap);
	gossmap_remove_localmods(pay_plugin->gossmap, payment->local_gossmods);
	if (skipped_count)
		plugin_log(pay_plugin->plugin, LOG_UNUSUAL,
			   "%s: uncertainty was updated but %d channels have "
			   "been ignored.",
			   __PRETTY_FUNCTION__, skipped_count);

	return payment_continue(payment);
}

static struct command_result *routehints_cb(struct payment *payment)
{
	struct command *cmd = payment_command(payment);
	assert(cmd);
	struct out_req *req = jsonrpc_request_start(
	    cmd->plugin, cmd, "waitblockheight", routehints_done,
	    payment_rpc_failure, payment);
	json_add_num(req->js, "blockheight", 0);
	return send_outreq(cmd->plugin, req);
}

REGISTER_PAYMENT_MODIFIER(routehints, routehints_cb);

/*****************************************************************************
 * compute_routes
 *
 * Compute the payment routes.
 */

static struct command_result *compute_routes_cb(struct payment *payment)
{
	assert(payment->status == PAYMENT_PENDING);
	struct routetracker *routetracker = payment->routetracker;
	assert(routetracker);

	if (routetracker->computed_routes &&
	    tal_count(routetracker->computed_routes))
		plugin_err(pay_plugin->plugin,
			   "%s: no previously computed routes expected.",
			   __PRETTY_FUNCTION__);

	struct amount_msat feebudget, fees_spent, remaining;

	/* Total feebudget  */
	if (!amount_msat_sub(&feebudget, payment->payment_info.maxspend,
			     payment->payment_info.amount))
		plugin_err(pay_plugin->plugin, "%s: fee budget is negative?",
			   __PRETTY_FUNCTION__);

	/* Fees spent so far */
	if (!amount_msat_sub(&fees_spent, payment->total_sent,
			     payment->total_delivering))
		plugin_err(pay_plugin->plugin,
			   "%s: total_delivering is greater than total_sent?",
			   __PRETTY_FUNCTION__);

	/* Remaining fee budget. */
	if (!amount_msat_sub(&feebudget, feebudget, fees_spent))
		feebudget = AMOUNT_MSAT(0);

	/* How much are we still trying to send? */
	if (!amount_msat_sub(&remaining, payment->payment_info.amount,
			     payment->total_delivering)) {
		plugin_log(pay_plugin->plugin, LOG_UNUSUAL,
			   "%s: Payment is pending with full amount already "
			   "committed. We skip the computation of new routes.",
			   __PRETTY_FUNCTION__);
		return payment_continue(payment);
	}

	enum jsonrpc_errcode errcode;
	const char *err_msg = NULL;

	gossmap_apply_localmods(pay_plugin->gossmap, payment->local_gossmods);

	/* get_routes returns the answer, we assign it to the computed_routes,
	 * that's why we need to tal_free the older array. Maybe it would be
	 * better to pass computed_routes as a reference? */
	routetracker->computed_routes = tal_free(routetracker->computed_routes);

	// TODO: add an algorithm selector here
	/* We let this return an unlikely path, as it's better to try  once than
	 * simply refuse.  Plus, models are not truth! */
	routetracker->computed_routes = get_routes(
					    routetracker,
					    &payment->payment_info,
					    &pay_plugin->my_id,
					    &payment->payment_info.destination,
					    pay_plugin->gossmap,
					    pay_plugin->uncertainty,
					    payment->disabledmap,
					    remaining,
					    feebudget,
					    &payment->next_partid,
					    payment->groupid,
					    &errcode,
					    &err_msg);
	/* Otherwise the error message remains a child of the routetracker. */
	err_msg = tal_steal(tmpctx, err_msg);

	gossmap_remove_localmods(pay_plugin->gossmap, payment->local_gossmods);

	/* Couldn't feasible route, we stop. */
	if (!routetracker->computed_routes ||
	    tal_count(routetracker->computed_routes) == 0) {
		if (err_msg == NULL)
			err_msg = tal_fmt(
			    tmpctx, "get_routes returned NULL error message");
		return payment_fail(payment, errcode, "%s", err_msg);
	}

	return payment_continue(payment);
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
			   __PRETTY_FUNCTION__);
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
			    __PRETTY_FUNCTION__,
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
			     __PRETTY_FUNCTION__);
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
				   __PRETTY_FUNCTION__, err);

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
				   __PRETTY_FUNCTION__, err);

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
					   __PRETTY_FUNCTION__, __LINE__);
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

static struct command_result *knowledgerelax_cb(struct payment *payment)
{
	const u64 now_sec = time_now().ts.tv_sec;
	enum renepay_errorcode err = uncertainty_relax(
	    pay_plugin->uncertainty, now_sec - pay_plugin->last_time);
	if (err)
		plugin_err(pay_plugin->plugin,
			   "uncertainty_relax failed with error %s",
			   renepay_errorcode_name(err));
	pay_plugin->last_time = now_sec;
	return payment_continue(payment);
}

REGISTER_PAYMENT_MODIFIER(knowledgerelax, knowledgerelax_cb);

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
    /*6*/ OP_CALL, &getmychannels_pay_mod,
    /*8*/ OP_CALL, &routehints_pay_mod,
    // TODO: add a channel filter, for example disable channels that have
    // htlcmax < 0.1% of payment amount, or base fee > 100msat, or
    // proportional_fee > 10%, or capacity < 10% payment amount
    // TODO shadow_additions
    /* do */
	    /*10*/ OP_CALL, &pendingsendpays_pay_mod,
	    /*12*/ OP_CALL, &checktimeout_pay_mod,
	    /*14*/ OP_CALL, &refreshgossmap_pay_mod,
	    /*16*/ OP_CALL, &compute_routes_pay_mod,
	    /*18*/ OP_CALL, &send_routes_pay_mod,
	    /*do*/
		    /*20*/ OP_CALL, &sleep_pay_mod,
		    /*22*/ OP_CALL, &collect_results_pay_mod,
	    /*while*/
	    /*24*/ OP_IF, &nothaveresults_pay_cond, (void *)20,
    /* while */
    /*27*/ OP_IF, &retry_pay_cond, (void *)10,
    /*30*/ OP_CALL, &end_pay_mod, /* safety net, default failure if reached */
    /*32*/ NULL};
