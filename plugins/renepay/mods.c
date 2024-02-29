#include <common/amount.h>
#include <common/gossmods_listpeerchannels.h>
#include <common/json_stream.h>
#include <plugins/renepay/finish.h>
#include <plugins/renepay/mods.h>
#include <plugins/renepay/payplugin.h>
#include <plugins/renepay/uncertainty_network.h>

#define INVALID_ID UINT32_MAX

void payment_continue(struct payment *payment)
{
	const struct payment_modifier *mod = payment_modifier_pop(payment);
	if (mod != NULL) {
		/* There is another modifier, so call it. */
		plugin_log(pay_plugin->plugin, LOG_DBG, "Calling modifier %s",
			   mod->name);
		return mod->post_step_cb(payment);
	}
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

	// TODO flag a payment as failed
	// payment_set_fail(
	//     payment, errcode,
	//     "Failing a partial payment due to a failed RPC call: %.*s",
	//     json_tok_full_len(toks), json_tok_full(buffer, toks));
	return payment_finish(payment);
}

/*****************************************************************************
 * previous_sendpays
 *
 * Obtain a list of previous sendpay requests and check if
 * the current payment hash has already being used in previous failed, pending
 * or completed attempts.
 */
// TODO: function test this previous_sendpays_pay_mod

static struct command_result *listsendpays_ok(struct command *cmd,
					      const char *buf,
					      const jsmntok_t *result,
					      struct payment *payment)
{
	size_t i;
	const jsmntok_t *t, *arr;
	u32 max_group_id = 0;

	/* Data for pending payments, this will be the one
	 * who's result gets replayed if we end up suspending. */
	u32 pending_group_id = INVALID_ID;
	u32 max_pending_partid = 0;
	struct amount_msat pending_sent = AMOUNT_MSAT(0),
			   pending_msat = AMOUNT_MSAT(0);

	/* Data for a complete payment, if one exists. */
	u32 complete_parts = 0;
	struct preimage complete_preimage;
	u32 complete_created_at;
	u32 complete_groupid = INVALID_ID;
	struct amount_msat complete_sent = AMOUNT_MSAT(0),
			   complete_msat = AMOUNT_MSAT(0);

	arr = json_get_member(buf, result, "payments");
	if (!arr || arr->type != JSMN_ARRAY) {
		// TODO
		// payment_set_fail(
		//     payment, LIGHTNINGD,
		//     "Unexpected non-array result from listsendpays: %.*s",
		//     json_tok_full_len(result), json_tok_full(buf, result));
		return payment_finish(payment);
	}

	json_for_each_arr(i, t, arr)
	{
		u32 partid = 0, groupid;
		struct amount_msat this_msat, this_sent;
		const char *status;

		// TODO: we assume amount_msat is always present, but according
		// to the documentation this field is optional. How do I
		// interpret if amount_msat is missing?
		const char *err =
		    json_scan(tmpctx, buf, t,
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

		/* status could be completed, pending or failed */
		if (streq(status, "complete")) {
			if (complete_groupid != INVALID_ID &&
			    groupid != complete_groupid) {
				// TODO
				// payment_set_fail(payment, PAY_STATUS_UNEXPECTED,
				// 		 "Multiple complete groupids "
				// 		 "for this payment?");
				return payment_finish(payment);
			}
			complete_groupid = groupid;
			/* Now we know the payment completed. */
			if (!amount_msat_add(&complete_msat, complete_msat,
					     this_msat) ||
			    !amount_msat_add(&complete_sent, complete_sent,
					     this_sent))
				plugin_err(pay_plugin->plugin,
					   "%s (line %d) amount_msat overflow.",
					   __PRETTY_FUNCTION__, __LINE__);
			json_scan(
			    tmpctx, buf, t,
			    "{created_at:%"
			    ",payment_preimage:%}",
			    JSON_SCAN(json_to_u32, &complete_created_at),
			    JSON_SCAN(json_to_preimage, &complete_preimage));
			// FIXME there is json_add_timeabs, but there isn't
			// json_to_timeabs
			complete_parts++;
		} else if (streq(status, "pending")) {
			/* If we have more than one pending group, something
			 * went wrong! */
			if (pending_group_id != INVALID_ID &&
			    groupid != pending_group_id) {
				// TODO
				// payment_set_fail(payment, PAY_STATUS_UNEXPECTED,
				// 		 "Multiple pending groups for "
				// 		 "this payment?");
				return payment_finish(payment);
			}
			pending_group_id = groupid;
			if (partid > max_pending_partid)
				max_pending_partid = partid;

			if (!amount_msat_add(&pending_msat, pending_msat,
					     this_msat) ||
			    !amount_msat_add(&pending_sent, pending_sent,
					     this_sent))
				plugin_err(pay_plugin->plugin,
					   "%s (line %d) amount_msat overflow.",
					   __PRETTY_FUNCTION__, __LINE__);

		} else
			assert(streq(status, "failed"));
	}

	if (complete_groupid != INVALID_ID) {
		/* There are completed sendpays, we don't need to do anything
		 * but summarize the result. */
		payment->status = PAYMENT_SUCCESS;
		payment->start_time.ts.tv_sec = complete_created_at;
		payment->start_time.ts.tv_nsec = 0;

		payment->total_delivering = complete_msat;
		payment->total_sent = complete_sent;
		payment->next_partid = complete_parts + 1;
		payment->groupid = complete_groupid;
		payment->preimage =
		    tal_dup(payment, struct preimage, &complete_preimage);

		payment_note(payment, LOG_DBG,
			     "Payment completed by a previous sendpay.");
		return payment_finish(payment);
	} else if (pending_group_id != INVALID_ID) {
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
			   type_to_string(tmpctx, struct amount_msat,
					  &payment->total_delivering),
			   max_pending_partid);

		if (amount_msat_greater_eq(payment->total_delivering,
					   payment->amount)) {
			/* Pending payment already pays the full amount, we
			 * better stop. */
			// TODO
			// payment_set_fail(payment, PAY_IN_PROGRESS,
			// 		 "Payment is pending with full amount "
			// 		 "already commited");
			return payment_finish(payment);
		}
	} else {
		/* There are no pending nor completed sendpays, get me the last
		 * sendpay group. */
		payment->groupid = max_group_id + 1;
		payment->next_partid = 1;
	}

	payment_continue(payment);
	return command_still_pending(cmd);
}

static void previous_sendpays_cb(struct payment *payment)
{
	struct command *cmd = payment_command(payment);
	assert(cmd);

	struct out_req *req = jsonrpc_request_start(
	    cmd->plugin, cmd, "listsendpays", listsendpays_ok,
	    payment_rpc_failure, payment);

	json_add_sha256(req->js, "payment_hash", &payment->payment_hash);
	send_outreq(cmd->plugin, req);
}

REGISTER_PAYMENT_MODIFIER(previous_sendpays, previous_sendpays_cb);

/*****************************************************************************
 * initial_sanity_checks
 *
 * Some checks on a payment about to start.
 */
static void initial_sanity_checks_cb(struct payment *payment)
{
	assert(amount_msat_zero(payment->total_sent));
	assert(amount_msat_zero(payment->total_delivering));
	assert(!payment->preimage);
	assert(tal_count(payment->cmd_array) == 1);

	payment_continue(payment);
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
					      const jsmntok_t *result,
					      struct payment *payment)
{
	struct preimage preimage;
	const char *err;
	err = json_scan(tmpctx, buf, result, "{payment_preimage:%}",
			JSON_SCAN(json_to_preimage, &preimage));
	if (err)
		plugin_err(
		    cmd->plugin, "selfpay didn't have payment_preimage? %.*s",
		    json_tok_full_len(result), json_tok_full(buf, result));

	payment->preimage = tal_dup(payment, struct preimage, &preimage);
	payment->status = PAYMENT_SUCCESS;
	payment_note(payment, LOG_DBG, "Paid with self-pay.");
	return payment_finish(payment);
}

static void selfpay_cb(struct payment *payment)
{
	if (!node_id_eq(&pay_plugin->my_id, &payment->destination)) {
		payment_continue(payment);
		return;
	}

	struct command *cmd = payment_command(payment);
	if (!cmd)
		plugin_err(pay_plugin->plugin,
			   "Selfpay: cannot get a valid cmd.");
	struct out_req *req;
	req =
	    jsonrpc_request_start(cmd->plugin, cmd, "sendpay", selfpay_success,
				  payment_rpc_failure, payment);
	/* Empty route means "to-self" */
	json_array_start(req->js, "route");
	json_array_end(req->js);
	json_add_sha256(req->js, "payment_hash", &payment->payment_hash);
	if (payment->label)
		json_add_string(req->js, "label", payment->label);
	json_add_amount_msat(req->js, "amount_msat", payment->amount);
	json_add_string(req->js, "bolt11", payment->invstr);
	if (payment->payment_secret)
		json_add_secret(req->js, "payment_secret",
				payment->payment_secret);
	json_add_u32(req->js, "groupid", payment->groupid);
	if (payment->payment_metadata)
		json_add_hex_talarr(req->js, "payment_metadata",
				    payment->payment_metadata);
	if (payment->description)
		json_add_string(req->js, "description", payment->description);

	/* Pretend we have sent partid=1 with the total amount. */
	payment->next_partid = 2;
	payment->total_sent = payment->amount;
	send_outreq(cmd->plugin, req);
}

REGISTER_PAYMENT_MODIFIER(selfpay, selfpay_cb);

/*****************************************************************************
 * getmychannels
 *
 * Calls listpeerchannels to get and updated state of the local channels.
 */

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
		       bool is_local,
		       const char *buf,
		       const jsmntok_t *chantok,
		       struct payment *payment)
{
	struct amount_msat min, max;

	if (is_local) {
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

	/* Also update uncertainty map */
	uncertainty_network_update_from_listpeerchannels(payment, scidd, max, enabled,
							 buf, chantok,
							 pay_plugin->chan_extra_map);
}

static struct command_result *listpeerchannels_ok(struct command *cmd,
						  const char *buf,
						  const jsmntok_t *result,
						  struct payment *payment)
{
	// FIXME: should local gossmods be global (ie. member of pay_plugin) or
	// local (ie. member of payment)?
	payment->local_gossmods = gossmods_from_listpeerchannels(
	    payment, &pay_plugin->my_id, buf, result, gossmod_cb, payment);

	payment_continue(payment);
	return command_still_pending(cmd);
}

static void getmychannels_cb(struct payment *payment)
{
	struct command *cmd = payment_command(payment);
	if (!cmd)
		plugin_err(pay_plugin->plugin,
			   "getmychannels_pay_mod: cannot get a valid cmd.");

	struct out_req *req = jsonrpc_request_start(
	    cmd->plugin, cmd, "listpeerchannels", listpeerchannels_ok,
	    payment_rpc_failure, payment);
	send_outreq(cmd->plugin, req);
}

REGISTER_PAYMENT_MODIFIER(getmychannels, getmychannels_cb);

/*****************************************************************************
 * refreshgossmap
 *
 * Update the gossmap.
 */
static void refreshgossmap_cb(struct payment *payment)
{
	assert(pay_plugin->gossmap); // gossmap must be already initialized

	size_t num_channel_updates_rejected;
	bool gossmap_changed =
	    gossmap_refresh(pay_plugin->gossmap, &num_channel_updates_rejected);

	if (num_channel_updates_rejected)
		plugin_log(pay_plugin->plugin, LOG_DBG,
			   "gossmap ignored %zu channel updates",
			   num_channel_updates_rejected);

	// TODO: use unetwork here instead of chan_extra_map
	if (gossmap_changed)
		uncertainty_network_update(pay_plugin->gossmap,
					   pay_plugin->chan_extra_map);

	payment_continue(payment);
}

REGISTER_PAYMENT_MODIFIER(refreshgossmap, refreshgossmap_cb);

/*****************************************************************************
 * routehints
 *
 * Use route hints from the invoice to update the local gossmods and uncertainty
 * network.
 */
// TODO check how this is done in pay.c
static void routehints_cb(struct payment *payment)
{
	// TODO(eduardo): are there route hints for B12?
	// TODO: use unetwork instead of chan_extra_map
	uncertainty_network_add_routehints(pay_plugin->chan_extra_map,
					   payment->routes, payment);
	payment_continue(payment);
}

REGISTER_PAYMENT_MODIFIER(routehints, routehints_cb);

/*****************************************************************************
 * compute_routes
 *
 * Compute the payment routes.
 */
static void compute_routes_cb(struct payment *payment)
{
	assert(payment->status == PAYMENT_PENDING);

	struct amount_msat feebudget, fees_spent, remaining;

	/* Total feebudget  */
	if (!amount_msat_sub(&feebudget, payment->maxspend, payment->amount))
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
		plugin_err(pay_plugin->plugin,
			   "%s: fees_speng is greater than feebudget?",
			   __PRETTY_FUNCTION__);

	/* How much are we still trying to send? */
	if (!amount_msat_sub(&remaining, payment->amount,
			     payment->total_delivering))
		plugin_err(pay_plugin->plugin,
			   "%s: total_delivering is greater than amount?",
			   __PRETTY_FUNCTION__);

	/* We let this return an unlikely path, as it's better to try once
	 * than simply refuse.  Plus, models are not truth! */
	gossmap_apply_localmods(pay_plugin->gossmap, payment->local_gossmods);
	// TODO: add an algorithm selector here
	// TODO: review add_payflows
	enum jsonrpc_errcode errcode;
	const char *err_msg =
	    add_payflows(tmpctx, payment, remaining, feebudget,
			 /* is entire payment? */
			 amount_msat_eq(remaining, AMOUNT_MSAT(0)), &errcode);
	gossmap_remove_localmods(pay_plugin->gossmap, payment->local_gossmods);

	/* Couldn't feasible route, we stop. */
	if (err_msg) {
		// TODO
		// payment_set_fail(payment, errcode, "%s", err_msg);
		payment_finish(payment);
	}

	payment_continue(payment);
}

REGISTER_PAYMENT_MODIFIER(compute_routes, compute_routes_cb);

/*****************************************************************************
 * send_routes
 *
 * This payment modifier takes the payment routes and starts the payment request
 * calling sendpay.
 */

static struct command_result *flow_sent(struct command *cmd, const char *buf,
					const jsmntok_t *result,
					struct pay_flow *pf)
{
	// TODO: put here the user interface messages
	return command_still_pending(cmd);
}

/* sendpay really only fails immediately in two ways:
 * 1. We screwed up and misused the API.
 * 2. The first peer is disconnected.
 */
static struct command_result *flow_sendpay_failed(struct command *cmd,
						  const char *buf,
						  const jsmntok_t *err,
						  struct pay_flow *pf)
{
	// TODO check how pay.c handles this
	struct payment *payment = pf->payment;
	enum jsonrpc_errcode errcode;
	const char *msg;

	assert(payment);

	if (json_scan(tmpctx, buf, err, "{code:%,message:%}",
		      JSON_SCAN(json_to_jsonrpc_errcode, &errcode),
		      JSON_SCAN_TAL(tmpctx, json_strdup, &msg)))
		plugin_err(pay_plugin->plugin,
			   "Unable to parse sendpay error: %.*s",
			   json_tok_full_len(err), json_tok_full(buf, err));

	if (errcode != PAY_TRY_OTHER_ROUTE)
		plugin_err(pay_plugin->plugin,
			   "Strange error from sendpay: %.*s",
			   json_tok_full_len(err), json_tok_full(buf, err));

	/* There is no new knowledge from this kind of failure.
	 * We just disable this scid. */
	// TODO: review this
	payflow_disable_chan(pf, pf->path_scidds[0].scid, LOG_INFORM,
			     "sendpay didn't like first hop: %s", msg);

	// TODO: review this
	pay_flow_failed(pf);
	return command_still_pending(cmd);
}

static void send_routes_cb(struct payment *payment)
{
	struct command *cmd = payment_command(payment);
	assert(cmd);

	// TODO: use struct route instead of struct pay_flow
	struct pay_flow *pf;

	/* Kick off all pay_flows which are in state PAY_FLOW_NOT_STARTED */
	list_for_each(&payment->flows, pf, list)
	{

		if (pf->state != PAY_FLOW_NOT_STARTED)
			continue;

		struct out_req *req =
		    jsonrpc_request_start(pay_plugin->plugin, cmd, "sendpay",
					  flow_sent, flow_sendpay_failed, pf);

		json_array_start(req->js, "route");
		for (size_t j = 0; j < tal_count(pf->path_nodes); j++) {
			json_object_start(req->js, NULL);
			json_add_node_id(req->js, "id", &pf->path_nodes[j]);
			json_add_short_channel_id(req->js, "channel",
						  &pf->path_scidds[j].scid);
			json_add_amount_msat(req->js, "amount_msat",
					     pf->amounts[j]);
			json_add_num(req->js, "direction",
				     pf->path_scidds[j].dir);
			json_add_u32(req->js, "delay", pf->cltv_delays[j]);
			json_add_string(req->js, "style", "tlv");
			json_object_end(req->js);
		}
		json_array_end(req->js);

		json_add_sha256(req->js, "payment_hash",
				&payment->payment_hash);
		json_add_secret(req->js, "payment_secret",
				payment->payment_secret);

		/* FIXME: sendpay has a check that we don't total more than
		 * the exact amount, if we're setting partid (i.e. MPP).
		 * However, we always set partid, and we add a shadow amount *if
		 * we've only have one part*, so we have to use that amount
		 * here.
		 *
		 * The spec was loosened so you are actually allowed
		 * to overpay, so this check is now overzealous. */
		if (amount_msat_greater(payflow_delivered(pf),
					payment->amount)) {
			json_add_amount_msat(req->js, "amount_msat",
					     payflow_delivered(pf));
		} else {
			json_add_amount_msat(req->js, "amount_msat",
					     payment->amount);
		}

		json_add_u64(req->js, "partid", pf->key.partid);

		json_add_u64(req->js, "groupid", payment->groupid);
		if (payment->payment_metadata)
			json_add_hex_talarr(req->js, "payment_metadata",
					    payment->payment_metadata);

		/* FIXME: We don't need these three for all payments! */
		if (payment->label)
			json_add_string(req->js, "label", payment->label);
		json_add_string(req->js, "bolt11", payment->invstr);
		if (payment->description)
			json_add_string(req->js, "description",
					payment->description);

		send_outreq(pay_plugin->plugin, req);

		/* Now you're started! */
		pf->state = PAY_FLOW_IN_PROGRESS;
	}

	/* Safety check. */
	payment_assert_delivering_all(payment);

	payment_continue(payment);
}

REGISTER_PAYMENT_MODIFIER(send_routes, send_routes_cb);

/*****************************************************************************
 * end
 *
 * A dummy modifier used to end the payment, just for testing.
 */
static void end_cb(struct payment *payment)
{
	// TODO flag a payment as failed
	// payment_set_fail(
	//     payment, LIGHTNINGD,
	//     "Failing the payment on purpose (call to end_pay_mod)");
	payment_finish(payment);
}

REGISTER_PAYMENT_MODIFIER(end, end_cb);
