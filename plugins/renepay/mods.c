#include <common/amount.h>
#include <common/gossmods_listpeerchannels.h>
#include <common/json_stream.h>
#include <plugins/renepay/finish.h>
#include <plugins/renepay/mods.h>
#include <plugins/renepay/payplugin.h>
#include <plugins/renepay/uncertainty_network.h>

#define INVALID_ID UINT32_MAX

void payment_continue(struct payment *p)
{
	const struct payment_modifier *mod = payment_modifier_pop(p);
	if (mod != NULL) {
		/* There is another modifier, so call it. */
		plugin_log(pay_plugin->plugin, LOG_DBG, "Calling modifier %s",
			   mod->name);
		return mod->post_step_cb(p);
	}
	plugin_err(pay_plugin->plugin,
		   "Finished all modifiers but we have not come to conclusion");
}

/* Generic handler for RPC failures that should end up failing the payment. */
static struct command_result *payment_rpc_failure(struct command *cmd,
						  const char *buffer,
						  const jsmntok_t *toks,
						  struct payment *p)
{
	const jsmntok_t *codetok = json_get_member(buffer, toks, "code");
	u32 errcode;
	if (codetok != NULL)
		json_to_u32(buffer, codetok, &errcode);
	else
		errcode = LIGHTNINGD;

	// TODO flag a payment as failed
	// payment_set_fail(
	//     p, errcode,
	//     "Failing a partial payment due to a failed RPC call: %.*s",
	//     json_tok_full_len(toks), json_tok_full(buffer, toks));
	return payment_finish(p);
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
					      struct payment *p)
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
		//     p, LIGHTNINGD,
		//     "Unexpected non-array result from listsendpays: %.*s",
		//     json_tok_full_len(result), json_tok_full(buf, result));
		return payment_finish(p);
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
				// payment_set_fail(p, PAY_STATUS_UNEXPECTED,
				// 		 "Multiple complete groupids "
				// 		 "for this payment?");
				return payment_finish(p);
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
				// payment_set_fail(p, PAY_STATUS_UNEXPECTED,
				// 		 "Multiple pending groups for "
				// 		 "this payment?");
				return payment_finish(p);
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
		p->status = PAYMENT_SUCCESS;
		p->start_time.ts.tv_sec = complete_created_at;
		p->start_time.ts.tv_nsec = 0;

		p->total_delivering = complete_msat;
		p->total_sent = complete_sent;
		p->next_partid = complete_parts + 1;
		p->groupid = complete_groupid;
		p->preimage = tal_dup(p, struct preimage, &complete_preimage);

		payment_note(p, LOG_DBG,
			     "Payment completed by a previous sendpay.");
		return payment_finish(p);
	} else if (pending_group_id != INVALID_ID) {
		/* Continue where we left off? */
		p->groupid = pending_group_id;
		p->next_partid = max_pending_partid + 1;
		p->total_sent = pending_sent;
		p->total_delivering = pending_msat;

		plugin_log(pay_plugin->plugin, LOG_DBG,
			   "There are pending sendpays to this invoice. "
			   "groupid = %" PRIu32 " "
			   "delivering = %s, "
			   "last_partid = %" PRIu32,
			   pending_group_id,
			   type_to_string(tmpctx, struct amount_msat,
					  &p->total_delivering),
			   max_pending_partid);

		if (amount_msat_greater_eq(p->total_delivering, p->amount)) {
			/* Pending payment already pays the full amount, we
			 * better stop. */
			// TODO
			// payment_set_fail(p, PAY_IN_PROGRESS,
			// 		 "Payment is pending with full amount "
			// 		 "already commited");
			return payment_finish(p);
		}
	} else {
		/* There are no pending nor completed sendpays, get me the last
		 * sendpay group. */
		p->groupid = max_group_id + 1;
		p->next_partid = 1;
	}

	payment_continue(p);
	return command_still_pending(cmd);
}

static void previous_sendpays_cb(struct payment *p)
{
	struct command *cmd = payment_command(p);
	assert(cmd);

	struct out_req *req =
	    jsonrpc_request_start(cmd->plugin, cmd, "listsendpays",
				  listsendpays_ok, payment_rpc_failure, p);

	json_add_sha256(req->js, "payment_hash", &p->payment_hash);
	send_outreq(cmd->plugin, req);
}

REGISTER_PAYMENT_MODIFIER(previous_sendpays, previous_sendpays_cb);

/*****************************************************************************
 * initial_sanity_checks
 *
 * Some checks on a payment about to start.
 */
static void initial_sanity_checks_cb(struct payment *p)
{
	assert(amount_msat_zero(p->total_sent));
	assert(amount_msat_zero(p->total_delivering));
	assert(!p->preimage);
	assert(tal_count(p->cmd_array) == 1);

	payment_continue(p);
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
					      struct payment *p)
{
	struct preimage preimage;
	const char *err;
	err = json_scan(tmpctx, buf, result, "{payment_preimage:%}",
			JSON_SCAN(json_to_preimage, &preimage));
	if (err)
		plugin_err(
		    cmd->plugin, "selfpay didn't have payment_preimage? %.*s",
		    json_tok_full_len(result), json_tok_full(buf, result));

	p->preimage = tal_dup(p, struct preimage, &preimage);
	p->status = PAYMENT_SUCCESS;
	payment_note(p, LOG_DBG, "Paid with self-pay.");
	return payment_finish(p);
}

static void selfpay_cb(struct payment *p)
{
	if (!node_id_eq(&pay_plugin->my_id, &p->destination)) {
		payment_continue(p);
		return;
	}

	struct command *cmd = payment_command(p);
	if (!cmd)
		plugin_err(pay_plugin->plugin,
			   "Selfpay: cannot get a valid cmd.");
	struct out_req *req;
	req = jsonrpc_request_start(cmd->plugin, cmd, "sendpay",
				    selfpay_success, payment_rpc_failure, p);
	/* Empty route means "to-self" */
	json_array_start(req->js, "route");
	json_array_end(req->js);
	json_add_sha256(req->js, "payment_hash", &p->payment_hash);
	if (p->label)
		json_add_string(req->js, "label", p->label);
	json_add_amount_msat(req->js, "amount_msat", p->amount);
	json_add_string(req->js, "bolt11", p->invstr);
	if (p->payment_secret)
		json_add_secret(req->js, "payment_secret", p->payment_secret);
	json_add_u32(req->js, "groupid", p->groupid);
	if (p->payment_metadata)
		json_add_hex_talarr(req->js, "payment_metadata",
				    p->payment_metadata);
	if (p->description)
		json_add_string(req->js, "description", p->description);

	/* Pretend we have sent partid=1 with the total amount. */
	p->next_partid = 2;
	p->total_sent = p->amount;
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
						  struct payment *p)
{
	// FIXME: should local gossmods be global (ie. member of pay_plugin) or
	// local (ie. member of payment)?
	p->local_gossmods = gossmods_from_listpeerchannels(
	    p, &pay_plugin->my_id, buf, result, gossmod_cb, p);

	payment_continue(p);
	return command_still_pending(cmd);
}

static void getmychannels_cb(struct payment *p)
{
	struct command *cmd = payment_command(p);
	if (!cmd)
		plugin_err(pay_plugin->plugin,
			   "getmychannels_pay_mod: cannot get a valid cmd.");

	struct out_req *req =
	    jsonrpc_request_start(cmd->plugin, cmd, "listpeerchannels",
				  listpeerchannels_ok, payment_rpc_failure, p);
	send_outreq(cmd->plugin, req);
}

REGISTER_PAYMENT_MODIFIER(getmychannels, getmychannels_cb);

/*****************************************************************************
 * end
 *
 * A dummy modifier used to end the payment, just for testing.
 */
static void end_cb(struct payment *p)
{
	// TODO flag a payment as failed
	// payment_set_fail(
	//     p, LIGHTNINGD,
	//     "Failing the payment on purpose (call to end_pay_mod)");
	payment_finish(p);
}

REGISTER_PAYMENT_MODIFIER(end, end_cb);
