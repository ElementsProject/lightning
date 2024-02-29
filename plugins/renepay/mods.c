#include <common/amount.h>
#include <common/json_stream.h>
#include <plugins/renepay/finish.h>
#include <plugins/renepay/mods.h>
#include <plugins/renepay/payplugin.h>

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

		plugin_log(pay_plugin->plugin, LOG_DBG,
			   "There are completed sendpays to this invoice.");
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
