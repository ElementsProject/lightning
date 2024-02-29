#include <common/json_stream.h>
#include <plugins/renepay/finish.h>
#include <plugins/renepay/mods.h>
#include <plugins/renepay/payplugin.h>

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

static struct command_result *listsendpays_ok(struct command *cmd,
					      const char *buf,
					      const jsmntok_t *result,
					      struct payment *p)
{
	// TODO: implement
	payment_continue(p);
	// TODO command_still_pendings are dangerous because we might end up in
	// a dead end. Think about how could we reduce dead-ends using
	// compile-time checks.
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
