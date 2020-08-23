#include <bitcoin/chainparams.h>
#include <bitcoin/psbt.h>
#include <bitcoin/script.h>
#include <bitcoin/tx.h>
#include <ccan/array_size/array_size.h>
#include <ccan/compiler/compiler.h>
#include <ccan/json_out/json_out.h>
#include <ccan/tal/str/str.h>
#include <common/json_helpers.h>
#include <common/json_stream.h>
#include <common/type_to_string.h>
#include <plugins/spender/donateutxo.h>

/*-----------------------------------------------------------------------------
Command Access
-----------------------------------------------------------------------------*/

static struct command_result*
json_donateutxo(struct command *cmd,
		const char *buf,
		const jsmntok_t *params);
const struct plugin_command donateutxo_commands[] = {
	{
		"donateutxo",
		"bitcoin",
		"Donate a specific {utxo} with {amount} to miners.",
		"Donate the entire amount of a specific {utxo} to miners, "
		"checking that this has a specific {amount};"
		"used for example if the UTXO is a dusting privacy attack.",
		&json_donateutxo,
		false
	}
};
const size_t num_donateutxo_commands = ARRAY_SIZE(donateutxo_commands);

/*-----------------------------------------------------------------------------
Donate Single UTXO
-----------------------------------------------------------------------------*/

static struct command_result*
donateutxo_after_utxopsbt(struct command *cmd,
			  const char *buf,
			  const jsmntok_t *result,
			  struct amount_sat *expected_amount);

static struct command_result*
json_donateutxo(struct command *cmd,
		const char *buf,
		const jsmntok_t *params)
{
	const jsmntok_t *utxo;
	struct out_req *req;
	struct amount_sat *expected_amount;

	if (!param(cmd, buf, params,
		   p_req("utxo", param_tok, &utxo),
		   p_req("amount", param_sat, &expected_amount),
		   NULL))
		return command_param_failed();

	req = jsonrpc_request_start(cmd->plugin, cmd, "utxopsbt",
				    &donateutxo_after_utxopsbt,
				    &forward_error, expected_amount);
	json_add_string(req->js, "satoshi", "all");
	/* This feerate is BS since we are donating the entire amount
	 * to miners, but we cannot set it (at utxopsbt) to lower than
	 * "slow" anyway, as "slow" means "lowest allowed feerate".  */
	json_add_string(req->js, "feerate", "slow");
	/* Also a BS weight.  Feerate does not matter since this is a
	 * miner donation, and weight matters only if feerate matters.  */
	json_add_num(req->js, "startweight", 0);
	json_array_start(req->js, "utxos");
	json_add_tok(req->js, NULL, utxo, buf);
	json_array_end(req->js);
	json_add_bool(req->js, "reserve", true);
	json_add_bool(req->js, "reservedok", false);

	return send_outreq(cmd->plugin, req);
}

static struct command_result*
donateutxo_fail_amount_check(struct command *cmd,
			     struct wally_psbt *psbt,
			     struct amount_sat expected,
			     struct amount_sat actual);
static struct command_result*
donateutxo_after_signpsbt(struct command *cmd,
			  const char *buf,
			  const jsmntok_t *result,
			  struct wally_psbt *prev_psbt);
static struct command_result*
donateutxo_fail_signsendpsbt(struct command *cmd,
			     const char *buf,
			     const jsmntok_t *error,
			     struct wally_psbt *psbt);

static struct command_result*
donateutxo_after_utxopsbt(struct command *cmd,
			  const char *buf,
			  const jsmntok_t *result,
			  struct amount_sat *expected_amount)
{
	struct wally_psbt *psbt;
	const jsmntok_t *field;
	bool ok;
	struct amount_sat actual_amount;
	struct out_req *req;

	ok = true;
	field = ok ? json_get_member(buf, result, "psbt") : NULL;
	ok = ok && field;
	psbt = ok ? psbt_from_b64(cmd,
				  buf + field->start,
				  field->end - field->start) : NULL;
	ok = ok && psbt;

	if (!ok)
		plugin_err(cmd->plugin,
			   "Unexpected result from utxopsbt: %.*s",
			   json_tok_full_len(result),
			   json_tok_full(buf, result));

	actual_amount = psbt_input_get_amount(psbt, 0);
	if (!amount_sat_eq(*expected_amount, actual_amount))
		return donateutxo_fail_amount_check(cmd, psbt,
						    *expected_amount,
						    actual_amount);

	/* Add an `OP_RETURN` output.  */
	psbt_append_output(psbt,
			   scriptpubkey_opreturn_padded(cmd),
			   AMOUNT_SAT(0));

	/* On elements, add a fee output.  */
	if (chainparams->is_elements)
		/* Donate to miners.  */
		psbt_append_output(psbt, NULL, actual_amount);

	/* Sign it.  */
	req = jsonrpc_request_start(cmd->plugin, cmd, "signpsbt",
				    &donateutxo_after_signpsbt,
				    &donateutxo_fail_signsendpsbt,
				    psbt);
	json_add_psbt(req->js, "psbt", psbt);
	return send_outreq(cmd->plugin, req);
}

static struct command_result*
donateutxo_after_signpsbt(struct command *cmd,
			  const char *buf,
			  const jsmntok_t *result,
			  struct wally_psbt *prev_psbt)
{
	struct wally_psbt *psbt;
	const jsmntok_t *field;
	bool ok;
	struct out_req *req;

	ok = true;
	field = ok ? json_get_member(buf, result, "signed_psbt") : NULL;
	ok = ok && field;
	psbt = ok ? psbt_from_b64(cmd,
				  buf + field->start,
				  field->end - field->start) : NULL;
	ok = ok && psbt;

	if (!ok)
		plugin_err(cmd->plugin,
			   "Unexpected result from signpsbt: %.*s",
			   json_tok_full_len(result),
			   json_tok_full(buf, result));

	/* Now we can free prev_psbt.  */
	tal_free(prev_psbt);

	/* Now send it.  */
	req = jsonrpc_request_start(cmd->plugin, cmd, "sendpsbt",
				    &forward_result,
				    &donateutxo_fail_signsendpsbt,
				    psbt);
	json_add_psbt(req->js, "psbt", psbt);
	return send_outreq(cmd->plugin, req);
}

/* Cleanup.  */
static struct command_result*
donateutxo_after_unreserveinputs(struct command *cmd,
				 const char *buf,
				 const jsmntok_t *ignored UNUSED,
				 char *error_json);

static struct command_result*
donateutxo_fail_amount_check(struct command *cmd,
			     struct wally_psbt *psbt,
			     struct amount_sat expected,
			     struct amount_sat actual)
{
	struct json_stream *js;
	const char *buf;
	size_t len;
	char *error_json;
	struct out_req *req;

	/* Construct error object.  */
	js = new_json_stream(tmpctx, cmd, NULL);
	json_object_start(js, NULL);
	json_add_errcode(js, "code", FUND_CANNOT_AFFORD);
	json_add_string(js, "message",
			tal_fmt(tmpctx, "UTXO is %s, not expected %s",
				type_to_string(tmpctx, struct amount_sat,
					       &actual),
				type_to_string(tmpctx, struct amount_sat,
					       &expected)));
	json_object_end(js);

	/* Extract error object into JSON string representation.  */
	buf = json_out_contents(js->jout, &len);
	error_json = tal_strndup(cmd, buf, len);

	/* Unreserve UTXO.  */
	req = jsonrpc_request_start(cmd->plugin, cmd, "unreserveinputs",
				    &donateutxo_after_unreserveinputs,
				    &donateutxo_after_unreserveinputs,
				    error_json);
	json_add_psbt(req->js, "psbt", psbt);
	return send_outreq(cmd->plugin, req);
}

static struct command_result*
donateutxo_fail_signsendpsbt(struct command *cmd,
			     const char *buf,
			     const jsmntok_t *error,
			     struct wally_psbt *psbt)
{
	char *error_json;
	struct out_req *req;

	/* Save a copy of the error.  */
	error_json = tal_strndup(cmd,
				 buf + error->start,
				 error->end - error->start);

	/* Unreserve UTXO.  */
	req = jsonrpc_request_start(cmd->plugin, cmd, "unreserveinputs",
				    &donateutxo_after_unreserveinputs,
				    &donateutxo_after_unreserveinputs,
				    error_json);
	json_add_psbt(req->js, "psbt", psbt);
	return send_outreq(cmd->plugin, req);
}
static struct command_result*
donateutxo_after_unreserveinputs(struct command *cmd,
				 const char *buf,
				 const jsmntok_t *ignored UNUSED,
				 char *error_json)
{
	return command_err_raw(cmd, error_json);
}
