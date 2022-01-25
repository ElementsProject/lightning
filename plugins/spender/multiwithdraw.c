#include "config.h"
#include <bitcoin/chainparams.h>
#include <bitcoin/psbt.h>
#include <ccan/array_size/array_size.h>
#include <ccan/json_out/json_out.h>
#include <ccan/tal/str/str.h>
#include <common/json_stream.h>
#include <common/json_tok.h>
#include <common/psbt_open.h>
#include <common/pseudorand.h>
#include <common/type_to_string.h>
#include <plugins/spender/multiwithdraw.h>
#include <wally_psbt.h>

/*-----------------------------------------------------------------------------
Command Access
-----------------------------------------------------------------------------*/

static struct command_result *
json_multiwithdraw(struct command *cmd,
		   const char *buf,
		   const jsmntok_t *params);

const struct plugin_command multiwithdraw_commands[] = {
	{
		"multiwithdraw",
		"bitcoin",
		"Send to multiple {outputs} via a single Bitcoin transaction.",
		"Send to multiple {outputs} at optiona {feerate}, spending "
		"coins at least {minconf} depth, or the specified {utxos}.",
		&json_multiwithdraw,
		false
	}
};
const size_t num_multiwithdraw_commands = ARRAY_SIZE(multiwithdraw_commands);

/*-----------------------------------------------------------------------------
Multiwithdraw Object
-----------------------------------------------------------------------------*/

struct multiwithdraw_destination {
	/* The destination scriptPubKey.  */
	const u8 *script;
	/* The amount to send to this destination.  */
	struct amount_sat amount;
	/* Whether the amount was "all".  */
	bool all;
	/* Whether this is to an external addr (all passed in are assumed) */
	bool is_to_external;
};

struct multiwithdraw_command {
	struct command *cmd;
	u64 id;

	/* Outputs to send to.  */
	struct multiwithdraw_destination *outputs;
	/* Whether any of the destinations is "all".  */
	bool has_all;
	/* Other params.  */
	const char *feerate;
	u32 *minconf;
	const char *utxos;

	/* The PSBT we are currently wrangling.  */
	struct wally_psbt *psbt;

	/* Details about change.  */
	struct amount_sat change_amount;
	bool change_needed;
};

/*-----------------------------------------------------------------------------
Input Validation
-----------------------------------------------------------------------------*/

static struct command_result *
param_outputs_array(struct command *cmd,
		    const char *name,
		    const char *buf,
		    const jsmntok_t *t,
		    struct multiwithdraw_destination **outputs)
{
	size_t i;
	const jsmntok_t *e;
	bool has_all = false;

	if (t->type != JSMN_ARRAY)
		goto err;
	if (t->size == 0)
		goto err;

	*outputs = tal_arr(cmd, struct multiwithdraw_destination, t->size);
	json_for_each_arr (i, e, t) {
		struct multiwithdraw_destination *dest;
		enum address_parse_result res;

		dest = &(*outputs)[i];
		dest->is_to_external = true;

		if (e->type != JSMN_OBJECT)
			goto err;
		if (e->size != 1)
			goto err;

		res = json_to_address_scriptpubkey(cmd, chainparams,
						   buf, &e[1],
						   &dest->script);
		if (res == ADDRESS_PARSE_UNRECOGNIZED)
			return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
					    "'%s' address could not be "
					    "parsed: %.*s",
					    name,
					    json_tok_full_len(&e[1]),
					    json_tok_full(buf, &e[1]));
		else if (res == ADDRESS_PARSE_WRONG_NETWORK)
			return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
					    "'%s' address is not on network "
					    "%s: %.*s",
					    name,
					    chainparams->network_name,
					    json_tok_full_len(&e[1]),
					    json_tok_full(buf, &e[1]));

		if (!json_to_sat_or_all(buf, &e[2], &dest->amount))
			return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
					    "'%s' amount could not be "
					    "parsed: %.*s",
					    name,
					    json_tok_full_len(&e[2]),
					    json_tok_full(buf, &e[2]));

		dest->all = amount_sat_eq(dest->amount, AMOUNT_SAT(-1ULL));

		if (dest->all) {
			if (has_all)
				return command_fail(cmd,
						    JSONRPC2_INVALID_PARAMS,
						    "'%s' cannot have more "
						    "than one amount as "
						    "\"all\"",
						    name);
			has_all = true;
		}
	}

	return NULL;

err:
	return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
			    "'%s' should be a non-empty array of "
			    "'{\"address\": amount}' objects, "
			    "got %.*s",
			    name,
			    json_tok_full_len(t),
			    json_tok_full(buf, t));
}

static struct command_result *start_mw(struct multiwithdraw_command *mw);

static struct command_result *
json_multiwithdraw(struct command *cmd,
		   const char *buf,
		   const jsmntok_t *params)
{
	struct multiwithdraw_command *mw;

	mw = tal(cmd, struct multiwithdraw_command);

	if (!param(cmd, buf, params,
		   p_req("outputs", param_outputs_array, &mw->outputs),
		   p_opt("feerate", param_string, &mw->feerate),
		   p_opt_def("minconf", param_number, &mw->minconf, 1),
		   p_opt("utxos", param_string, &mw->utxos),
		   NULL))
		return command_param_failed();

	mw->cmd = cmd;
	assert(cmd->id);
	mw->id = *cmd->id;
	mw->psbt = NULL;

	if (!mw->feerate)
		mw->feerate = "normal";

	/* Check if there are any 'all' amounts.  */
	mw->has_all = false;
	for (size_t i = 0; i < tal_count(mw->outputs); ++i)
		if (mw->outputs[i].all)
			mw->has_all = true;
		else if (amount_sat_less(mw->outputs[i].amount,
					 chainparams->dust_limit))
			return command_fail(cmd, FUND_OUTPUT_IS_DUST,
					    "Output %s would be "
					    "dust.",
					    type_to_string(tmpctx,
							   struct amount_sat,
							   &mw->outputs[i].amount));

	/* Begin.  */
	return start_mw(mw);
}

/*-----------------------------------------------------------------------------
Error Handling
-----------------------------------------------------------------------------*/
/*~ We handle a PSBT, which actually represents a set of inputs that have
been reserved for our use.

Naturally, if we encounter an error somewhere in processing, we have to
back out of this by unreserving the inputs of the PSBT.

The most common is `all`-related: if it turns out that the `all` output
would be below the dust limit, we should not make the transaction (it
would not propagate across the network) and instead fail, but failure
should unreserve the inputs of the PSBT.
*/

struct multiwithdraw_cleanup {
	/* The multiwithdraw being cleaned up.  */
	struct multiwithdraw_command *mw;
	/* The complete error object, as a JSON-formatted string.  */
	char *error_json;
};

static struct command_result *
mw_after_cleanup(struct command *cmd UNUSED,
		 const char *buf UNUSED,
		 const jsmntok_t *result UNUSED,
		 struct multiwithdraw_cleanup *cleanup);

static struct command_result *
mw_perform_cleanup(struct multiwithdraw_command *mw,
		   char *error_json TAKES)
{
	struct multiwithdraw_cleanup *cleanup;
	struct out_req *req;

	if (!mw->psbt) {
		plugin_log(mw->cmd->plugin, LOG_DBG,
			   "multiwithdraw %"PRIu64": no cleanup needed.",
			   mw->id);
		if (taken(error_json))
			error_json = tal_steal(tmpctx, error_json);
		return command_err_raw(mw->cmd, error_json);
	}

	plugin_log(mw->cmd->plugin, LOG_DBG,
		   "multiwithdraw %"PRIu64": cleanup, unreserveinputs.",
		   mw->id);

	cleanup = tal(mw, struct multiwithdraw_cleanup);
	cleanup->mw = mw;
	cleanup->error_json = tal_strdup(cleanup, error_json);

	req = jsonrpc_request_start(mw->cmd->plugin,
				    mw->cmd,
				    "unreserveinputs",
				    &mw_after_cleanup, &mw_after_cleanup,
				    cleanup);
	json_add_psbt(req->js, "psbt", mw->psbt);
	return send_outreq(mw->cmd->plugin, req);
}
static struct command_result *
mw_after_cleanup(struct command *cmd UNUSED,
		 const char *buf UNUSED,
		 const jsmntok_t *result UNUSED,
		 struct multiwithdraw_cleanup *cleanup)
{
	struct multiwithdraw_command *mw = cleanup->mw;

	plugin_log(mw->cmd->plugin, LOG_DBG,
		   "multiwithdraw %"PRIu64": cleanup, unreserveinputs done.",
		   mw->id);

	return command_err_raw(mw->cmd, cleanup->error_json);
}

/* Use this instead of forward_error.  */
static struct command_result *
mw_forward_error(struct command *cmd UNUSED,
		 const char *buf,
		 const jsmntok_t *error,
		 struct multiwithdraw_command *mw)
{
	return mw_perform_cleanup(mw,
				  take(json_strdup(NULL, buf, error)));
}
/* Use this instead of command_fail.  */
static struct command_result *
mw_fail(struct multiwithdraw_command *mw, errcode_t code,
	const char *fmt, ...)
{
	va_list ap;
	char *message;
	struct json_stream *js;
	size_t len;
	const char *rawjson;

	va_start(ap, fmt);
	message = tal_vfmt(tmpctx, fmt, ap);
	va_end(ap);

	js = new_json_stream(tmpctx, mw->cmd, NULL);
	json_object_start(js, NULL);
	json_add_errcode(js, "code", code);
	json_add_string(js, "message", message);
	json_object_end(js);

	rawjson = json_out_contents(js->jout, &len);

	return mw_perform_cleanup(mw,
				  take(tal_strndup(NULL, rawjson, len)));
}

/*-----------------------------------------------------------------------------
Initiate Multiwithdraw
-----------------------------------------------------------------------------*/
/*~ The first thing we have to do is to get a starting PSBT.

We get this from either a `fundpsbt` command, or if any UTXOs were
specified, from a `utxopsbt` command.
*/

static struct command_result *
mw_after_fundpsbt(struct command *cmd,
		  const char *buf,
		  const jsmntok_t *result,
		  struct multiwithdraw_command *mw);

static struct command_result *start_mw(struct multiwithdraw_command *mw)
{
	size_t startweight;
	struct out_req *req;

	plugin_log(mw->cmd->plugin, LOG_DBG,
		   "multiwithdraw %"PRIu64": start.",
		   mw->id);

	startweight = bitcoin_tx_core_weight(1, tal_count(mw->outputs));
	for (size_t i = 0; i < tal_count(mw->outputs); ++i) {
		struct multiwithdraw_destination *dest;
		dest = &mw->outputs[i];
		startweight += bitcoin_tx_output_weight(
					tal_count(dest->script));
	}

	if (mw->utxos) {
		plugin_log(mw->cmd->plugin, LOG_DBG,
			   "multiwithdraw %"PRIu64": utxopsbt.",
			   mw->id);
		req = jsonrpc_request_start(mw->cmd->plugin,
					    mw->cmd,
					    "utxopsbt",
					    &mw_after_fundpsbt,
					    &mw_forward_error,
					    mw);
		json_add_bool(req->js, "reservedok", false);
		json_add_jsonstr(req->js, "utxos", mw->utxos);
	} else {
		plugin_log(mw->cmd->plugin, LOG_DBG,
			   "multiwithdraw %"PRIu64": fundpsbt.",
			   mw->id);
		req = jsonrpc_request_start(mw->cmd->plugin,
					    mw->cmd,
					    "fundpsbt",
					    &mw_after_fundpsbt,
					    &mw_forward_error,
					    mw);
		json_add_u32(req->js, "minconf", *mw->minconf);
	}
	json_add_bool(req->js, "reserve", true);
	if (mw->has_all)
		json_add_string(req->js, "satoshi", "all");
	else {
		struct amount_sat sum = AMOUNT_SAT(0);
		for (size_t i = 0; i < tal_count(mw->outputs); ++i)
			if (!amount_sat_add(&sum, sum, mw->outputs[i].amount))
				return mw_fail(mw,
					       FUND_CANNOT_AFFORD,
					       "Overflow in amount sum.");
		json_add_string(req->js, "satoshi",
				type_to_string(tmpctx, struct amount_sat,
					       &sum));
	}
	json_add_string(req->js, "feerate", mw->feerate);
	json_add_u64(req->js, "startweight", startweight);

	return send_outreq(mw->cmd->plugin, req);
}

/*-----------------------------------------------------------------------------
Analyze PSBT
-----------------------------------------------------------------------------*/
/*~ We got the result from fundpsbt/utxopsbt.
Now analyze it: extract the fields, determine what "all" means,
and see if we need to add a change output as well.  */

static struct command_result *
mw_get_change_addr(struct multiwithdraw_command *mw);
static struct command_result *
mw_load_outputs(struct multiwithdraw_command *mw);

static struct command_result *
mw_after_fundpsbt(struct command *cmd,
		  const char *buf,
		  const jsmntok_t *result,
		  struct multiwithdraw_command *mw)
{
	const jsmntok_t *field;
	u32 feerate_per_kw;
	u32 estimated_final_weight;
	struct amount_sat excess_sat;
	bool ok = true;

	/* Extract results.  */
	field = ok ? json_get_member(buf, result, "psbt") : NULL;
	ok = ok && field;
	mw->psbt = ok ? psbt_from_b64(mw,
				      buf + field->start,
				      field->end - field->start) : NULL;
	ok = ok && mw->psbt;

	field = ok ? json_get_member(buf, result, "feerate_per_kw") : NULL;
	ok = ok && field;
	ok = ok && json_to_number(buf, field, &feerate_per_kw);

	field = ok ? json_get_member(buf, result, "estimated_final_weight") : NULL;
	ok = ok && field;
	ok = ok && json_to_number(buf, field, &estimated_final_weight);

	field = ok ? json_get_member(buf, result, "excess_msat") : NULL;
	ok = ok && field;
	ok = ok && json_to_sat(buf, field, &excess_sat);

	if (!ok)
		plugin_err(mw->cmd->plugin,
			   "Unexpected result from fundpsbt/utxopsbt: %.*s",
			   json_tok_full_len(result),
			   json_tok_full(buf, result));

	plugin_log(mw->cmd->plugin, LOG_DBG,
		   "multiwithdraw %"PRIu64": %s done: %s.",
		   mw->id,
		   mw->utxos ? "utxopsbt" : "fundpsbt",
		   psbt_to_b64(tmpctx, mw->psbt));

	/* Handle 'all'.  */
	if (mw->has_all) {
		size_t all_index = SIZE_MAX;
		for (size_t i = 0; i < tal_count(mw->outputs); ++i) {
			if (mw->outputs[i].all) {
				all_index = i;
				continue;
			}
			if (!amount_sat_sub(&excess_sat, excess_sat,
					    mw->outputs[i].amount))
				return mw_fail(mw,
					       FUND_CANNOT_AFFORD,
					       "Insufficient funds.");
		}
		assert(all_index != SIZE_MAX);

		if (amount_sat_less(excess_sat, chainparams->dust_limit))
			return mw_fail(mw, FUND_OUTPUT_IS_DUST,
				       "Output 'all' %s would be dust.",
				       type_to_string(tmpctx,
						      struct amount_sat,
						      &excess_sat));

		/* Transfer the excess to the 'all' output.  */
		mw->outputs[all_index].amount = excess_sat;
		excess_sat = AMOUNT_SAT(0);
	}

	/* Handle any change output.  */
	mw->change_amount = change_amount(excess_sat, feerate_per_kw,
					  estimated_final_weight);
	mw->change_needed = !amount_sat_eq(mw->change_amount, AMOUNT_SAT(0));

	if (mw->change_needed)
		return mw_get_change_addr(mw);
	else
		return mw_load_outputs(mw);
}

/*-----------------------------------------------------------------------------
Get Change Address
-----------------------------------------------------------------------------*/
/*~ Most of the time we will be having a change output, so
we need to `newaddr` and get one.  */

static struct command_result *
mw_after_newaddr(struct command *cmd,
		 const char *buf,
		 const jsmntok_t *result,
		 struct multiwithdraw_command *mw);

static struct command_result *
mw_get_change_addr(struct multiwithdraw_command *mw)
{
	struct out_req *req;

	plugin_log(mw->cmd->plugin, LOG_DBG,
		   "multiwithdraw %"PRIu64": change output newaddr.",
		   mw->id);

	req = jsonrpc_request_start(mw->cmd->plugin, mw->cmd,
				    "newaddr",
				    &mw_after_newaddr, &mw_forward_error, mw);
	json_add_string(req->js, "addresstype", "bech32");
	return send_outreq(mw->cmd->plugin, req);
}

static struct command_result *
mw_after_newaddr(struct command *cmd,
		 const char *buf,
		 const jsmntok_t *result,
		 struct multiwithdraw_command *mw)
{
	const jsmntok_t *bech32tok;
	const u8 *script;

	bech32tok = json_get_member(buf, result, "bech32");
	if (!bech32tok
	 || json_to_address_scriptpubkey(mw, chainparams, buf, bech32tok,
					 &script) != ADDRESS_PARSE_SUCCESS)
		plugin_err(mw->cmd->plugin,
			   "Unexpected result from newaddr: %.*s",
			   json_tok_full_len(result),
			   json_tok_full(buf, result));

	plugin_log(mw->cmd->plugin, LOG_DBG,
		   "multiwithdraw %"PRIu64": change output: %.*s.",
		   mw->id,
		   json_tok_full_len(bech32tok),
		   json_tok_full(buf, bech32tok));

	/* Now add the change output.  */
	struct multiwithdraw_destination change;
	change.script = script;
	change.amount = mw->change_amount;
	change.all = false;
	change.is_to_external = false;

	tal_arr_expand(&mw->outputs, change);

	return mw_load_outputs(mw);
}

/*-----------------------------------------------------------------------------
PSBT Outputs Creation
-----------------------------------------------------------------------------*/
/*~ At this point we load our outputs into the PSBT.
The initial PSBT contains only the inputs and has no outputs.

We shuffle the order of the outputs by inserting at random points.
*/

static struct command_result *
mw_sign_and_send(struct multiwithdraw_command *mw);

static struct command_result *
mw_load_outputs(struct multiwithdraw_command *mw)
{
	/* Insert outputs at random locations.  */
	for (size_t i = 0; i < tal_count(mw->outputs); ++i) {
		struct wally_psbt_output *out;
		/* There are already `i` outputs at this point,
		 * select from 0 to `i` inclusive, with 0 meaning
		 * "before first output" and `i` meaning "after
		 * last output".  */
		size_t point = pseudorand(i + 1);
		out = psbt_insert_output(mw->psbt,
					 mw->outputs[i].script,
					 mw->outputs[i].amount,
					 point);
		if (mw->outputs[i].is_to_external)
			psbt_output_mark_as_external(mw->psbt, out);
	}

	if (chainparams->is_elements) {
		struct amount_sat sum = AMOUNT_SAT(0);
		/* Elements transactions have a fee output.
		 * Bitcoin assumes fee = inputs - outputs, so just
		 * do that here.  */
		for (size_t i = 0; i < mw->psbt->num_inputs; ++i)
			if (!amount_sat_add(&sum, sum,
					    psbt_input_get_amount(mw->psbt,
								  i)))
				plugin_err(mw->cmd->plugin,
					   "Overflow in summing inputs.");
		for (size_t i = 0; i < mw->psbt->num_outputs; ++i)
			if (!amount_sat_sub(&sum, sum,
					    psbt_output_get_amount(mw->psbt,
								   i))) {
				/* Not enough already.  */
				sum = AMOUNT_SAT(0);
				break;
			}

		/* We always add this at the end.
		 * The fee output is fairly obvious --- it is
		 * the one without a SCRIPT --- so it is actually
		 * pointless to shuffle it with the rest of the
		 * outputs, since it will never fool chain analysis.  */
		if (!amount_sat_eq(sum, AMOUNT_SAT(0)))
			psbt_append_output(mw->psbt,
					   NULL,
					   sum);
	}

	return mw_sign_and_send(mw);
}

/*-----------------------------------------------------------------------------
Sign and Send PSBT
-----------------------------------------------------------------------------*/
/*~ Perform `signpsbt` followed by `sendpsbt`.  */

static struct command_result *
mw_after_signpsbt(struct command *cmd,
		  const char *buf,
		  const jsmntok_t *result,
		  struct multiwithdraw_command *mw);

static struct command_result *
mw_sign_and_send(struct multiwithdraw_command *mw)
{
	struct out_req *req;

	plugin_log(mw->cmd->plugin, LOG_DBG,
		   "multiwithdraw %"PRIu64": signpsbt.", mw->id);

	req = jsonrpc_request_start(mw->cmd->plugin, mw->cmd,
				    "signpsbt",
				    &mw_after_signpsbt,
				    &mw_forward_error,
				    mw);
	json_add_psbt(req->js, "psbt", mw->psbt);
	return send_outreq(mw->cmd->plugin, req);
}

static struct command_result *
mw_after_signpsbt(struct command *cmd,
		  const char *buf,
		  const jsmntok_t *result,
		  struct multiwithdraw_command *mw)
{
	const jsmntok_t *signed_psbttok;
	struct wally_psbt *psbt;
	bool ok = true;
	struct out_req *req;

	signed_psbttok = ok ? json_get_member(buf, result, "signed_psbt") : NULL;
	ok = ok && signed_psbttok;
	psbt = ok ? psbt_from_b64(mw,
				  buf + signed_psbttok->start,
				  signed_psbttok->end - signed_psbttok->start) : NULL;
	ok = ok && psbt;

	if (!ok)
		plugin_err(mw->cmd->plugin,
			   "Unexpected result from signpsbt: %.*s",
			   json_tok_full_len(result),
			   json_tok_full(buf, result));

	/* Substitute the PSBT.  */
	tal_free(mw->psbt);
	mw->psbt = psbt;

	/* Perform sendpsbt.  */
	plugin_log(mw->cmd->plugin, LOG_DBG,
		   "multiwithdraw: %"PRIu64": sendpsbt.", mw->id);

	req = jsonrpc_request_start(mw->cmd->plugin,
				    mw->cmd,
				    "sendpsbt",
				    &forward_result,
				    /* Properly speaking, if `sendpsbt` fails,
				     * we should assume an edge case where the
				     * the transaction was sent to *some*
				     * mempool (from where it *could* get
				     * propagated to miners), but confirmation
				     * that it got into *some* mempool was not
				     * received.
				     */
				    &mw_forward_error,
				    mw);
	json_add_psbt(req->js, "psbt", mw->psbt);
	return send_outreq(mw->cmd->plugin, req);
}
