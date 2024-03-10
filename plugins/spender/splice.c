#include "config.h"
#include <bitcoin/psbt.h>
#include <bitcoin/script.h>
#include <ccan/array_size/array_size.h>
#include <ccan/err/err.h>
#include <ccan/tal/str/str.h>
#include <ccan/tal/tal.h>
#include <common/json_param.h>
#include <common/json_parse.h>
#include <common/json_stream.h>
#include <common/psbt_open.h>
#include <common/splice_script.h>
#include <common/type_to_string.h>
#include <plugins/spender/splice.h>

struct abort_pkg {
	struct splice_cmd *splice_cmd;
	enum jsonrpc_errcode code;
	char *str;
};

static void debug_log_to_json(struct json_stream *response,
			      const char *debug_log)
{
	char **lines = tal_strsplit(tmpctx, debug_log, "\n", STR_NO_EMPTY);

	for (size_t i = 0; lines[i]; i++)
		json_add_string(response, NULL, lines[i]);
}

static struct command_result *make_error(struct command *cmd,
					 struct abort_pkg *abort_pkg,
					 const char *phase)
{
	struct splice_cmd *splice_cmd = abort_pkg->splice_cmd;
	char *str = abort_pkg->str;
	struct json_stream *response = jsonrpc_stream_fail(cmd,
							   abort_pkg->code,
							   str ?: phase);

	if (splice_cmd->debug_log) {
		json_array_start(response, "log");
		debug_log_to_json(response, splice_cmd->debug_log);
		json_array_end(response);
	}

	tal_free(abort_pkg);

	return command_finished(cmd, response);
}

static struct command_result *unreserve_get_result(struct command *cmd,
						   const char *buf,
						   const jsmntok_t *result,
						   struct abort_pkg *abort_pkg)
{
	struct splice_cmd *splice_cmd = abort_pkg->splice_cmd;
	struct json_stream *response;
	struct bitcoin_tx *tx;
	u8 *tx_bytes;

	if (splice_cmd->wetrun) {

		response = jsonrpc_stream_success(cmd);
		if (splice_cmd->psbt) {
			json_add_psbt(response, "psbt", splice_cmd->psbt);

			tx = bitcoin_tx_with_psbt(tmpctx, splice_cmd->psbt);
			tx_bytes = linearize_tx(tmpctx, tx);
			json_add_hex(response, "tx", tx_bytes,
				     tal_bytelen(tx_bytes));
			json_add_txid(response, "txid",
				      &splice_cmd->final_txid);
		}

		json_array_start(response, "log");
		debug_log_to_json(response, splice_cmd->debug_log);
		json_array_end(response);

		tal_free(abort_pkg);
		return command_finished(cmd, response);
	}

	return make_error(cmd, abort_pkg, "unreserve_get_result");
}

static struct command_result *abort_get_result(struct command *cmd,
					       const char *buf,
					       const jsmntok_t *result,
					       struct abort_pkg *abort_pkg)
{
	struct out_req *req;
	struct splice_cmd *splice_cmd = abort_pkg->splice_cmd;

	plugin_log(cmd->plugin, LOG_DBG,
		   "unreserveinputs(psbt:%p)", splice_cmd->psbt);

	if (!splice_cmd->psbt)
		return make_error(cmd, abort_pkg, "abort_get_result");

	req = jsonrpc_request_start(cmd->plugin, cmd, "unreserveinputs",
				    unreserve_get_result, forward_error,
				    abort_pkg);

	json_add_psbt(req->js, "psbt", splice_cmd->psbt);

	return send_outreq(cmd->plugin, req);
}

static struct command_result *do_fail(struct command *cmd,
				      struct splice_cmd *splice_cmd,
				      enum jsonrpc_errcode code,
				      char *str)
{
	struct out_req *req;
	struct abort_pkg *abort_pkg;
	size_t added;

	/* If we encounter an error, wetrun is canceled */
	splice_cmd->wetrun = false;

	plugin_log(cmd->plugin, LOG_DBG,
		   "splice_error(psbt:%p, splice_cmd_stat:%p)",
		   splice_cmd->psbt, splice_cmd);

	abort_pkg = tal(cmd->plugin, struct abort_pkg);
	abort_pkg->splice_cmd = tal_steal(abort_pkg, splice_cmd);
	abort_pkg->str = tal_strdup(abort_pkg, str);
	abort_pkg->code = code;

	req = jsonrpc_request_start(cmd->plugin, cmd, "abort_channels",
				    abort_get_result, forward_error, abort_pkg);

	added = 0;
	json_array_start(req->js, "channel_ids");
	for (size_t i = 0; i < tal_count(splice_cmd->actions); i++) {
		if (splice_cmd->actions[i]->channel_id) {
			added++;
			json_add_channel_id(req->js, NULL,
					    splice_cmd->actions[i]->channel_id);
		}
	}
	json_array_end(req->js);

	if (!added) {
		plugin_log(cmd->plugin, LOG_DBG,
			   "No channels were stfu'ed, skipping to unreserve"
			   " (psbt:%p)", splice_cmd->psbt);
		return abort_get_result(cmd, NULL, NULL, abort_pkg);
	}

	return send_outreq(cmd->plugin, req);
}

static struct command_result *splice_error(struct command *cmd,
					   const char *buf,
					   const jsmntok_t *error,
					   struct splice_cmd *splice_cmd)
{
	char *str = tal_strndup(cmd, buf + error->start,
			      error->end - error->start);

	return do_fail(cmd, splice_cmd, JSONRPC2_INVALID_PARAMS, str);
}

struct splice_index_pkg {
	struct splice_cmd *splice_cmd;
	size_t index;
};

static struct command_result *splice_error_pkg(struct command *cmd,
					       const char *buf,
					       const jsmntok_t *error,
					       struct splice_index_pkg *pkg)
{
	return splice_error(cmd, buf, error, pkg->splice_cmd);
}

static struct command_result *calc_in_ppm_and_fee(struct command *cmd,
						  struct splice_cmd *splice_cmd,
						  struct amount_sat onchain_fee)
{
	struct splice_script_result *action;
	struct amount_sat out_sats = splice_cmd->initial_funds;
	bool is_any_paying_fee = false;

	/* First add all sats going into general fund */
	for (size_t i = 0; i < tal_count(splice_cmd->actions); i++) {
		action = splice_cmd->actions[i];
		if (action->pays_fee)
			is_any_paying_fee = true;
		if (!amount_sat_add(&out_sats, out_sats, action->out_sat))
			return do_fail(cmd, splice_cmd, JSONRPC2_INVALID_PARAMS,
					    "Unable to add out_sats");
		if (action->out_ppm)
			return do_fail(cmd, splice_cmd, JSONRPC2_INVALID_PARAMS,
					    "Unable to resolve out_ppm");
	}

	/* Now take away all sats being spent by general fund */
	for (size_t i = 0; i < tal_count(splice_cmd->actions); i++) {
		action = splice_cmd->actions[i];
		if (!amount_sat_sub(&out_sats, out_sats, action->in_sat))
			return do_fail(cmd, splice_cmd, JSONRPC2_INVALID_PARAMS,
					    "Unable to sub out_sats");
	}

	/* If no one voulenteers to pay the fee, we take it out of the general
	 * fund. */
	if (!is_any_paying_fee) {
		if (!amount_sat_sub(&out_sats, out_sats, onchain_fee))
			return do_fail(cmd, splice_cmd, JSONRPC2_INVALID_PARAMS,
				       tal_fmt(tmpctx,
					       "Unable to take onchain fee %s"
					       " fromm  general funds of %s",
					       fmt_amount_sat(tmpctx, onchain_fee),
					       fmt_amount_sat(tmpctx, out_sats)));
	}

	for (size_t i = 0; i < tal_count(splice_cmd->actions); i++) {
		action = splice_cmd->actions[i];
		if (action->in_ppm) {
			/* ppm percentage calculation:
			 * action->in_sat = out_sats * in_ppm / 1000000 */
			if (!amount_sat_mul(&action->in_sat, out_sats, action->in_ppm))
				return do_fail(cmd, splice_cmd, JSONRPC2_INVALID_PARAMS,
						    "Unable to mul sats & in_ppm");
			action->in_sat = amount_sat_div(action->in_sat, 1000000);
			action->in_ppm = 0;
		}

		/* If this item pays the fee, subtract it from either their
		 * in_sats or out_sats. */
		if (action->pays_fee && !amount_sat_zero(action->in_sat)) {
			if (!amount_sat_sub(&action->in_sat, action->in_sat,
					    onchain_fee))
				return do_fail(cmd, splice_cmd,
						    JSONRPC2_INVALID_PARAMS,
						    "Unable to sub fee from"
						    " item in_sat");
		}
		if (action->pays_fee && !amount_sat_zero(action->out_sat)) {
			if (!amount_sat_add(&action->out_sat, action->out_sat,
					    onchain_fee))
				return do_fail(cmd, splice_cmd,
						    JSONRPC2_INVALID_PARAMS,
						    "Unable to sub fee from"
						    " item out_sat");
		}
	}

	/*  validate result */
	for (size_t i = 0; i < tal_count(splice_cmd->actions); i++) {
		action = splice_cmd->actions[i];
		if (!action->channel_id)
			continue;
		if (!amount_sat_zero(action->in_sat))
			continue;
		if (!amount_sat_zero(action->out_sat))
			continue;
		if (!amount_sat_zero(action->lease_sat))
			continue;
		return do_fail(cmd, splice_cmd, JSONRPC2_INVALID_PARAMS,
				    "Each channel action must include non-zero"
				    " in sats, out sats, or lease sats.");
	}

	return NULL;
}

static struct command_result *continue_splice(struct command *cmd,
					      struct splice_cmd *splice_cmd);

static bool json_to_msat_to_sat(const char *buffer, const jsmntok_t *tok,
				struct amount_sat *sat)
{
	struct amount_msat msat;

	if (!json_to_msat(buffer, tok, &msat))
		return false;
	return amount_msat_to_sat(sat, msat);
}

static struct splice_script_result *output_wallet(struct splice_cmd *splice_cmd)
{
	for (size_t i = 0; i < tal_count(splice_cmd->actions); i++) {
		struct splice_script_result *action = splice_cmd->actions[i];
		if (!action->onchain_wallet)
			continue;
		if (action->in_ppm || !amount_sat_zero(action->in_sat))
			return action;
	}
	return NULL;
}

static struct command_result *addpsbt_get_result(struct command *cmd,
			const char *buf,
			const jsmntok_t *result,
			struct splice_index_pkg *pkg)
{
	struct splice_cmd *splice_cmd = pkg->splice_cmd;
	size_t index = pkg->index;
	struct splice_script_result *action = splice_cmd->actions[index];
	const jsmntok_t *tok;
	struct amount_sat excess_sat;
	struct splice_script_result *out_wallet;

	tal_free(pkg);
	tok = json_get_member(buf, result, "psbt");

	tal_free(splice_cmd->psbt);
	splice_cmd->psbt = json_to_psbt(splice_cmd, buf, tok);
	assert(splice_cmd->psbt);

	tok = json_get_member(buf, result, "excess_msat");
	if (tok) {
		if (!json_to_msat_to_sat(buf, tok, &excess_sat))
			return command_fail_badparam(cmd, "addpsbt", buf, tok,
						     "invalid excess_msat");

		if (!amount_sat_zero(excess_sat)) {
			if (!amount_sat_add(&action->out_sat, action->out_sat,
					   excess_sat))
				return do_fail(cmd, splice_cmd,
					       JSONRPC2_INVALID_PARAMS,
					       "Unable to add excess sats");

			out_wallet = output_wallet(splice_cmd);
			if (out_wallet) {
				if (!out_wallet->in_ppm
				     && !amount_sat_add(&out_wallet->in_sat,
						       out_wallet->in_sat,
						       excess_sat))
					return do_fail(cmd, splice_cmd,
						       JSONRPC2_INVALID_PARAMS,
						       "Unable to add excess"
						       " sats to existing"
						       " wallet output");
			}
			else {
				return do_fail(cmd, splice_cmd,
					       JSONRPC2_INVALID_PARAMS,
					       "Putting change back into same"
					       " wallet outpoint not yet"
					       " supported");
			}
		}
	}

	tok = json_get_member(buf, result, "emergency_sat");
	if (tok) {
		if (!amount_sat_zero(splice_cmd->emergency_sat))
			return do_fail(cmd, splice_cmd, JSONRPC2_INVALID_PARAMS,
					    "Internal error: two"
					    " emergency_sat");
		if (!json_to_msat_to_sat(buf, tok, &splice_cmd->emergency_sat))
			return command_fail_badparam(cmd, "addpsbt", buf, tok,
						     "invalid emergency_sat");
	}

	return continue_splice(splice_cmd->cmd, splice_cmd);
}

static struct command_result *onchain_wallet_fund(struct command *cmd,
						  struct splice_cmd *splice_cmd,
						  size_t index)
{
	struct splice_script_result *action = splice_cmd->actions[index];
	struct splice_cmd_action_state *state = splice_cmd->states[index];
	struct out_req *req;
	struct splice_index_pkg *pkg;
	const char *command;

	pkg = tal(cmd->plugin, struct splice_index_pkg);
	pkg->splice_cmd = splice_cmd;
	pkg->index = index;

	command = "addpsbtoutput";
	if (!amount_sat_zero(action->out_sat)) {
		command = "addpsbtinput";
		splice_cmd->wallet_inputs_to_signed++;
		/* DTODO track which specific inputs are added and only sign
		 * those */
	}

	req = jsonrpc_request_start(cmd->plugin, cmd, command,
				    addpsbt_get_result,
				    splice_error_pkg, pkg);

	if (!amount_sat_zero(action->out_sat)) {
		json_add_sats(req->js, "satoshi", action->out_sat);
		assert(splice_cmd->feerate_per_kw);
		json_add_u32(req->js, "min_feerate", splice_cmd->feerate_per_kw);
	}
	else {
		json_add_sats(req->js, "satoshi", action->in_sat);
	}

	json_add_psbt(req->js, "initialpsbt", splice_cmd->psbt);
	json_add_bool(req->js, "add_initiator_serial_ids", true);

	state->state = SPLICE_CMD_DONE;

	return send_outreq(cmd->plugin, req);
}

static struct command_result *feerate_get_result(struct command *cmd,
			const char *buf,
			const jsmntok_t *result,
			struct splice_cmd *splice_cmd)
{
	const jsmntok_t *tok = json_get_member(buf, result, "perkw");
	tok = json_get_member(buf, tok, "opening");

	if (!json_to_u32(buf, tok, &splice_cmd->feerate_per_kw))
		return command_fail_badparam(cmd, "opening", buf,
					     tok, "invalid u32");

	if (!splice_cmd->feerate_per_kw)
		return command_fail(splice_cmd->cmd,
					 JSONRPC2_INVALID_PARAMS,
					 "Failed to load a default feerate");

	plugin_log(cmd->plugin, LOG_DBG,
		   "got feerate %"PRIu32" perkw", splice_cmd->feerate_per_kw);

	return continue_splice(splice_cmd->cmd, splice_cmd);
}

static struct command_result *load_feerate(struct command *cmd,
					   struct splice_cmd *splice_cmd)
{
	struct out_req *req;

	req = jsonrpc_request_start(cmd->plugin, cmd, "feerates",
				    feerate_get_result, splice_error,
				    splice_cmd);

	json_add_string(req->js, "style", "perkw");

	return send_outreq(cmd->plugin, req);
}

static size_t calc_weight(struct splice_cmd *splice_cmd,
			  bool simulate_wallet_outputs)
{
	struct splice_script_result *action;
	struct wally_psbt *psbt = splice_cmd->psbt;
	size_t weight = 0;
	size_t extra_inputs = 0;
	size_t extra_outputs = 0;

	/* BOLT-0d8b701614b09c6ee4172b04da2203e73deec7e2 #2:
	 * Each node:
	 * - MUST pay for their own added inputs and outputs.
	 */
	for (size_t i = 0; i < psbt->num_inputs; i++)
		weight += psbt_input_get_weight(psbt, i);

	for (size_t i = 0; i < psbt->num_outputs; i++)
		weight += psbt_output_get_weight(psbt, i);

	/* Count the splice input & outputs manually */
	for (size_t i = 0; i < tal_count(splice_cmd->actions); i++) {
		action = splice_cmd->actions[i];
		if (simulate_wallet_outputs && action->onchain_wallet) {
			if (!amount_sat_zero(action->in_sat) || action->in_ppm) {
				weight += bitcoin_tx_output_weight(BITCOIN_SCRIPTPUBKEY_P2TR_LEN);
				extra_outputs++;
			}

		} else if (splice_cmd->actions[i]->channel_id) {
			weight += bitcoin_tx_output_weight(BITCOIN_SCRIPTPUBKEY_P2WSH_LEN);
			weight += bitcoin_tx_input_weight(true,
							  bitcoin_tx_2of2_input_witness_weight());
			extra_inputs++;
			extra_outputs++;
		}
	}
	/* DTODO make a test to confirm weight calculation is correct */

	/* BOLT-0d8b701614b09c6ee4172b04da2203e73deec7e2 #2:
	 * The initiator:
	 *   ...
	 * - MUST pay for the common fields.
	 */
	weight += bitcoin_tx_core_weight(psbt->num_inputs + extra_inputs,
					 psbt->num_outputs + extra_outputs);

	return weight;
}

static struct command_result *splice_init_get_result(struct command *cmd,
			    const char *buf,
			    const jsmntok_t *result,
			    struct splice_cmd *splice_cmd)
{
	const jsmntok_t *tok = json_get_member(buf, result, "psbt");

	tal_free(splice_cmd->psbt);
	splice_cmd->psbt = json_to_psbt(splice_cmd, buf, tok);

	return continue_splice(splice_cmd->cmd, splice_cmd);
}

static struct command_result *splice_init(struct command *cmd,
					  struct splice_cmd *splice_cmd,
					  size_t index)
{
	struct splice_script_result *action = splice_cmd->actions[index];
	struct splice_cmd_action_state *state = splice_cmd->states[index];
	struct out_req *req;

	req = jsonrpc_request_start(cmd->plugin, cmd, "splice_init",
				    splice_init_get_result, splice_error,
				    splice_cmd);

	json_add_channel_id(req->js, "channel_id", action->channel_id);
	if (!amount_sat_zero(action->in_sat)) {
		json_add_u64(req->js, "relative_amount",
			     action->in_sat.satoshis);  /* Raw: signed RPC */
	} else if (!amount_sat_zero(action->out_sat)) {
		json_add_string(req->js, "relative_amount",
				tal_fmt(req->js, "-%"PRIu64,
					action->out_sat.satoshis)); /* Raw: signed RPC */
	} else {
		json_add_sats(req->js, "relative_amount", amount_sat(0));
	}
	json_add_psbt(req->js, "initialpsbt", splice_cmd->psbt);
	json_add_u32(req->js, "feerate_per_kw", splice_cmd->feerate_per_kw);
	json_add_bool(req->js, "skip_stfu", true);
	json_add_bool(req->js, "force_feerate", splice_cmd->force_feerate);

	state->state = SPLICE_CMD_INIT;

	return send_outreq(cmd->plugin, req);
}

static struct command_result *splice_update_get_result(struct command *cmd,
			      const char *buf,
			      const jsmntok_t *result,
			      struct splice_index_pkg *pkg)
{
	size_t index = pkg->index;
	struct splice_cmd *splice_cmd = pkg->splice_cmd;
	struct splice_cmd_action_state *state = splice_cmd->states[index];
	const jsmntok_t *tok;
	struct wally_psbt *psbt;
	enum splice_cmd_state old_state = state->state;
	bool got_sigs;

	tal_free(pkg);

	/* DTODO: juggle serial ids correctly for cross-channel splice */
	tok = json_get_member(buf, result, "psbt");
	psbt = json_to_psbt(splice_cmd, buf, tok);

	if (psbt_contribs_changed(splice_cmd->psbt, psbt))
		for (size_t i = 0; i < tal_count(splice_cmd->states); i++)
			if (splice_cmd->actions[i]->channel_id)
				splice_cmd->states[i]->state = SPLICE_CMD_UPDATE_NEEDS_CHANGES;

	assert(psbt);
	tal_free(splice_cmd->psbt);
	splice_cmd->psbt = tal_steal(splice_cmd, psbt);

	tok = json_get_member(buf, result, "signatures_secured");
	if (!json_to_bool(buf, tok, &got_sigs))
		return command_fail_badparam(cmd, "signatures_secured", buf,
					     tok, "invalid bool");

	if (old_state != SPLICE_CMD_UPDATE)
		state->state = SPLICE_CMD_UPDATE;
	else
		state->state = got_sigs ? SPLICE_CMD_UPDATE_DONE : SPLICE_CMD_RECVED_SIGS;

	return continue_splice(splice_cmd->cmd, splice_cmd);
}

static struct command_result *splice_update(struct command *cmd,
					    struct splice_cmd *splice_cmd,
					    size_t index)
{
	struct splice_script_result *action = splice_cmd->actions[index];
	struct out_req *req;
	struct splice_index_pkg *pkg = tal(cmd->plugin, struct splice_index_pkg);

	pkg->splice_cmd = splice_cmd;
	pkg->index = index;

	plugin_log(cmd->plugin, LOG_DBG,
		   "splice_update(channel_id:%s)",
		   type_to_string(tmpctx, struct channel_id,
		   		  action->channel_id));

	req = jsonrpc_request_start(cmd->plugin, cmd, "splice_update",
				    splice_update_get_result, splice_error_pkg,
				    pkg);

	json_add_channel_id(req->js, "channel_id", action->channel_id);
	json_add_psbt(req->js, "psbt", splice_cmd->psbt);

	return send_outreq(cmd->plugin, req);
}

static struct command_result *signpsbt_get_result(struct command *cmd,
						  const char *buf,
						  const jsmntok_t *result,
						  struct splice_cmd *splice_cmd)
{
	const jsmntok_t *tok = json_get_member(buf, result, "signed_psbt");
	struct channel_id *channel_ids;

	tal_free(splice_cmd->psbt);

	splice_cmd->psbt = json_to_psbt(splice_cmd, buf, tok);
	splice_cmd->wallet_inputs_to_signed = 0;

	/* After signing we add channel_ids to the PSBT for splice_signed */
	channel_ids = tal_arr(NULL, struct channel_id, 0);
	for (size_t i = 0; i < tal_count(splice_cmd->actions); i++)
		if (splice_cmd->actions[i]->channel_id)
			tal_arr_expand(&channel_ids,
				       *splice_cmd->actions[i]->channel_id);

	psbt_set_channel_ids(splice_cmd->psbt, channel_ids);
	tal_free(channel_ids);

	return continue_splice(splice_cmd->cmd, splice_cmd);
}

static struct command_result *signpsbt(struct command *cmd,
				       struct splice_cmd *splice_cmd)
{
	struct out_req *req;

	req = jsonrpc_request_start(cmd->plugin, cmd, "signpsbt",
				    signpsbt_get_result, splice_error,
				    splice_cmd);

	/* TODO: add the inputs indices we should sign */
	json_add_psbt(req->js, "psbt", splice_cmd->psbt);

	splice_cmd->wallet_inputs_to_signed = 0;

	return send_outreq(cmd->plugin, req);
}

static struct splice_script_result *requires_our_sigs(struct splice_cmd *splice_cmd,
						      size_t *index)
{
	struct splice_script_result *action = NULL;
	*index = UINT32_MAX;
	for (size_t i = 0; i < tal_count(splice_cmd->actions); i++) {
		if (splice_cmd->states[i]->state == SPLICE_CMD_UPDATE_DONE) {
			/* There can only be one node that requires our sigs */
			assert(!action);
			action = splice_cmd->actions[i];
			*index = i;
		}
	}
	return action;
}

static struct command_result *splice_signed_get_result(struct command *cmd,
			      const char *buf,
			      const jsmntok_t *result,
			      struct splice_index_pkg *pkg)
{
	size_t index = pkg->index;
	struct splice_cmd *splice_cmd = pkg->splice_cmd;
	const jsmntok_t *tok;

	tal_free(pkg);

	tok = json_get_member(buf, result, "psbt");
	tal_free(splice_cmd->psbt);
	splice_cmd->psbt = json_to_psbt(splice_cmd, buf, tok);

	tok = json_get_member(buf, result, "txid");
	if (!json_to_txid(buf, tok, &splice_cmd->final_txid))
		return command_fail_badparam(cmd, "txid", buf,
					     tok, "invalid txid");

	splice_cmd->states[index]->state = SPLICE_CMD_DONE;

	return continue_splice(splice_cmd->cmd, splice_cmd);
}

static struct command_result *splice_signed(struct command *cmd,
					    struct splice_cmd *splice_cmd,
					    size_t index)
{
	struct splice_script_result *action = splice_cmd->actions[index];
	struct out_req *req;
	struct splice_index_pkg *pkg;

	pkg = tal(cmd->plugin, struct splice_index_pkg);
	pkg->splice_cmd = splice_cmd;
	pkg->index = index;

	req = jsonrpc_request_start(cmd->plugin, cmd, "splice_signed",
				    splice_signed_get_result, splice_error_pkg,
				    pkg);

	json_add_channel_id(req->js, "channel_id", action->channel_id);
	json_add_psbt(req->js, "psbt", splice_cmd->psbt);

	return send_outreq(cmd->plugin, req);
}

static struct command_result *check_emergency_sat(struct command *cmd,
						  struct splice_cmd *splice_cmd)
{
	struct amount_sat to_wallet = AMOUNT_SAT(0);
	if (amount_sat_zero(splice_cmd->emergency_sat))
		return NULL;

	for (size_t i = 0; i < tal_count(splice_cmd->actions); i++) {
		struct splice_script_result *action = splice_cmd->actions[i];
		if (action->onchain_wallet)
			if (!amount_sat_add(&to_wallet, to_wallet,
					    action->in_sat))
				return do_fail(cmd, splice_cmd,
						    JSONRPC2_INVALID_PARAMS,
						    "Unable to amount_sat_add"
						    " wallet amounts for"
						    " emergency_sat calc");
	}

	if (!amount_sat_greater_eq(to_wallet, splice_cmd->emergency_sat))
		return do_fail(cmd, splice_cmd, JSONRPC2_INVALID_PARAMS,
			       tal_fmt(tmpctx,
				       "Amount going to onchain wallet %s is"
				       " not enough to meet the emergency"
				       " minimum of %s",
				       fmt_amount_sat(tmpctx, to_wallet),
				       fmt_amount_sat(tmpctx, splice_cmd->emergency_sat)));

	return NULL;
}

static const char *cmd_state_string(enum splice_cmd_state state)
{
	switch (state) {
		case SPLICE_CMD_NONE:
			return "                    ";
		case SPLICE_CMD_INIT:
			return "        INIT        ";
		case SPLICE_CMD_UPDATE:
			return "       UPDATE       ";
		case SPLICE_CMD_UPDATE_NEEDS_CHANGES:
			return "UPDATE_NEEDS_CHANGES";
		case SPLICE_CMD_UPDATE_DONE:
			return "     UPDATE_DONE    ";
		case SPLICE_CMD_RECVED_SIGS:
			return "     RECVED_SIGS    ";
		case SPLICE_CMD_DONE:
			return "        DONE        ";
	}
	return NULL;
}

static void add_to_debug_log(struct splice_cmd *scmd, const char *phase)
{
	char **log = &scmd->debug_log;
	if (!*log)
		return;

	tal_append_fmt(log, "#%d: (%s)\n", ++scmd->debug_counter, phase);

	for (size_t i = 0; i < tal_count(scmd->actions); i++) {
		struct splice_script_result *action = scmd->actions[i];
		struct splice_cmd_action_state *state = scmd->states[i];

		tal_append_fmt(log, "[%s] %s\n",
			       cmd_state_string(state->state),
			       splice_to_string(tmpctx, &action, 1));
	}
}

static struct command_result *handle_wetrun(struct command *cmd,
					    struct splice_cmd *splice_cmd)
{
	struct out_req *req;
	struct abort_pkg *abort_pkg;
	size_t added;

	abort_pkg = tal(cmd->plugin, struct abort_pkg);
	abort_pkg->splice_cmd = tal_steal(abort_pkg, splice_cmd);
	abort_pkg->str = NULL;

	req = jsonrpc_request_start(cmd->plugin, cmd, "abort_channels",
				    abort_get_result, forward_error, abort_pkg);

	added = 0;
	json_array_start(req->js, "channel_ids");
	for (size_t i = 0; i < tal_count(splice_cmd->actions); i++) {
		if (splice_cmd->actions[i]->channel_id) {
			added++;
			json_add_channel_id(req->js, NULL,
					    splice_cmd->actions[i]->channel_id);
		}
	}
	json_array_end(req->js);

	if (!added)
		return unreserve_get_result(cmd, NULL, NULL, abort_pkg);

	return send_outreq(cmd->plugin, req);
}

static struct command_result *continue_splice(struct command *cmd,
					      struct splice_cmd *splice_cmd)
{
	struct splice_script_result *action;
	struct splice_cmd_action_state *state;
	struct command_result *result;
	size_t index;
	size_t weight;
	struct amount_sat onchain_fee;

	add_to_debug_log(splice_cmd, "continue_splice");

	if (!splice_cmd->feerate_per_kw)
		return load_feerate(cmd, splice_cmd);

	/* On first pass we add wallet actions that contribute funds */
	for (size_t i = 0; i < tal_count(splice_cmd->actions); i++) {
		action = splice_cmd->actions[i];
		state = splice_cmd->states[i];
		if (state->state != SPLICE_CMD_NONE)
			continue;
		if (splice_cmd->actions[i]->onchain_wallet
			&& !amount_sat_zero(splice_cmd->actions[i]->out_sat)) {
			state->state = SPLICE_CMD_DONE;
			return onchain_wallet_fund(cmd, splice_cmd, i);
		}
	}

	if (!splice_cmd->fee_calculated) {
		splice_cmd->fee_calculated = true;

		/* We calculate the weight simulator wallet outputs */
		weight = calc_weight(splice_cmd, true);
		onchain_fee = amount_tx_fee(splice_cmd->feerate_per_kw, weight);

		plugin_log(cmd->plugin, LOG_INFORM,
			   "Splice fee is %s at %"PRIu32" perkw (%.02f sat/vB) "
			   "on tx where our personal bytes are %.02f",
			   fmt_amount_sat(tmpctx, onchain_fee),
			   splice_cmd->feerate_per_kw,
			   4 * splice_cmd->feerate_per_kw / 1000.0f,
			   weight / 4.0f);

		result = calc_in_ppm_and_fee(cmd, splice_cmd, onchain_fee);
		if (result)
			return result;
	}

	/* Only after fee calcualtion can we add wallet actions taking funds */
	for (size_t i = 0; i < tal_count(splice_cmd->actions); i++) {
		action = splice_cmd->actions[i];
		state = splice_cmd->states[i];
		if (state->state != SPLICE_CMD_NONE)
			continue;
		if (splice_cmd->actions[i]->onchain_wallet
			&& !amount_sat_zero(splice_cmd->actions[i]->in_sat)) {
			state->state = SPLICE_CMD_DONE;
			return onchain_wallet_fund(cmd, splice_cmd, i);
		}
	}

	result = check_emergency_sat(cmd, splice_cmd);
	if (result)
		return result;

	for (size_t i = 0; i < tal_count(splice_cmd->actions); i++) {
		action = splice_cmd->actions[i];
		state = splice_cmd->states[i];
		if (state->state != SPLICE_CMD_NONE)
			continue;
		if (!action->channel_id)
			return do_fail(cmd, splice_cmd, JSONRPC2_INVALID_PARAMS,
					    "Internal error; should not get"
					    " here with non-channels with state"
					    " NONE");
		return splice_init(cmd, splice_cmd, i);
	}

	for (size_t i = 0; i < tal_count(splice_cmd->actions); i++) {
		action = splice_cmd->actions[i];
		state = splice_cmd->states[i];
		if (state->state == SPLICE_CMD_INIT)
			return splice_update(cmd, splice_cmd, i);
	}

	for (size_t i = 0; i < tal_count(splice_cmd->actions); i++) {
		action = splice_cmd->actions[i];
		state = splice_cmd->states[i];
		if (state->state == SPLICE_CMD_UPDATE_NEEDS_CHANGES)
			return splice_update(cmd, splice_cmd, i);
	}

	if (splice_cmd->wetrun)
		return handle_wetrun(cmd, splice_cmd);

	for (size_t i = 0; i < tal_count(splice_cmd->actions); i++) {
		action = splice_cmd->actions[i];
		state = splice_cmd->states[i];
		if (state->state == SPLICE_CMD_UPDATE)
			return splice_update(cmd, splice_cmd, i);
	}

	/* The signpsbt operation also adds channel_ids to psbt */
	if (splice_cmd->wallet_inputs_to_signed)
		return signpsbt(cmd, splice_cmd);

	if (requires_our_sigs(splice_cmd, &index))
		return splice_signed(cmd, splice_cmd, index);

	for (size_t i = 0; i < tal_count(splice_cmd->actions); i++) {
		action = splice_cmd->actions[i];
		state = splice_cmd->states[i];
		if (i != index && state->state == SPLICE_CMD_RECVED_SIGS)
			return splice_signed(cmd, splice_cmd, i);
	}

	for (size_t i = 0; i < tal_count(splice_cmd->actions); i++)
		assert(splice_cmd->states[i]->state == SPLICE_CMD_DONE);

	add_to_debug_log(splice_cmd, "continue_splice-finished");

	struct json_stream *response = jsonrpc_stream_success(cmd);
	json_add_psbt(response, "psbt", splice_cmd->psbt);
	json_add_txid(response, "txid", &splice_cmd->final_txid);
	if (splice_cmd->debug_log) {
		json_array_start(response, "log");
		debug_log_to_json(response, splice_cmd->debug_log);
		json_array_end(response);
	}
	return command_finished(cmd, response);
}

static struct command_result *execute_splice(struct command *cmd,
					      struct splice_cmd *splice_cmd)
{
	struct splice_script_result *action;
	struct splice_cmd_action_state *state;
	struct wally_psbt_output *output;
	u64 serial_id;
	int pays_fee;
	jsmntok_t tok;
	const u8 *scriptpubkey;

	/* Basic validation */
	pays_fee = 0;
	for (size_t i = 0; i < tal_count(splice_cmd->actions); i++) {
		int dest_count = 0;
		action = splice_cmd->actions[i];
		state = splice_cmd->states[i];

		if (splice_cmd->actions[i]->out_ppm)
			return do_fail(cmd, splice_cmd, JSONRPC2_INVALID_PARAMS,
					    "Should be no out_ppm on final");
		if (splice_cmd->actions[i]->pays_fee && pays_fee++)
			return do_fail(cmd, splice_cmd, JSONRPC2_INVALID_PARAMS,
					    "Only one item may pay fee");
		if (splice_cmd->actions[i]->channel_id)
			dest_count++;
		if (splice_cmd->actions[i]->bitcoin_address)
			dest_count++;
		if (splice_cmd->actions[i]->onchain_wallet)
			dest_count++;
		if (dest_count < 1)
			return do_fail(cmd, splice_cmd, JSONRPC2_INVALID_PARAMS,
					    "Must specify 1 destination per");
		if (dest_count > 1)
			return do_fail(cmd, splice_cmd, JSONRPC2_INVALID_PARAMS,
					    "Too many destinations per");

		/* If user specifies both sats in and out, we just use the
		 * larger of the two and subtract the smaller. */
		if (amount_sat_greater(action->in_sat, action->out_sat)) {
			if (!amount_sat_sub(&action->in_sat, action->in_sat,
					    action->out_sat))
				return do_fail(cmd, splice_cmd,
						    JSONRPC2_INVALID_PARAMS,
						    "Unable to sub out_sat from"
						    " in_sat");
			action->out_sat = amount_sat(0);
		} else {
			if (!amount_sat_sub(&action->out_sat, action->out_sat,
					    action->in_sat))
				return do_fail(cmd, splice_cmd,
						    JSONRPC2_INVALID_PARAMS,
						    "Unable to sub in_sat from"
						    " out_sat");
			action->in_sat = amount_sat(0);
		}
	}

	add_to_debug_log(splice_cmd, "execute_splice");

	for (size_t i = 0; i < tal_count(splice_cmd->actions); i++) {
		action = splice_cmd->actions[i];
		state = splice_cmd->states[i];

		/* Load (only one) feerate if user provided one */
		if (action->feerate_per_kw) {
			if (splice_cmd->feerate_per_kw)
				return do_fail(cmd, splice_cmd,
						    JSONRPC2_INVALID_PARAMS,
						    "Only one item may set"
						    " feerate");
			splice_cmd->feerate_per_kw = action->feerate_per_kw;
		}

		/* Fund out to bitcoin address */
		if (action->bitcoin_address) {
			if (!amount_sat_zero(action->in_sat))
				return do_fail(cmd, splice_cmd,
						    JSONRPC2_INVALID_PARAMS,
						    "Cannot fund from bitcoin"
						    " address");
			tok.type = JSMN_STRING;
			tok.start = 0;
			tok.end = strlen(action->bitcoin_address);
			tok.size = tok.end;
			switch(json_to_address_scriptpubkey(cmd,
							    chainparams,
							    action->bitcoin_address,
							    &tok,
							    &scriptpubkey)) {
				case ADDRESS_PARSE_UNRECOGNIZED:
					return do_fail(cmd, splice_cmd,
							    JSONRPC2_INVALID_PARAMS,
							    "Bitcoin address"
							    " unrecognized");
				case ADDRESS_PARSE_WRONG_NETWORK:
					return do_fail(cmd, splice_cmd,
							    JSONRPC2_INVALID_PARAMS,
							    "Bitcoin address not on"
							    " correct network");
				case ADDRESS_PARSE_SUCCESS:
					break;
			}
			output = psbt_append_output(splice_cmd->psbt,
						    scriptpubkey,
						    action->in_sat);

			/* DTODO: should be action->in_sat but we haven't calculated those yet... */

			serial_id = psbt_new_output_serial(splice_cmd->psbt,
					       		   TX_INITIATOR);
			psbt_output_set_serial_id(splice_cmd->psbt, output,
						  serial_id);

			state->state = SPLICE_CMD_DONE;

			add_to_debug_log(splice_cmd,
					 "execute_splice-load_btcaddress");
		}
	}

	return continue_splice(cmd, splice_cmd);
}

static struct command_result *adjust_pending_out_ppm(struct splice_script_result **actions,
						     struct channel_id channel_id,
						     struct amount_sat available_funds,
						     struct splice_cmd *splice_cmd)
{
	for (size_t i = 0; i < tal_count(actions); i++) {
		if (!actions[i]->channel_id)
			continue;
		if (!channel_id_eq(actions[i]->channel_id, &channel_id))
			continue;
		/* Skip channels not using out_ppm */
		if (!actions[i]->out_ppm)
			continue;

		/* For now max (asterisks) means 100% but that may change in the
		 * future */
		if (actions[i]->out_ppm == UINT32_MAX)
			actions[i]->out_ppm = 1000000;

		/* ppm percentage calculation:
		 * action->out_sat = available_funds * out_ppm / 1000000 */
		if (!amount_sat_mul(&actions[i]->out_sat, available_funds,
				    actions[i]->out_ppm))
			return command_fail(splice_cmd->cmd, JSONRPC2_INVALID_PARAMS,
					    "Unable to mul sats & out_ppm");
		actions[i]->out_sat = amount_sat_div(actions[i]->out_sat,
						     1000000);
		actions[i]->out_ppm = 0;
	}

	return NULL;
}

static struct command_result *stfu_channels_get_result(struct command *cmd,
			      const char *buf,
			      const jsmntok_t *toks,
			      struct splice_cmd *splice_cmd)
{
	const jsmntok_t *jchannels, *jchannel;
	size_t i;
	const char *err;
	struct command_result *result;

	jchannels = json_get_member(buf, toks, "channels");
	json_for_each_arr(i, jchannel, jchannels) {
		struct channel_id channel_id;
		struct amount_sat sat;

		memset(&channel_id, 0x77, sizeof(channel_id));
		memset(&sat, 0x77, sizeof(sat));

		err = json_scan(tmpctx, buf, jchannel,
				"{channel_id?:%,available_msat?:%}",
				JSON_SCAN(json_to_channel_id, &channel_id),
				JSON_SCAN(json_to_msat_to_sat, &sat));
		if (err)
			errx(1, "Bad stfu_channels.channels %zu: %s",
			     i, err);

		result = adjust_pending_out_ppm(splice_cmd->actions,
						channel_id, sat, splice_cmd);
		if (result)
			return result;
	}

	return execute_splice(splice_cmd->cmd, splice_cmd);
}

static struct command_result *splice_dryrun(struct command *cmd,
					    struct splice_cmd *splice_cmd)
{
	char **lines;
 	unsigned int i;
	struct json_stream *response;
	const char *str;

	response = jsonrpc_stream_success(cmd);
	json_array_start(response, "dryrun");

	str = splice_to_string(response, splice_cmd->actions,
			       tal_count(splice_cmd->actions));
 	lines = tal_strsplit(response, take(str), "\n", STR_NO_EMPTY);
 	for (i = 0; lines[i] != NULL; i++)
 		json_add_string(response, NULL, lines[i]);
	json_array_end(response);
	return command_finished(cmd, response);
}

static struct command_result *handle_splice_cmd(struct command *cmd,
						struct splice_cmd *splice_cmd)
{
	struct out_req *req;

	if (splice_cmd->dryrun)
		return splice_dryrun(cmd, splice_cmd);

	req = jsonrpc_request_start(cmd->plugin, cmd, "stfu_channels",
				    stfu_channels_get_result,
				    splice_error, splice_cmd);

	json_array_start(req->js, "channel_ids");
	/* We begin by stfu'ing and getting available balance on all MAX reqs */
	for (size_t i = 0; i < tal_count(splice_cmd->actions); i++)
		if (splice_cmd->actions[i]->channel_id)
			json_add_channel_id(req->js, NULL,
					    splice_cmd->actions[i]->channel_id);
	json_array_end(req->js);

	return send_outreq(cmd->plugin, req);
}

static struct command_result *
validate_splice_cmd(struct splice_cmd *splice_cmd)
{
	struct splice_script_result *action;
	int paying_fee_count = 0;
	int channels = 0;
	for (size_t i = 0; i < tal_count(splice_cmd->actions); i++) {
		action = splice_cmd->actions[i];
		/* Taking fee from onchain wallet requires recursive looping
		 * since adding more funds adds more input bytes. We don't
		 * support it for now. */
		if (action->pays_fee && action->onchain_wallet
			&& action->out_ppm)
			return command_fail(splice_cmd->cmd,
					    JSONRPC2_INVALID_PARAMS,
					    "Don't support dynamic fee being"
					    " added to onchain wallet");
		if (action->onchain_wallet && action->out_ppm)
			return command_fail(splice_cmd->cmd,
					    JSONRPC2_INVALID_PARAMS,
					    "Don't support dynamic wallet"
					    " funding amounts for now");
		if (action->pays_fee && action->onchain_wallet
			&& !amount_sat_zero(action->out_sat))
			return command_fail(splice_cmd->cmd,
					    JSONRPC2_INVALID_PARAMS,
					    "Don't support wallet funding"
					    " being used for fee");
		if (action->pays_fee && paying_fee_count++)
			return command_fail(splice_cmd->cmd,
					    JSONRPC2_INVALID_PARAMS,
					    "Only one item may pay the fee");
		if (action->bitcoin_address && action->in_ppm)
			return command_fail(splice_cmd->cmd,
					    JSONRPC2_INVALID_PARAMS,
					    "Dynamic bitcoin address amounts"
					    " not supported for now");
		if (action->bitcoin_address && action->in_ppm)
			return command_fail(splice_cmd->cmd,
					    JSONRPC2_INVALID_PARAMS,
					    "Dynamic bitcoin address amounts"
					    " not supported for now");
		if (action->channel_id && channels++)
			return command_fail(splice_cmd->cmd,
					    JSONRPC2_INVALID_PARAMS,
					    "Multi-channel splice not supported"
					    " for now");
	}

	return NULL;
}

static struct command_result *listpeerchannels_get_result(struct command *cmd,
				 const char *buf,
				 const jsmntok_t *toks,
				 struct splice_cmd *splice_cmd)
{
	struct splice_script_error *error;
	struct splice_script_chan *channels;
	struct command_result *result;
	const jsmntok_t *jchannels, *jchannel;
	char **lines;
	struct json_stream *response;
	const char *str;
	size_t i;
	const char *err;

	channels = tal_arr(tmpctx, struct splice_script_chan, 0);
	jchannels = json_get_member(buf, toks, "channels");
	json_for_each_arr(i, jchannel, jchannels) {
		tal_arr_expand(&channels, (struct splice_script_chan){});

		err = json_scan(tmpctx, buf, jchannel,
				"{peer_id?:%,channel_id?:%}",
				JSON_SCAN(json_to_node_id,
					  &channels[i].node_id),
				JSON_SCAN(json_to_channel_id,
					  &channels[i].chan_id));
		if (err)
			errx(1, "Bad listpeerchannels.channels %zu: %s",
			     i, err);
	}

	if (splice_cmd->script) {
		error = parse_splice_script(splice_cmd, splice_cmd->script,
					    channels, tal_count(channels),
					    &splice_cmd->actions);
		if (error) {
			response = jsonrpc_stream_fail(cmd,
						       JSONRPC2_INVALID_PARAMS,
						       "Splice script compile"
						       " failed");

			json_array_start(response, "compiler_error");

			str = splice_script_compiler_error(response,
							   splice_cmd->script,
							   error);
		 	lines = tal_strsplit(response, take(str), "\n",
		 			     STR_NO_EMPTY);
		 	for (i = 0; lines[i] != NULL; i++)
		 		json_add_string(response, NULL, lines[i]);
			json_array_end(response);
			return command_finished(cmd, response);
		}

		splice_cmd->states = tal_arr(splice_cmd,
					     struct splice_cmd_action_state*,
					     tal_count(splice_cmd->actions));

		for (i = 0; i < tal_count(splice_cmd->states); i++) {
			splice_cmd->states[i] = tal(splice_cmd->states,
						    struct splice_cmd_action_state);
			splice_cmd->states[i]->state = SPLICE_CMD_NONE;
		}
	}

	assert(splice_cmd->actions);

	result = validate_splice_cmd(splice_cmd);
	if (result)
		return result;

	return handle_splice_cmd(splice_cmd->cmd, splice_cmd);
}

static struct command_result *
json_splice(struct command *cmd, const char *buf, const jsmntok_t *params)
{
	struct out_req *req;
	const char *script;
	const jsmntok_t *json;
	struct wally_psbt *psbt;
	struct amount_sat *user_provided_funds;
	bool *dryrun, *force_feerate, *debug_log, *wetrun;

	if (!param(cmd, buf, params,
		   p_opt("script", param_string, &script),
		   p_opt_def("dryrun", param_bool, &dryrun, false),
		   p_opt("psbt", param_psbt, &psbt),
		   p_opt_def("user_provided_sats", param_sat,
		   	     &user_provided_funds,
		   	     AMOUNT_SAT(0)),
		   p_opt_def("force_feerate", param_bool, &force_feerate,
		   	     false),
		   p_opt("json", param_array, &json),
		   p_opt_def("debug_log", param_bool, &debug_log, false),
		   p_opt_def("wetrun", param_bool, &wetrun, false),
		   NULL))
		return command_param_failed();

	if (!script && !json)
		return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
				    "Must pass 'script' or 'json'");
	if (psbt)
		return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
				    "Passing an initial psbt is not supported"
				    " yet");
	if (!psbt)
		psbt = create_psbt(cmd, 0, 0, 0);
	if (!validate_psbt(psbt))
		return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
				    "PSBT failed to validate.");

	struct splice_cmd *splice_cmd = tal(cmd, struct splice_cmd);

	splice_cmd->cmd = cmd;
	splice_cmd->script = tal_steal(splice_cmd, script);
	splice_cmd->psbt = tal_steal(splice_cmd, psbt);
	splice_cmd->dryrun = *dryrun;
	splice_cmd->wetrun = *wetrun;
	splice_cmd->feerate_per_kw = 0;
	splice_cmd->force_feerate = *force_feerate;
	splice_cmd->wallet_inputs_to_signed = 0;
	splice_cmd->fee_calculated = false;
	splice_cmd->initial_funds = *user_provided_funds;
	splice_cmd->emergency_sat = AMOUNT_SAT(0);
	splice_cmd->debug_log = *debug_log ? tal_strdup(splice_cmd, "") : NULL;
	splice_cmd->debug_counter = 0;
	memset(&splice_cmd->final_txid, 0x77, sizeof(splice_cmd->final_txid));

	if (json) {
		if (!json_to_splice(splice_cmd, buf, json,
				    &splice_cmd->actions))
			return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
					    "splice json failed validation");

		splice_cmd->states = tal_arr(splice_cmd,
					     struct splice_cmd_action_state*,
					     tal_count(splice_cmd->actions));

		for (size_t i = 0; i < tal_count(splice_cmd->states); i++) {
			splice_cmd->states[i] = tal(splice_cmd->states,
						    struct splice_cmd_action_state);
			splice_cmd->states[i]->state = SPLICE_CMD_NONE;
		}
	}

	req = jsonrpc_request_start(cmd->plugin, cmd, "listpeerchannels",
				    listpeerchannels_get_result,
				    splice_error, splice_cmd);

	return send_outreq(cmd->plugin, req);
}

const struct plugin_command splice_commands[] = {
	{
		"splice",
		"channels",
		"Execute a splice specified by {script} or {json}, optionally"
		" beginning with {psbt}. Specify {dryrun} true to output what"
		" the command would have done",
		"A given {script} or {json} is used to specify a splice of any"
		" complexity. All actions in the splice are merged into a"
		" single transaction. If no signatures are required from the"
		" user this will complete the action(s), otherwise a psbt will"
		" be returned for you to sign and pass to `splice_signed`."
		" If you are providing funds in {psbt} include the amount you"
		" are adding in {user_provided_funds}.",
		json_splice
	},
};
const size_t num_splice_commands = ARRAY_SIZE(splice_commands);
