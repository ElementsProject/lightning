#include "config.h"
#include <bitcoin/psbt.h>
#include <bitcoin/script.h>
#include <ccan/array_size/array_size.h>
#include <ccan/err/err.h>
#include <ccan/tal/str/str.h>
#include <ccan/tal/tal.h>
#include <common/addr.h>
#include <common/json_param.h>
#include <common/json_parse.h>
#include <common/json_stream.h>
#include <common/psbt_open.h>
#include <common/splice_script.h>
#include <inttypes.h>
#include <plugins/spender/splice.h>

struct abort_pkg {
	struct splice_cmd *splice_cmd;
	enum jsonrpc_errcode code;
	char *str;
};

static const char *cmd_state_string(enum splice_cmd_state state)
{
	switch (state) {
		case SPLICE_CMD_NONE:
			return "                    ";
		case SPLICE_CMD_PENDING:
			return "       PENDING      ";
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
		bool simulate_wallet_amount = false;
		bool hide_fee = false;

		if (action->onchain_wallet && action->pays_fee) {
			if (amount_sat_is_zero(action->out_sat)) {
				simulate_wallet_amount = true;
				action->out_sat = scmd->needed_funds;
			} else {
				hide_fee = true;
				action->pays_fee = false;
			}
		}

		tal_append_fmt(log, "[%s] %s\n",
			       cmd_state_string(state->state),
			       splice_to_string(tmpctx, action));

		if (simulate_wallet_amount)
			action->out_sat = AMOUNT_SAT(0);

		if (hide_fee)
			action->pays_fee = true;
	}
}

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
						   const char *methodname,
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

		if (splice_cmd->debug_log) {
			json_array_start(response, "log");
			debug_log_to_json(response, splice_cmd->debug_log);
			json_array_end(response);
		}

		tal_free(abort_pkg);
		return command_finished(cmd, response);
	}

	return make_error(cmd, abort_pkg, "unreserve_get_result");
}

static struct command_result *abort_get_result(struct command *cmd,
					       const char *methodname,
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

	req = jsonrpc_request_start(cmd, "unreserveinputs",
				    unreserve_get_result, forward_error,
				    abort_pkg);

	json_add_psbt(req->js, "psbt", splice_cmd->psbt);

	return send_outreq(req);
}

static struct command_result *do_fail(struct command *cmd,
				      struct splice_cmd *splice_cmd,
				      enum jsonrpc_errcode code,
				      const char *str TAKES)
{
	struct out_req *req;
	struct abort_pkg *abort_pkg;
	size_t added;

	/* If we encounter an error, wetrun is canceled */
	splice_cmd->wetrun = false;

	plugin_log(cmd->plugin, LOG_DBG,
		   "splice_error(psbt:%p, splice_cmd:%p, str: %s)",
		   splice_cmd->psbt, splice_cmd, str ?: "");

	abort_pkg = tal(cmd->plugin, struct abort_pkg);
	abort_pkg->splice_cmd = tal_steal(abort_pkg, splice_cmd);
	abort_pkg->str = tal_strdup(abort_pkg, str);
	abort_pkg->code = code;

	req = jsonrpc_request_start(cmd, "abort_channels",
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
		return abort_get_result(cmd, NULL, NULL, NULL, abort_pkg);
	}

	return send_outreq(req);
}

static struct command_result *splice_error(struct command *cmd,
					   const char *methodname,
					   const char *buf,
					   const jsmntok_t *error,
					   struct splice_cmd *splice_cmd)
{
	char *str = tal_fmt(NULL, "%s: %.*s",
			    methodname,
			    error->end - error->start,
			    buf + error->start);

	return do_fail(cmd, splice_cmd, JSONRPC2_INVALID_PARAMS, take(str));
}

struct splice_index_pkg {
	struct splice_cmd *splice_cmd;
	size_t index;
};

static struct command_result *splice_error_pkg(struct command *cmd,
					       const char *methodname,
					       const char *buf,
					       const jsmntok_t *error,
					       struct splice_index_pkg *pkg)
{
	struct command_result *res = splice_error(cmd, methodname, buf, error, pkg->splice_cmd);

	tal_free(pkg);

	return res;
}

static struct splice_script_result *input_wallet(struct splice_cmd *splice_cmd,
						 size_t *index)
{
	for (size_t i = 0; i < tal_count(splice_cmd->actions); i++) {
		struct splice_script_result *action = splice_cmd->actions[i];
		if (action->onchain_wallet
		    && !action->in_ppm
		    && amount_sat_is_zero(action->in_sat)) {
			if (index)
				*index = i;
			return action;
		}
	}
	return NULL;
}

static struct splice_script_result *output_wallet(struct splice_cmd *splice_cmd)
{
	for (size_t i = 0; i < tal_count(splice_cmd->actions); i++) {
		struct splice_script_result *action = splice_cmd->actions[i];
		if (!action->onchain_wallet)
			continue;
		if (action->in_ppm || !amount_sat_is_zero(action->in_sat))
			return action;
	}
	return NULL;
}

static struct splice_script_result *fee_action(struct splice_cmd *splice_cmd)
{
	for (size_t i = 0; i < tal_count(splice_cmd->actions); i++) {
		struct splice_script_result *action = splice_cmd->actions[i];
		if (action->pays_fee)
			return action;
	}
	return NULL;
}

static struct command_result *notice_missing_funds(struct command *cmd,
						   struct splice_cmd *splice_cmd,
						   struct amount_sat *missing_funds,
						   struct amount_sat funds_needed,
						   struct amount_sat *funds_available)
{
	if (!amount_sat_add(missing_funds, *missing_funds, funds_needed))
		return do_fail(cmd, splice_cmd, JSONRPC2_INVALID_PARAMS,
				    "Unable to add for missing_funds");
	if (!amount_sat_sub(missing_funds, *missing_funds, *funds_available))
		return do_fail(cmd, splice_cmd, JSONRPC2_INVALID_PARAMS,
				    "Unable to sub for missing_funds");
	*funds_available = AMOUNT_SAT(0);
	plugin_log(cmd->plugin, LOG_DBG, "  missing_funds detected, now %s",
		   fmt_amount_sat(tmpctx, *missing_funds));
	return NULL;
}

#define NOTICE_MISSING(missing_funds, funds_needed, funds_available) \
	{ \
		struct command_result *result; \
		result = notice_missing_funds(cmd, splice_cmd, missing_funds, \
					      funds_needed, funds_available); \
		if (result) \
			return result; \
	}

 /* Because wallets increase the fee paying for the fee (due to inputs
  * increasing transaction size), this process must be inherently recursive.
  *
  * Adding to the complication is that wallets may take a percentage of total
  * funds in the splice before accomodating the fee.
  *
  * Finally, any percentage based receiver or contributor of funds may also be
  * responsible for the fee.
  *
  * Supporting all this means we need to build a solver that can be executed
  * repeatidly, solving what can be solved on each pass. Some answers inherently
  * require answers from prior passes.
  *
  * This method can be called repeatidly and it will solve more of the splice
  * each time. It must be called once at the end with `final_pass` set to true
  * to resolve ambigious percentages and place fees in some cases.
  *
  * After calling with `final_pass` you are free to call it again and in this
  * mode it works as an error checker, filling the `extra_funds`,
  * `missing_funds`, and `non_wallet_demand` values for verification.
  */
static struct command_result *calc_in_ppm_and_fee(struct command *cmd,
						  struct splice_cmd *splice_cmd,
						  struct amount_sat onchain_fee,
						  bool final_pass,
						  struct amount_sat *extra_funds,
						  struct amount_sat *missing_funds,
						  struct amount_sat *non_wallet_demand)
{
	struct splice_script_result *action, *last_ppm_action;
	struct amount_sat out_sats;
	bool sub_fee_from_general;
	struct needed_sats;
	int ppm_actions;
	struct splice_script_result *in_wallet, *out_wallet;


	add_to_debug_log(splice_cmd, "calc_in_ppm_and_fee");

	plugin_log(cmd->plugin, LOG_DBG, "calc_in_ppm_and_fee starting"
		   " calculations%s", final_pass ? " FINALIZING PASS" : "");

	out_sats = splice_cmd->initial_funds;
	sub_fee_from_general = true;

	in_wallet = input_wallet(splice_cmd, NULL);
	out_wallet = output_wallet(splice_cmd);

	/* First add all sats going into general fund */
	for (size_t i = 0; i < tal_count(splice_cmd->actions); i++) {
		action = splice_cmd->actions[i];
		if (action->pays_fee) {
			sub_fee_from_general = false;
			/* Has the onchain fee been finalized? */
			if (action->onchain_wallet) {
				if (!amount_sat_is_zero(action->out_sat)
				    || !amount_sat_is_zero(action->in_sat))
					sub_fee_from_general = true;
			}
			/* If we're the input wallet -- the fee may be finalized
			 * on the output wallet instead. Check there. */
			if (action == in_wallet && out_wallet) {
				if (!amount_sat_is_zero(out_wallet->out_sat)
				    || !amount_sat_is_zero(out_wallet->in_sat)) {
					sub_fee_from_general = true;
				}

			}
		}
		plugin_log(cmd->plugin, LOG_DBG, " plus %s (pays_fee %s, "
			   "out_ppm %u, out_sat %s, in_ppm %u, in_sat %s)",
			   fmt_amount_sat(tmpctx, action->out_sat),
			   action->pays_fee ? "yes" : "no",
			   action->out_ppm,
			   fmt_amount_sat(tmpctx, action->out_sat),
			   action->in_ppm,
			   fmt_amount_sat(tmpctx, action->in_sat));
		if (!amount_sat_add(&out_sats, out_sats, action->out_sat))
			return do_fail(cmd, splice_cmd, JSONRPC2_INVALID_PARAMS,
					    "Unable to add out_sats");
		if (action->out_ppm && !action->onchain_wallet)
			return do_fail(cmd, splice_cmd, JSONRPC2_INVALID_PARAMS,
					    "Unable to resolve out_ppm");
	}

	*non_wallet_demand = AMOUNT_SAT(0);
	*missing_funds = AMOUNT_SAT(0);

	/* Now take away all sats being spent by general fund */
	for (size_t i = 0; i < tal_count(splice_cmd->actions); i++) {
		action = splice_cmd->actions[i];
		plugin_log(cmd->plugin, LOG_DBG, " minus %s",
			   fmt_amount_sat(tmpctx, action->in_sat));
		/* Subtract used funds from out_sats */
		if (!amount_sat_sub(&out_sats, out_sats, action->in_sat))
			NOTICE_MISSING(missing_funds, action->in_sat,
				       &out_sats);
		if (action->onchain_wallet)
			continue;
		/* Add up non_wallet_demand (needed for wallet out_ppm) */
		if (!amount_sat_add(non_wallet_demand, *non_wallet_demand,
				    action->in_sat))
			return do_fail(cmd, splice_cmd, JSONRPC2_INVALID_PARAMS,
				       "Unable to add to non_wallet_demand");
	}

	/* Reduce non_wallet_demand by sats added from channels */
	for (size_t i = 0; i < tal_count(splice_cmd->actions); i++) {
		action = splice_cmd->actions[i];
		if (!action->channel_id)
			continue;
		if (!amount_sat_sub(non_wallet_demand, *non_wallet_demand,
				    action->out_sat))
			*non_wallet_demand = AMOUNT_SAT(0);
	}

	/* If no one voulenteers to pay the fee, we take it out of the general
	 * fund. */
	if (sub_fee_from_general) {

		plugin_log(cmd->plugin, LOG_DBG, " remove %s fee from general"
			   " fund %s",
			   fmt_amount_sat(tmpctx, onchain_fee),
			   fmt_amount_sat(tmpctx, out_sats));

		if (!amount_sat_sub(&out_sats, out_sats, onchain_fee))
			NOTICE_MISSING(missing_funds, onchain_fee, &out_sats);

		if (!amount_sat_add(non_wallet_demand, *non_wallet_demand,
				    onchain_fee))
			return do_fail(cmd, splice_cmd, JSONRPC2_INVALID_PARAMS,
				       "Unable to add to non_wallet_demand");
	}

	*extra_funds = out_sats;

	plugin_log(cmd->plugin, LOG_DBG, " general fund is %s",
		   fmt_amount_sat(tmpctx, out_sats));

	ppm_actions = 0;

	for (size_t i = 0; i < tal_count(splice_cmd->actions); i++) {
		struct amount_sat sat;
		action = splice_cmd->actions[i];
		if (action->in_ppm) {
			/* ppm percentage calculation:
			 * action->in_sat = out_sats * in_ppm / 1000000 */
			if (!amount_sat_mul(&sat, out_sats, action->in_ppm))
				return do_fail(cmd, splice_cmd,
					       JSONRPC2_INVALID_PARAMS,
					       "Unable to mul sats & in_ppm");

			sat = amount_sat_div(sat, 1000000);

			if (!amount_sat_add(&action->in_sat, action->in_sat, sat))
				return do_fail(cmd, splice_cmd,
					       JSONRPC2_INVALID_PARAMS,
					       "Unable to add sats & in_sat");
			if (!amount_sat_is_zero(sat) || final_pass) {
				plugin_log(cmd->plugin, LOG_DBG,
					   " resolving percentage, in_ppm calc"
					   " %u of %s = %s",
					   action->in_ppm,
					   fmt_amount_sat(tmpctx, out_sats),
					   fmt_amount_sat(tmpctx, sat));
				action->in_ppm = 0;
			}

			/* Remove used sats from extra_funds */
			if (!amount_sat_sub(extra_funds, *extra_funds, sat)) {
				/* If we can't do that then add to missing */
				NOTICE_MISSING(missing_funds, sat,
					       extra_funds);
			}

			ppm_actions++;
			last_ppm_action = action;
		}

		if (final_pass && action->pays_fee
		    && !amount_sat_is_zero(action->in_sat)) {
			plugin_log(cmd->plugin, LOG_DBG,
				   " subtracting fee of %s from %s",
				   fmt_amount_sat(tmpctx, onchain_fee),
				   fmt_amount_sat(tmpctx, action->in_sat));
			if (!amount_sat_sub(&action->in_sat, action->in_sat,
					    onchain_fee))
				NOTICE_MISSING(missing_funds, onchain_fee,
					       &action->in_sat);
			action->pays_fee = false;
		}

		if (action->pays_fee && !sub_fee_from_general) {
			plugin_log(cmd->plugin, LOG_DBG,
				   " action pays fee, so removing fee %s from"
				   " extra_funds %s",
				   fmt_amount_sat(tmpctx, onchain_fee),
				   fmt_amount_sat(tmpctx, *extra_funds));
			if (!amount_sat_sub(extra_funds, *extra_funds,
					    onchain_fee))
				NOTICE_MISSING(missing_funds, onchain_fee,
					       extra_funds);
		}

		/* Onchain wallet fees are handled seperately */
		if (action->onchain_wallet)
			continue;

		if (!final_pass)
			continue;

		/* If this item pays the fee, subtract it from either their
		 * in_sats or add it to out_sats. */
		if (action->pays_fee && !amount_sat_is_zero(action->in_sat)) {
			plugin_log(cmd->plugin, LOG_DBG, " sub fee %s",
				   fmt_amount_sat(tmpctx, onchain_fee));
			if (!amount_sat_sub(&action->in_sat, action->in_sat,
					    onchain_fee))
				return do_fail(cmd, splice_cmd,
						    JSONRPC2_INVALID_PARAMS,
						    "Unable to sub fee from"
						    " item in_sat");
		}
		if (action->pays_fee && !amount_sat_is_zero(action->out_sat)) {
			plugin_log(cmd->plugin, LOG_DBG, "add fee %s",
				   fmt_amount_sat(tmpctx, onchain_fee));
			if (!amount_sat_add(&action->out_sat, action->out_sat,
					    onchain_fee))
				return do_fail(cmd, splice_cmd,
						    JSONRPC2_INVALID_PARAMS,
						    "Unable to add fee to"
						    " item out_sat");
		}
	}

	/* Because of percentage based rounding, we can lose ~1 sat per
	 * percentage amount receiver. If extra sats is at or below 1 per
	 * receiver, we simply dump it in the last ppm receiver. */
	if (ppm_actions && !amount_sat_is_zero(*extra_funds)
	    && amount_sat_less_eq(*extra_funds, amount_sat(ppm_actions))) {
		plugin_log(cmd->plugin, LOG_DBG,
			   " placing %s lost during rounding",
			   fmt_amount_sat(tmpctx, *extra_funds));
		if (!amount_sat_add(&last_ppm_action->in_sat,
			       last_ppm_action->in_sat,
			       *extra_funds))
			return do_fail(cmd, splice_cmd, JSONRPC2_INVALID_PARAMS,
				       "Failed to add extra sats");
		*extra_funds = AMOUNT_SAT(0);
	}

	plugin_log(cmd->plugin, LOG_DBG, "calc_in_ppm_and_fee finished."
		   " out_sats: %s, extra_funds: %s, missing_funds: %s,"
		   " non_wallet_demand: %s",
		   fmt_amount_sat(tmpctx, out_sats),
		   fmt_amount_sat(tmpctx, *extra_funds),
		   fmt_amount_sat(tmpctx, *missing_funds),
		   fmt_amount_sat(tmpctx, *non_wallet_demand));

	/*  validate result */
	for (size_t i = 0; i < tal_count(splice_cmd->actions); i++) {
		action = splice_cmd->actions[i];
		if (!action->channel_id)
			continue;
		if (!amount_sat_is_zero(action->in_sat))
			continue;
		if (!amount_sat_is_zero(action->out_sat))
			continue;
		if (!amount_sat_is_zero(action->lease_sat))
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

static struct splice_script_result *make_wallet(struct splice_cmd *splice_cmd)
{
	struct splice_script_result *action;
	struct splice_cmd_action_state *state;

	action = talz(splice_cmd->actions, struct splice_script_result);
	state = talz(splice_cmd->states, struct splice_cmd_action_state);

	action->onchain_wallet = true;
	state->state = SPLICE_CMD_NONE;

	tal_arr_expand(&splice_cmd->actions, action);
	tal_arr_expand(&splice_cmd->states, state);

	return action;
}

static struct command_result *addpsbt_get_result(struct command *cmd,
			const char *methodname,
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

		if (!amount_sat_is_zero(excess_sat)) {
			if (!amount_sat_add(&action->out_sat, action->out_sat,
					   excess_sat))
				return do_fail(cmd, splice_cmd,
					       JSONRPC2_INVALID_PARAMS,
					       "Unable to add excess sats");

			plugin_log(cmd->plugin, LOG_DBG,
				   "Received input(s) with %s",
				   fmt_amount_sat(tmpctx, action->out_sat));

			out_wallet = output_wallet(splice_cmd);
			plugin_log(cmd->plugin, LOG_DBG,
				   "Adding excess sats back into out wallet %s"
				   " which already has %s",
				   fmt_amount_sat(tmpctx, excess_sat),
				   out_wallet
				   	? fmt_amount_sat(tmpctx,
				   		out_wallet->in_sat)
				   	: "(NO WALLET)");

			if (!out_wallet) {
				plugin_log(cmd->plugin, LOG_DBG, "Generating"
					   " output wallet.");
				out_wallet = make_wallet(splice_cmd);
			}

			if (out_wallet) {
				if (!amount_sat_add(&out_wallet->in_sat,
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
		if (!amount_sat_is_zero(splice_cmd->emergency_sat))
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
						  size_t index,
						  struct amount_sat already_funded)
{
	struct splice_script_result *action = splice_cmd->actions[index];
	struct splice_cmd_action_state *state = splice_cmd->states[index];
	struct out_req *req;
	struct splice_index_pkg *pkg;
	struct amount_sat sats;
	const char *command;
	bool addinginputs = !amount_sat_is_zero(action->out_sat);

	pkg = tal(cmd->plugin, struct splice_index_pkg);
	pkg->splice_cmd = splice_cmd;
	pkg->index = index;

	command = "addpsbtoutput";
	if (addinginputs) {
		command = "addpsbtinput";
		splice_cmd->wallet_inputs_to_signed++;
	}

	req = jsonrpc_request_start(cmd, command,
				    addpsbt_get_result,
				    splice_error_pkg, pkg);

	if (addinginputs) {
		sats = action->out_sat;
		if (!amount_sat_sub(&sats, sats, already_funded))
			return do_fail(cmd, splice_cmd, JSONRPC2_INVALID_PARAMS,
				       tal_fmt(tmpctx,
				       "Internal error; unable to sub"
				       " already_funded %s sats from out_stats"
				       " %s onchain_wallet_fund",
				       fmt_amount_sat(tmpctx, already_funded),
				       fmt_amount_sat(tmpctx, sats)));
		json_add_sats(req->js, "satoshi", sats);
		assert(splice_cmd->feerate_per_kw);
		json_add_u32(req->js, "min_feerate", splice_cmd->feerate_per_kw);

		plugin_log(cmd->plugin, LOG_DBG, "Adding input of at least %s",
			   fmt_amount_sat(tmpctx, sats));
	}
	else {
		json_add_sats(req->js, "satoshi", action->in_sat);

		plugin_log(cmd->plugin, LOG_DBG, "Adding output of %s",
			   fmt_amount_sat(tmpctx, action->in_sat));
	}

	json_add_psbt(req->js, "initialpsbt", splice_cmd->psbt);
	json_add_bool(req->js, "add_initiator_serial_ids", true);
	if (addinginputs)
		json_add_bool(req->js, "mark_our_inputs", true);

	if (state->state == SPLICE_CMD_PENDING) {
		plugin_log(cmd->plugin, LOG_DBG, "Not marking index %d done"
			   " because it is pending", (int)index);
	} else {
		plugin_log(cmd->plugin, LOG_DBG, "Marking index %d done",
			   (int)index);
		state->state = SPLICE_CMD_DONE;
	}

	return send_outreq(req);
}

static struct command_result *feerate_get_result(struct command *cmd,
			const char *method,
			const char *buf,
			const jsmntok_t *result,
			struct splice_cmd *splice_cmd)
{
	const jsmntok_t *tok = json_get_member(buf, result, "perkw");
	tok = json_get_member(buf, tok, "splice");

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

	req = jsonrpc_request_start(cmd, "feerates",
				    feerate_get_result, splice_error,
				    splice_cmd);

	json_add_string(req->js, "style", "perkw");

	return send_outreq(req);
}

static struct amount_sat wallet_funding_amnt(struct splice_cmd *splice_cmd)
{
	struct amount_sat wallet_funding = AMOUNT_SAT(0);

	/* Being unable to wallet inputs shouldn't happen, so we log UNUSUAL */
	for (size_t i = 0; i < tal_count(splice_cmd->actions); i++) {
		if (splice_cmd->actions[i]->onchain_wallet) {
			if (!amount_sat_add(&wallet_funding, wallet_funding,
					    splice_cmd->actions[i]->out_sat))
				plugin_log(splice_cmd->cmd->plugin, LOG_UNUSUAL,
					   "Failed to add out_sat %s to"
					   " wallet_funding %s",
					   fmt_amount_sat(tmpctx, splice_cmd->actions[i]->out_sat),
					   fmt_amount_sat(tmpctx, wallet_funding));
		}
	}

	for (size_t i = 0; i < tal_count(splice_cmd->actions); i++) {
		if (splice_cmd->actions[i]->onchain_wallet) {
			if (!amount_sat_sub(&wallet_funding, wallet_funding,
					    splice_cmd->actions[i]->in_sat))
				wallet_funding = AMOUNT_SAT(0);
		}
	}

	return wallet_funding;
}

static bool unresolved_wallet_inputs(struct splice_cmd *splice_cmd)
{
	struct amount_sat wallet_funding = wallet_funding_amnt(splice_cmd);

	return amount_sat_less(wallet_funding, splice_cmd->needed_funds);
}

static size_t calc_weight(struct splice_cmd *splice_cmd,
			  bool simulate_wallet_outputs)
{
	struct splice_script_result *action;
	struct plugin *plugin = splice_cmd->cmd->plugin;
	struct wally_psbt *psbt = splice_cmd->psbt;
	size_t lweight = 0, weight = 0;
	size_t extra_inputs = 0;
	size_t extra_outputs = 0;
	bool add_wallet_output = output_wallet(splice_cmd) ? true : false;

	plugin_log(plugin, LOG_DBG, "Counting potenetial tx weight;");

	/* BOLT #2:
	 * The rest of the transaction bytes' fees are the responsibility of
	 * the peer who contributed that input or output via `tx_add_input` or
	 * `tx_add_output`, at the agreed upon `feerate`.
	 */
	for (size_t i = 0; i < psbt->num_inputs; i++) {
		weight += psbt_input_get_weight(psbt, i, PSBT_GUESS_2OF2);
		plugin_log(plugin, LOG_DBG, " Counting input; weight: %lu",
			   weight - lweight);
		lweight = weight;
	}

	if (unresolved_wallet_inputs(splice_cmd)) {
		add_wallet_output = true;
		weight += bitcoin_tx_input_weight(false,
						  bitcoin_tx_input_witness_weight(UTXO_P2TR) - 1);
		plugin_log(plugin, LOG_DBG, " Simulating input (wallet);"
			   " weight: %lu", weight - lweight);
		lweight = weight;
	}

	/* Count the splice input manually */
	for (size_t i = 0; i < tal_count(splice_cmd->actions); i++) {
		action = splice_cmd->actions[i];
		if (action->channel_id) {
			weight += bitcoin_tx_input_weight(false,
							  bitcoin_tx_2of2_input_witness_weight() - 1);
			plugin_log(plugin, LOG_DBG, " Simulating input"
				   " (channel); weight:"
				   " %lu", weight - lweight);
			lweight = weight;
			extra_inputs++;
		}
	}

	/* Count the splice outputs manually */
	for (size_t i = 0; i < tal_count(splice_cmd->actions); i++) {
		action = splice_cmd->actions[i];
		if (action->onchain_wallet) {
			if (!amount_sat_is_zero(action->in_sat) || action->in_ppm)
				add_wallet_output = true;
			assert(!splice_cmd->actions[i]->channel_id);
		}
		if (splice_cmd->actions[i]->channel_id) {
			weight += bitcoin_tx_output_weight(BITCOIN_SCRIPTPUBKEY_P2WSH_LEN);
			plugin_log(plugin, LOG_DBG, " Simulating output"
				   " (channel); weight:"
				   " %lu", weight - lweight);
			lweight = weight;

			extra_outputs++;
		}
	}

	if (simulate_wallet_outputs && add_wallet_output) {
		weight += bitcoin_tx_output_weight(BITCOIN_SCRIPTPUBKEY_P2TR_LEN);
		extra_outputs++;
		plugin_log(plugin, LOG_DBG, " Simulating output"
			   " (wallet); weight:"
			   " %lu", weight - lweight);
		lweight = weight;
	}

	for (size_t i = 0; i < psbt->num_outputs; i++) {
		weight += psbt_output_get_weight(psbt, i);
		plugin_log(plugin, LOG_DBG, " Adding output; weight: %lu",
			   weight - lweight);
		lweight = weight;
	}

	/* BOLT #2:
	 * The *initiator* is responsible for paying the fees for the following fields,
	 * to be referred to as the `common fields`.
	 *
  	 * - version
  	 * - segwit marker + flag
  	 * - input count
  	 * - output count
  	 * - locktime
	 */
	weight += bitcoin_tx_core_weight(psbt->num_inputs + extra_inputs,
					 psbt->num_outputs + extra_outputs);
	plugin_log(plugin, LOG_DBG, " Adding bitcoin_tx_core_weight;"
		   " weight: %lu", weight - lweight);
	lweight = weight;

	plugin_log(plugin, LOG_DBG, "Total weight: %lu", weight);
	return weight;
}

static struct command_result *splice_init_get_result(struct command *cmd,
			    const char *methodname,
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

	req = jsonrpc_request_start(cmd, "splice_init",
				    splice_init_get_result, splice_error,
				    splice_cmd);

	json_add_channel_id(req->js, "channel_id", action->channel_id);
	if (!amount_sat_is_zero(action->in_sat)) {
		json_add_u64(req->js, "relative_amount",
			     action->in_sat.satoshis);  /* Raw: signed RPC */
	} else if (!amount_sat_is_zero(action->out_sat)) {
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

	return send_outreq(req);
}

static struct command_result *splice_update_get_result(struct command *cmd,
			      const char *methodname,
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
		state->state = got_sigs ? SPLICE_CMD_RECVED_SIGS : SPLICE_CMD_UPDATE_DONE;

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
		   fmt_channel_id(tmpctx, action->channel_id));

	req = jsonrpc_request_start(cmd, "splice_update",
				    splice_update_get_result, splice_error_pkg,
				    pkg);

	json_add_channel_id(req->js, "channel_id", action->channel_id);
	json_add_psbt(req->js, "psbt", splice_cmd->psbt);

	return send_outreq(req);
}

static struct command_result *signpsbt_get_result(struct command *cmd,
						  const char *methodname,
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
	size_t num_to_be_signed;

	req = jsonrpc_request_start(cmd, "signpsbt",
				    signpsbt_get_result, splice_error,
				    splice_cmd);

	/* Use input markers to identify which inputs
	 * are ours, only sign those */
	json_array_start(req->js, "signonly");
	num_to_be_signed = 0;
	for (size_t i = 0; i < splice_cmd->psbt->num_inputs; i++) {
		if (psbt_input_is_ours(&splice_cmd->psbt->inputs[i])) {
			json_add_num(req->js, NULL, i);
			num_to_be_signed++;
		}
	}
	json_array_end(req->js);

	json_add_psbt(req->js, "psbt", splice_cmd->psbt);

	/* If we have no inputs to be signed, skip ahead */
	if (!num_to_be_signed) {
		splice_cmd->wallet_inputs_to_signed = 0;
		return continue_splice(splice_cmd->cmd, splice_cmd);
	}

	return send_outreq(req);
}

static struct splice_script_result *requires_our_sigs(struct splice_cmd *splice_cmd,
						      size_t *index,
						      bool *multiple_require_sigs)
{
	struct splice_script_result *action = NULL;
	*index = UINT32_MAX;
	*multiple_require_sigs = false;
	for (size_t i = 0; i < tal_count(splice_cmd->actions); i++) {
		if (splice_cmd->states[i]->state == SPLICE_CMD_UPDATE_DONE) {
			/* There can only be one node that requires our sigs */
			if (action) {
				*multiple_require_sigs = true;
				return NULL;
			}
			action = splice_cmd->actions[i];
			*index = i;
		}
	}
	return action;
}

static struct command_result *splice_signed_get_result(struct command *cmd,
			      const char *methodname,
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

static struct command_result *splice_signed_error_pkg(struct command *cmd,
						      const char *methodname,
						      const char *buf,
						      const jsmntok_t *error,
						      struct splice_index_pkg *pkg)
{
	struct splice_cmd *splice_cmd = pkg->splice_cmd;
	struct abort_pkg *abort_pkg;

	splice_cmd->wetrun = false;

	abort_pkg = tal(cmd->plugin, struct abort_pkg);
	abort_pkg->splice_cmd = tal_steal(abort_pkg, pkg->splice_cmd);
	abort_pkg->str = tal_strndup(abort_pkg, buf + error->start,
				     error->end - error->start);
	abort_pkg->code = -1;

	tal_free(pkg);

	return make_error(cmd, abort_pkg, "splice_signed_error");
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

	req = jsonrpc_request_start(cmd, "splice_signed",
				    splice_signed_get_result,
				    splice_signed_error_pkg,
				    pkg);

	json_add_channel_id(req->js, "channel_id", action->channel_id);
	json_add_psbt(req->js, "psbt", splice_cmd->psbt);

	return send_outreq(req);
}

static struct command_result *check_emergency_sat(struct command *cmd,
						  struct splice_cmd *splice_cmd)
{
	struct amount_sat to_wallet = AMOUNT_SAT(0);
	if (amount_sat_is_zero(splice_cmd->emergency_sat))
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

static struct command_result *handle_wetrun(struct command *cmd,
					    struct splice_cmd *splice_cmd)
{
	struct out_req *req;
	struct abort_pkg *abort_pkg;
	size_t added;

	abort_pkg = tal(cmd->plugin, struct abort_pkg);
	abort_pkg->splice_cmd = tal_steal(abort_pkg, splice_cmd);
	abort_pkg->str = NULL;

	req = jsonrpc_request_start(cmd, "abort_channels",
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
		return unreserve_get_result(cmd, NULL, NULL, NULL, abort_pkg);

	return send_outreq(req);
}

/* Before calling, ensure `onchain_fee` is accounted for in `needed_funds`.
 *
 * If we need to fund from the onchain wallet this requires another pass so
 * `onchain_fee` will be subtracted out of `needed_funds` and an
 * `onchain_wallet_fund` command is returned.
 *
 * If we are finished funding or we can take the needed funds out of a wallet
 * output, we return NULL for success and leave `needed_funds` unmolested.
 */
static struct command_result *handle_wallet_fund(struct command *cmd,
						 struct splice_cmd *splice_cmd,
						 struct amount_sat onchain_fee)
{
	size_t index;
	struct splice_script_result *input, *output;
	struct amount_sat already_funded, wallet_funding, missing_funds;

	wallet_funding = wallet_funding_amnt(splice_cmd);

	if (!amount_sat_sub(&missing_funds, splice_cmd->needed_funds,
			    wallet_funding))
		return do_fail(cmd, splice_cmd,
			       JSONRPC2_INVALID_PARAMS,
			       "Failed to calculate missing funds");

	plugin_log(cmd->plugin, LOG_INFORM, "handle_wallet_fund needed_funds"
		   " %s, current_funds %s, missing_funds %s",
		   fmt_amount_sat(tmpctx, splice_cmd->needed_funds),
		   fmt_amount_sat(tmpctx, wallet_funding),
		   fmt_amount_sat(tmpctx, missing_funds));

	input = input_wallet(splice_cmd, &index);
	output = output_wallet(splice_cmd);

	if (!input)
		return do_fail(cmd, splice_cmd,
			       JSONRPC2_INVALID_PARAMS,
			       "Can't fund wallet with no input wallet");

	/* Can we fund the input by just subtracting from the output? */
	if (output && amount_sat_greater(output->in_sat, missing_funds)) {

		plugin_log(cmd->plugin, LOG_INFORM, "Taking %s"
			   " from output wallet %s to cover fee",
			   fmt_amount_sat(tmpctx, missing_funds),
			   fmt_amount_sat(tmpctx, output->in_sat));

		if (!amount_sat_sub(&output->in_sat, output->in_sat,
				    missing_funds))
			return do_fail(cmd, splice_cmd,
				       JSONRPC2_INVALID_PARAMS,
				       tal_fmt(tmpctx,
				       "Failed to subtract fee amount %s"
				       " from output %s",
				       fmt_amount_sat(tmpctx, missing_funds),
				       fmt_amount_sat(tmpctx, output->in_sat)));

		return NULL;
	}

	already_funded = input->out_sat;

	if (!amount_sat_add(&input->out_sat, input->out_sat, missing_funds))
		return do_fail(cmd, splice_cmd,
			       JSONRPC2_INVALID_PARAMS,
			       "Unable to add missing funds to wallet input");

	/* Retruning `onchain_wallet_fund` means we will need to go around
	 * again and the caller will added the new `onchain_fee` to
	 * `needed_funds`, so we must take the now old amount out. */
	if (!amount_sat_sub(&splice_cmd->needed_funds,
			    splice_cmd->needed_funds,
			    onchain_fee))
		return do_fail(cmd, splice_cmd,
			       JSONRPC2_INVALID_PARAMS,
			       "Internal error; unable"
			       " to subtract fee from"
			       " needed_funds");

	plugin_log(cmd->plugin, LOG_INFORM, "Requesting funding"
		   " amount + %s fee wallet inputs for %s"
		   " with %s already_funded",
		   fmt_amount_sat(tmpctx, onchain_fee),
		   fmt_amount_sat(tmpctx, input->out_sat),
		   fmt_amount_sat(tmpctx, already_funded));

	return onchain_wallet_fund(cmd, splice_cmd,
				   index,
				   already_funded);
}

static struct command_result *handle_fee_and_ppm(struct command *cmd,
						 struct splice_cmd *splice_cmd)
{
	struct command_result *result;
	struct amount_sat onchain_fee;
	size_t weight;
	struct amount_sat extra_funds, missing_funds, non_wallet_demand, sat;
	struct splice_script_result *funding_wallet_action = NULL;
	size_t funding_wallet_index;

	funding_wallet_action = input_wallet(splice_cmd, &funding_wallet_index);

	/* We calculate the weight with simulated wallet */
	weight = calc_weight(splice_cmd, true);
	onchain_fee = amount_tx_fee(splice_cmd->feerate_per_kw, weight);

	plugin_log(cmd->plugin, LOG_INFORM,
		   "Splice fee is %s at %"PRIu32" perkw (%.02f sat/vB) "
		   "on tx where our weight units are %lu",
		   fmt_amount_sat(tmpctx, onchain_fee),
		   splice_cmd->feerate_per_kw,
		   4 * splice_cmd->feerate_per_kw / 1000.0f,
		   weight);

	/* If the wallet pays the fee, we need to add input(s) to cover
	 * it. This can potentially need to be done mulitple times since
	 * adding an input increases the needed fee. */
	if (funding_wallet_action && funding_wallet_action->pays_fee
		&& !funding_wallet_action->out_ppm
		&& splice_cmd->states[funding_wallet_index]->state != SPLICE_CMD_PENDING) {

		result = calc_in_ppm_and_fee(cmd, splice_cmd,
					     onchain_fee,
					     false,
					     &extra_funds,
					     &missing_funds,
					     &non_wallet_demand);
		if (result)
			return result;

		if (!amount_sat_add(&splice_cmd->needed_funds,
				    splice_cmd->needed_funds,
				    onchain_fee))
			return do_fail(cmd, splice_cmd,
				       JSONRPC2_INVALID_PARAMS,
				       "Internal error; unable to add"
				       " fee to needed_funds");

		/* We need to add wallet funds (again?) */
		if (unresolved_wallet_inputs(splice_cmd)) {
			result = handle_wallet_fund(cmd, splice_cmd,
						    onchain_fee);
			if (result)
				return result;
		}
	}

	/* Now we're ready to calculate wallet funding in_ppm. This is
	 * a special case where we take a percentage of the
	 * non_wallet_demand. */
	if (funding_wallet_action && funding_wallet_action->out_ppm) {

		result = calc_in_ppm_and_fee(cmd, splice_cmd,
					     onchain_fee,
					     false,
					     &extra_funds,
					     &missing_funds,
					     &non_wallet_demand);
		if (result)
			return result;

		if (!amount_sat_mul(&sat, non_wallet_demand,
				    funding_wallet_action->out_ppm))
			return do_fail(cmd, splice_cmd,
				       JSONRPC2_INVALID_PARAMS,
				       "Unable to mul sats & out_ppm");
		sat = amount_sat_div(sat, 1000000);

		plugin_log(cmd->plugin, LOG_DBG,
			   "Processing wallet percentage,"
			   " non_wallet_demand %s * %uppm = %s",
			   fmt_amount_sat(tmpctx, non_wallet_demand),
			   funding_wallet_action->out_ppm,
			   fmt_amount_sat(tmpctx, sat));

		/* Add onchain fee to `sat` if wallet pays the fee */
		if (funding_wallet_action->pays_fee) {
			if (!amount_sat_add(&sat, sat, onchain_fee))
				return do_fail(cmd, splice_cmd,
					       JSONRPC2_INVALID_PARAMS,
					       "Failed to add onchain fee to"
					       " ppm funding wallet");

			plugin_log(cmd->plugin, LOG_DBG,
				   "Adding onchain_fee %s = %s",
				   fmt_amount_sat(tmpctx, onchain_fee),
				   fmt_amount_sat(tmpctx, sat));
		}

		if (!amount_sat_is_zero(extra_funds)) {
			plugin_log(cmd->plugin, LOG_DBG,
				   "Extra funds %s",
				   fmt_amount_sat(tmpctx, extra_funds));
		}

		/* Marking `out_ppm` as resolved allows the next pass
		 * here to drop down past this block */
		funding_wallet_action->out_ppm = 0;

		/* If sat resolves to real number, add it to `needed_funds` and
		 * fund it */
		if (!amount_sat_is_zero(sat)) {

			/* PENDING is a special case that funds the wallet but
			 * keeps it from being marked DONE by the funder */
			splice_cmd->states[funding_wallet_index]->state = SPLICE_CMD_PENDING;

			if (!amount_sat_add(&splice_cmd->needed_funds,
					    splice_cmd->needed_funds,
					    sat))
				return do_fail(cmd, splice_cmd,
					       JSONRPC2_INVALID_PARAMS,
					       "Internal error; unable"
					       " to add fee to"
					       " needed_funds (wallet"
					       " ppm)");

			plugin_log(cmd->plugin, LOG_DBG,
				   "Wallet funding pass for sats"
				   " %s, total %s",
				   fmt_amount_sat(tmpctx, sat),
				   fmt_amount_sat(tmpctx, splice_cmd->needed_funds));

			result = handle_wallet_fund(cmd, splice_cmd,
						    AMOUNT_SAT(0));
			if (result)
				return result;
		}
	}

	/* Here we know `funding_wallet_action->out_ppm` is resolved
	 * but we need to check for repeat funding needs */

	/* If adding funds required more funds to pay for fees, we must repeat
	 * the funding operation started by the `out_ppm` block */
	if (funding_wallet_action
	    && splice_cmd->states[funding_wallet_index]->state == SPLICE_CMD_PENDING) {

		result = calc_in_ppm_and_fee(cmd, splice_cmd,
					     onchain_fee,
					     false,
					     &extra_funds,
					     &missing_funds,
					     &non_wallet_demand);
		if (result)
			return result;

		/* Are we done? */
		if (amount_sat_is_zero(missing_funds)) {
			plugin_log(cmd->plugin, LOG_DBG,
				   "Wallet percentage processing done because"
				   " we have no missing funds");
			splice_cmd->states[funding_wallet_index]->state = SPLICE_CMD_NONE;
		} else if (funding_wallet_action->pays_fee
			|| !fee_action(splice_cmd)) {
			/* We only do extra rounds if our wallet pays the fee
			 * or if no one is paying fee (ie fee is paid from)
			 * general funds */

			if (amount_sat_greater(missing_funds, onchain_fee))
				return do_fail(cmd, splice_cmd,
					       JSONRPC2_INVALID_PARAMS,
					       tal_fmt(tmpctx,
					       "Internal error; should never"
					       " need an extra pass on ppm"
					       " wallet funding that is larger"
					       " than onchain_fee."
					       " missing_funds %s,"
					       " onchain_fee %s",
					       fmt_amount_sat(tmpctx, missing_funds),
					       fmt_amount_sat(tmpctx, onchain_fee)));

			if (!amount_sat_add(&splice_cmd->needed_funds,
					    splice_cmd->needed_funds,
					    missing_funds))
				return do_fail(cmd, splice_cmd,
					       JSONRPC2_INVALID_PARAMS,
					       "Internal error; unable"
					       " to add fee to"
					       " needed_funds (wallet"
					       " ppm)");

			plugin_log(cmd->plugin, LOG_DBG,
				   "Extra wallet funding pass for missing sats"
				   " %s, total %s",
				   fmt_amount_sat(tmpctx, missing_funds),
				   fmt_amount_sat(tmpctx, splice_cmd->needed_funds));

			result = handle_wallet_fund(cmd, splice_cmd,
						    AMOUNT_SAT(0));
			if (result)
				return result;
			else
				splice_cmd->states[funding_wallet_index]->state = SPLICE_CMD_NONE;
		} else {
			splice_cmd->states[funding_wallet_index]->state = SPLICE_CMD_NONE;
		}
	}

	/* Success! */
	plugin_log(cmd->plugin, LOG_INFORM, "Wallet funding done");

	/* Do a final pass to update values */
	result = calc_in_ppm_and_fee(cmd, splice_cmd,
				     onchain_fee,
				     true,
				     &extra_funds,
				     &missing_funds,
				     &non_wallet_demand);
	if (result)
		return result;

	/* One more pass to check for missing or extra funds */
	result = calc_in_ppm_and_fee(cmd, splice_cmd,
				     onchain_fee,
				     false,
				     &extra_funds,
				     &missing_funds,
				     &non_wallet_demand);
	if (result)
		return result;

	if (!amount_sat_is_zero(extra_funds))
		return do_fail(cmd, splice_cmd, JSONRPC2_INVALID_PARAMS,
			       tal_fmt(tmpctx,
				       "Script calculation ended with"
				       " unclaimed extra funds %s",
				       fmt_amount_sat(tmpctx,
				       		      extra_funds)));
	if (!amount_sat_is_zero(missing_funds))
		return do_fail(cmd, splice_cmd, JSONRPC2_INVALID_PARAMS,
			       tal_fmt(tmpctx,
				       "Script is missing %s funds",
				       fmt_amount_sat(tmpctx,
				       		      missing_funds)));

	return NULL;
}

static struct command_result *continue_splice(struct command *cmd,
					      struct splice_cmd *splice_cmd)
{
	struct splice_script_result *action;
	struct splice_cmd_action_state *state;
	struct command_result *result;
	size_t index;
	bool multiple_require_sigs;
	struct splice_script_result *funding_wallet_action = NULL;
	size_t funding_wallet_index;

	add_to_debug_log(splice_cmd, "continue_splice");

	if (!splice_cmd->feerate_per_kw)
		return load_feerate(cmd, splice_cmd);

	funding_wallet_action = input_wallet(splice_cmd, &funding_wallet_index);

	/* On first pass we add wallet actions that contribute funds but only
	 * if it is a static amount */
	if (funding_wallet_action
	    && splice_cmd->states[funding_wallet_index]->state == SPLICE_CMD_NONE
	    && !funding_wallet_action->out_ppm && !funding_wallet_action->pays_fee) {

		funding_wallet_action->out_sat = splice_cmd->needed_funds;
		plugin_log(cmd->plugin, LOG_INFORM, "funding static"
			   " wallet inputs for %s",
			   fmt_amount_sat(tmpctx, funding_wallet_action->out_sat));
		return onchain_wallet_fund(cmd, splice_cmd,
					   funding_wallet_index, AMOUNT_SAT(0));
	}

	if (!splice_cmd->fee_calculated) {

		result = handle_fee_and_ppm(cmd, splice_cmd);
		if (result)
			return result;

		splice_cmd->fee_calculated = true;
	}

	/* Only after fee calcualtion can we add wallet actions taking funds */
	for (size_t i = 0; i < tal_count(splice_cmd->actions); i++) {
		action = splice_cmd->actions[i];
		state = splice_cmd->states[i];
		if (state->state != SPLICE_CMD_NONE)
			continue;
		if (!action->onchain_wallet)
			continue;
		/* Add output for wallet funds */
		if (amount_sat_less(action->in_sat, splice_cmd->dust_limit)) {
			plugin_log(cmd->plugin, LOG_INFORM, "Adding a"
				   " wallet output of %s is below"
				   " dust_limit of %s. Leaving dust as"
				   " contribution to fee",
				   fmt_amount_sat(tmpctx, action->in_sat),
				   fmt_amount_sat(tmpctx, splice_cmd->dust_limit));
		} else {
			return onchain_wallet_fund(cmd, splice_cmd, i,
						   AMOUNT_SAT(0));
		}
		state->state = SPLICE_CMD_DONE;
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
		if (state->state == SPLICE_CMD_INIT
			|| state->state == SPLICE_CMD_UPDATE_NEEDS_CHANGES)
			return splice_update(cmd, splice_cmd, i);
	}

	/* It is possible to receive a signature when we do splice_update with
	 * no changes. Therefore wetrun must abort here to prevent any of our
	 * peers locking up funds */
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

	if (requires_our_sigs(splice_cmd, &index, &multiple_require_sigs))
		return splice_signed(cmd, splice_cmd, index);

	if (multiple_require_sigs)
		return do_fail(cmd, splice_cmd, JSONRPC2_INVALID_PARAMS,
			       "Requested splice is impossible because multiple"
			       " peers demand they do not sign first. Someone"
			       " must sign first.");

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
	u8 *scriptpubkey;

	/* Basic validation */
	pays_fee = 0;
	for (size_t i = 0; i < tal_count(splice_cmd->actions); i++) {
		int dest_count = 0;
		action = splice_cmd->actions[i];
		state = splice_cmd->states[i];

		if (action->out_ppm && !action->onchain_wallet)
			return do_fail(cmd, splice_cmd, JSONRPC2_INVALID_PARAMS,
					    "Should be no out_ppm on final"
					    " except for the wallet");
		if (splice_cmd->actions[i]->pays_fee) {
			if (pays_fee)
				return do_fail(cmd, splice_cmd,
					       JSONRPC2_INVALID_PARAMS,
					       "Only one item may pay fee");
			pays_fee++;
		}
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
		char *bitcoin_address;

		/* `out_ppm` is the percent to take out of the action.
		 * If it is set to '*' we get a value of UINT32_MAX.
		 * In this case we treat it as "take 100% out of the action." */
		if (action->out_ppm == UINT32_MAX)
			action->out_ppm = 1000000;

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
			if (!amount_sat_is_zero(action->in_sat))
				return do_fail(cmd, splice_cmd,
						    JSONRPC2_INVALID_PARAMS,
						    "Cannot fund from bitcoin"
						    " address");
			if (!decode_scriptpubkey_from_addr(cmd, chainparams,
							   action->bitcoin_address,
							   &scriptpubkey))
				return do_fail(cmd, splice_cmd,
					       JSONRPC2_INVALID_PARAMS,
					       "Bitcoin address"
					       " unrecognized");

			/* Reencode scriptpubkey to addr for verification */
			bitcoin_address = encode_scriptpubkey_to_addr(tmpctx,
								      chainparams,
								      scriptpubkey);
			if (!bitcoin_address)
				return do_fail(cmd, splice_cmd,
					       JSONRPC2_INVALID_PARAMS,
					       "Bitcoin scriptpubkey failed"
					       " reencoding for address");

			if (!strcmp(bitcoin_address, action->bitcoin_address))
				return do_fail(cmd, splice_cmd,
					       JSONRPC2_INVALID_PARAMS,
					       "Bitcoin scriptpubkey failed"
					       " validation for address");

			output = psbt_append_output(splice_cmd->psbt,
						    scriptpubkey,
						    action->in_sat);

			/* DTODO: support dynamic address payouts (percent) */

			serial_id = psbt_new_output_serial(splice_cmd->psbt,
					       		   TX_INITIATOR);
			psbt_output_set_serial_id(splice_cmd->psbt, output,
						  serial_id);

			state->state = SPLICE_CMD_DONE;

			add_to_debug_log(splice_cmd,
					 "execute_splice-load_btcaddress");
		}
	}

	/* Set needed funds to the wallet contributions. */
	for (size_t i = 0; i < tal_count(splice_cmd->actions); i++) {
		action = splice_cmd->actions[i];
		state = splice_cmd->states[i];
		if (action->onchain_wallet
		    && !amount_sat_is_zero(action->out_sat)) {
			splice_cmd->needed_funds = action->out_sat;
			plugin_log(cmd->plugin, LOG_INFORM, "setting"
				   " needed_funds to %s",
				   fmt_amount_sat(tmpctx,
				   		  splice_cmd->needed_funds));
			action->out_sat = AMOUNT_SAT(0);
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
					    "Unable to mul sats(%s) &"
					    " out_ppm(%"PRIu32") for channel id"
					    " %s",
					    fmt_amount_sat(tmpctx, available_funds),
					    actions[i]->out_ppm,
					    fmt_channel_id(tmpctx, &channel_id));
		actions[i]->out_sat = amount_sat_div(actions[i]->out_sat,
						     1000000);
		actions[i]->out_ppm = 0;
	}

	return NULL;
}

static struct command_result *stfu_channels_get_result(struct command *cmd,
			      const char *methodname,
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

		memset(&channel_id, 0, sizeof(channel_id));
		memset(&sat, 0, sizeof(sat));

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

	str = splicearr_to_string(response, splice_cmd->actions);
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

	req = jsonrpc_request_start(cmd, "stfu_channels",
				    stfu_channels_get_result,
				    splice_error, splice_cmd);

	json_array_start(req->js, "channel_ids");
	/* We begin by stfu'ing and getting available balance on all MAX reqs */
	for (size_t i = 0; i < tal_count(splice_cmd->actions); i++)
		if (splice_cmd->actions[i]->channel_id)
			json_add_channel_id(req->js, NULL,
					    splice_cmd->actions[i]->channel_id);
	json_array_end(req->js);

	return send_outreq(req);
}

static struct command_result *
validate_splice_cmd(struct splice_cmd *splice_cmd)
{
	struct splice_script_result *action;
	int paying_fee_count = 0;
	for (size_t i = 0; i < tal_count(splice_cmd->actions); i++) {
		action = splice_cmd->actions[i];
		if (action->pays_fee) {
			if (paying_fee_count)
				return command_fail(splice_cmd->cmd,
						    JSONRPC2_INVALID_PARAMS,
						    "Only one item may pay the"
						    " fee");
			paying_fee_count++;
		}
		if (action->bitcoin_address && action->in_ppm)
			return command_fail(splice_cmd->cmd,
					    JSONRPC2_INVALID_PARAMS,
					    "Dynamic bitcoin address amounts"
					    " not supported for now");
		if (action->bitcoin_address)
			return command_fail(splice_cmd->cmd,
					    JSONRPC2_INVALID_PARAMS,
					    "Paying out to bitcoin addresses"
					    " not supported for now.");
	}

	return NULL;
}

static struct command_result *listpeerchannels_get_result(struct command *cmd,
				 const char *methodname,
				 const char *buf,
				 const jsmntok_t *toks,
				 struct splice_cmd *splice_cmd)
{
	struct splice_script_error *error;
	struct splice_script_chan **channels;
	struct command_result *result;
	const jsmntok_t *jchannels, *jchannel;
	char **lines;
	struct json_stream *response;
	const char *str;
	size_t i;
	const char *err;

	splice_cmd->dust_limit = AMOUNT_SAT(0);
	channels = tal_arr(tmpctx, struct splice_script_chan*, 0);
	jchannels = json_get_member(buf, toks, "channels");
	json_for_each_arr(i, jchannel, jchannels) {
		struct amount_sat dust_candidate;
		tal_arr_expand(&channels, tal(channels,
					      struct splice_script_chan));

		err = json_scan(tmpctx, buf, jchannel,
				"{peer_id?:%,channel_id?:%,dust_limit_msat?:%}",
				JSON_SCAN(json_to_node_id,
					  &channels[i]->node_id),
				JSON_SCAN(json_to_channel_id,
					  &channels[i]->chan_id),
				JSON_SCAN(json_to_msat_to_sat,
					  &dust_candidate));
		if (err)
			errx(1, "Bad listpeerchannels.channels %zu: %s",
			     i, err);

		if (amount_sat_greater(dust_candidate, splice_cmd->dust_limit))
			splice_cmd->dust_limit = dust_candidate;
	}

	if (splice_cmd->script) {
		error = parse_splice_script(splice_cmd, splice_cmd->script,
					    channels,  &splice_cmd->actions);
		if (error) {
			response = jsonrpc_stream_fail(cmd,
						       JSONRPC2_INVALID_PARAMS,
						       "Splice script compile"
						       " failed");

			json_array_start(response, "compiler_error");

			str = fmt_splice_script_compiler_error(response,
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
	bool *dryrun, *force_feerate, *debug_log, *wetrun;
	struct str_or_arr *str_or_arr;

	if (!param(cmd, buf, params,
		   p_opt("script_or_json", param_string_or_array, &str_or_arr),
		   p_opt_def("dryrun", param_bool, &dryrun, false),
		   p_opt_def("force_feerate", param_bool, &force_feerate,
		   	     false),
		   p_opt_def("debug_log", param_bool, &debug_log, false),
		   p_opt_dev("dev-wetrun", param_bool, &wetrun, false),
		   NULL))
		return command_param_failed();

	if (!str_or_arr)
		return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
				    "Must pass 'script_or_json'");

	script = str_or_arr->str;
	json = str_or_arr->arr;

	psbt = create_psbt(cmd, 0, 0, 0);

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
	splice_cmd->initial_funds = AMOUNT_SAT(0);
	splice_cmd->emergency_sat = AMOUNT_SAT(0);
	splice_cmd->debug_log = *debug_log ? tal_strdup(splice_cmd, "") : NULL;
	splice_cmd->debug_counter = 0;
	splice_cmd->needed_funds = AMOUNT_SAT(0);
	splice_cmd->dust_limit = AMOUNT_SAT(0);
	memset(&splice_cmd->final_txid, 0, sizeof(splice_cmd->final_txid));

	/* If script validates as json, parse it as json instead */
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

	req = jsonrpc_request_start(cmd, "listpeerchannels",
				    listpeerchannels_get_result,
				    splice_error, splice_cmd);

	return send_outreq(req);
}

const struct plugin_command splice_commands[] = {
	{
		"dev-splice",
		json_splice
	},
};
const size_t num_splice_commands = ARRAY_SIZE(splice_commands);
