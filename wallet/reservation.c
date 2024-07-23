/* Dealing with reserving UTXOs */
#include "config.h"
#include <bitcoin/psbt.h>
#include <bitcoin/script.h>
#include <ccan/cast/cast.h>
#include <ccan/mem/mem.h>
#include <common/configdir.h>
#include <common/json_command.h>
#include <common/json_param.h>
#include <common/key_derive.h>
#include <lightningd/chaintopology.h>
#include <lightningd/channel.h>
#include <lightningd/hsm_control.h>
#include <lightningd/jsonrpc.h>
#include <lightningd/lightningd.h>
#include <wallet/txfilter.h>
#include <wally_psbt.h>

/* 12 hours is usually enough reservation time */
#define RESERVATION_DEFAULT (6 * 12)

static bool was_reserved(enum output_status oldstatus,
			 u32 reserved_til,
			 u32 current_height)
{
	if (oldstatus != OUTPUT_STATE_RESERVED)
		return false;

	return reserved_til > current_height;
}

static void json_add_reservestatus(struct json_stream *response,
				   const struct utxo *utxo,
				   enum output_status oldstatus,
				   u32 old_res,
				   u32 current_height)
{
	json_object_start(response, NULL);
	json_add_txid(response, "txid", &utxo->outpoint.txid);
	json_add_u32(response, "vout", utxo->outpoint.n);
	json_add_bool(response, "was_reserved",
		      was_reserved(oldstatus, old_res, current_height));
	json_add_bool(response, "reserved",
		      utxo_is_reserved(utxo, current_height));
	if (utxo_is_reserved(utxo, current_height))
		json_add_u32(response, "reserved_to_block",
			     utxo->reserved_til);
	json_object_end(response);
}

/* Reserve these UTXOs and print to JSON */
static void reserve_and_report(struct json_stream *response,
			       struct wallet *wallet,
			       u32 current_height,
			       u32 reserve,
			       struct utxo **utxos)
{
	json_array_start(response, "reservations");
	for (size_t i = 0; i < tal_count(utxos); i++) {
		enum output_status oldstatus;
		u32 old_res;

		oldstatus = utxos[i]->status;
		old_res = utxos[i]->reserved_til;

		if (!wallet_reserve_utxo(wallet,
					 utxos[i],
					 current_height,
					 reserve)) {
			fatal("Unable to reserve %s!",
			      fmt_bitcoin_outpoint(tmpctx,
						   &utxos[i]->outpoint));
		}
		json_add_reservestatus(response, utxos[i], oldstatus, old_res,
				       current_height);
	}
	json_array_end(response);
}

static struct command_result *json_reserveinputs(struct command *cmd,
						 const char *buffer,
						 const jsmntok_t *obj UNNEEDED,
						 const jsmntok_t *params)
{
	struct json_stream *response;
	struct wally_psbt *psbt;
	struct utxo **utxos = tal_arr(cmd, struct utxo *, 0);
	bool *exclusive;
	u32 *reserve, current_height;

	if (!param_check(cmd, buffer, params,
			 p_req("psbt", param_psbt, &psbt),
			 p_opt_def("exclusive", param_bool, &exclusive, true),
			 p_opt_def("reserve", param_number, &reserve,
				   RESERVATION_DEFAULT),
			 NULL))
		return command_param_failed();

	/* We only deal with V2 internally */
	if (!psbt_set_version(psbt, 2)) {
		return command_fail(cmd, LIGHTNINGD,
					"Failed to set version for PSBT: %s",
					fmt_wally_psbt(tmpctx, psbt));
	}

	current_height = get_block_height(cmd->ld->topology);
	for (size_t i = 0; i < psbt->num_inputs; i++) {
		struct bitcoin_outpoint outpoint;
		struct utxo *utxo;

		wally_psbt_input_get_outpoint(&psbt->inputs[i], &outpoint);
		utxo = wallet_utxo_get(cmd, cmd->ld->wallet, &outpoint);
		if (!utxo)
			continue;
		if (*exclusive && utxo_is_reserved(utxo, current_height)) {
			return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
					    "%s already reserved",
					    fmt_bitcoin_outpoint(tmpctx,
								 &utxo->outpoint));
		}
		if (utxo->status == OUTPUT_STATE_SPENT)
			return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
					    "%s already spent",
					    fmt_bitcoin_outpoint(tmpctx,
								 &utxo->outpoint));
		tal_arr_expand(&utxos, utxo);
	}

	if (command_check_only(cmd))
		return command_check_done(cmd);

	response = json_stream_success(cmd);
	reserve_and_report(response, cmd->ld->wallet, current_height, *reserve, utxos);
	return command_success(cmd, response);
}

static const struct json_command reserveinputs_command = {
	"reserveinputs",
	json_reserveinputs,
	false
};
AUTODATA(json_command, &reserveinputs_command);

static struct command_result *json_unreserveinputs(struct command *cmd,
						   const char *buffer,
						   const jsmntok_t *obj UNNEEDED,
						   const jsmntok_t *params)
{
	struct json_stream *response;
	struct wally_psbt *psbt;
	u32 *reserve;

	if (!param_check(cmd, buffer, params,
			 p_req("psbt", param_psbt, &psbt),
			 p_opt_def("reserve", param_number, &reserve,
				   RESERVATION_DEFAULT),
			 NULL))
		return command_param_failed();

	/* We only deal with V2 internally */
	if (!psbt_set_version(psbt, 2)) {
		log_broken(cmd->ld->log,
			"Unable to set version for PSBT: %s",
			fmt_wally_psbt(tmpctx, psbt));
	}

	/* We should also add the utxo info for these inputs!
	 * (absolutely required for using this psbt in a dual-funded
	 * round) */
	for (size_t i = 0; i < psbt->num_inputs; i++) {
		struct bitcoin_tx *utxo_tx;
		struct bitcoin_txid txid;

		wally_psbt_input_get_txid(&psbt->inputs[i], &txid);
		utxo_tx = wallet_transaction_get(psbt, cmd->ld->wallet,
						 &txid);
		if (utxo_tx) {
			tal_wally_start();
			wally_psbt_input_set_utxo(&psbt->inputs[i],
						  utxo_tx->wtx);
			tal_wally_end(psbt);
		} else
			log_broken(cmd->ld->log,
				   "No transaction found for UTXO %s",
				   fmt_bitcoin_txid(tmpctx, &txid));
	}

	if (command_check_only(cmd))
		return command_check_done(cmd);

	response = json_stream_success(cmd);
	json_array_start(response, "reservations");
	for (size_t i = 0; i < psbt->num_inputs; i++) {
		struct bitcoin_outpoint outpoint;
		struct utxo *utxo;
		enum output_status oldstatus;
		u32 old_res;

		wally_psbt_input_get_outpoint(&psbt->inputs[i], &outpoint);
		utxo = wallet_utxo_get(cmd, cmd->ld->wallet, &outpoint);
		if (!utxo || utxo->status != OUTPUT_STATE_RESERVED)
			continue;

		oldstatus = utxo->status;
		old_res = utxo->reserved_til;

		wallet_unreserve_utxo(cmd->ld->wallet,
				      utxo,
				      get_block_height(cmd->ld->topology),
				      *reserve);

		json_add_reservestatus(response, utxo, oldstatus, old_res,
				       get_block_height(cmd->ld->topology));
	}
	json_array_end(response);
	return command_success(cmd, response);
}

static const struct json_command unreserveinputs_command = {
	"unreserveinputs",
	json_unreserveinputs,
	false
};
AUTODATA(json_command, &unreserveinputs_command);

/**
 * inputs_sufficient - are we there yet?
 * @input: total input amount
 * @amount: required output amount
 * @feerate_per_kw: feerate we have to pay
 * @weight: weight of transaction so far.
 * @diff: (output) set to amount over or under requirements.
 *
 * Returns true if inputs >= fees + amount, otherwise false.  diff is
 * the amount over (if returns true) or under (if returns false)
 */
static bool inputs_sufficient(struct amount_sat input,
			      struct amount_sat amount,
			      u32 feerate_per_kw,
			      size_t weight,
			      struct amount_sat *diff)
{
	struct amount_sat fee;

	fee = amount_tx_fee(feerate_per_kw, weight);

	/* If we can't add fees, amount is huge (e.g. "all") */
	if (!amount_sat_add(&amount, amount, fee))
		return false;

	/* One of these must work! */
	if (amount_sat_sub(diff, input, amount))
		return true;
	if (!amount_sat_sub(diff, amount, input))
		abort();
	return false;
}

struct wally_psbt *psbt_using_utxos(const tal_t *ctx,
				    struct wallet *wallet,
				    struct utxo **utxos,
				    u32 nlocktime,
				    u32 nsequence,
				    struct wally_psbt *base)
{
	struct pubkey key;
	u8 *scriptSig, *scriptPubkey, *redeemscript;
	struct wally_psbt *psbt;

	if (base)
		psbt = base;
	else
		psbt = create_psbt(ctx, tal_count(utxos), 0, nlocktime);

	for (size_t i = 0; i < tal_count(utxos); i++) {
		u32 this_nsequence;
		struct bitcoin_tx *tx;

		if (utxos[i]->is_p2sh) {
			bip32_pubkey(wallet->ld, &key, utxos[i]->keyindex);
			scriptSig = bitcoin_scriptsig_p2sh_p2wpkh(tmpctx, &key);
			redeemscript = bitcoin_redeem_p2sh_p2wpkh(tmpctx, &key);
			scriptPubkey = scriptpubkey_p2sh(tmpctx, redeemscript);

			/* Make sure we've got the right info! */
			if (utxos[i]->scriptPubkey)
				assert(tal_arr_eq(utxos[i]->scriptPubkey, scriptPubkey));
		} else {
			scriptSig = NULL;
			redeemscript = NULL;
			scriptPubkey = utxos[i]->scriptPubkey;
		}

		/* BOLT #3:
		 * #### `to_remote` Output
		 * ...
		 * The output is spent by an input with `nSequence` field
		 * set to `1` and witness:
		 */
		if (utxos[i]->close_info
		    && utxos[i]->close_info->option_anchors)
			this_nsequence = utxos[i]->close_info->csv;
		else
			this_nsequence = nsequence;

		psbt_append_input(psbt, &utxos[i]->outpoint,
				  this_nsequence, scriptSig,
				  NULL, redeemscript);

		psbt_input_set_wit_utxo(psbt, psbt->num_inputs-1,
					scriptPubkey, utxos[i]->amount);
		if (is_elements(chainparams)) {
			/* FIXME: persist asset tags */
			amount_sat_to_asset(&utxos[i]->amount,
						    chainparams->fee_asset_tag);
			/* FIXME: persist nonces */
		}

		/* FIXME: as of 17 sept 2020, elementsd is *at most* at par
		 * with v0.18.0 of bitcoind, which doesn't support setting
		 * non-witness and witness utxo data for an input; remove this
		 * check once elementsd can be updated */
		if (!is_elements(chainparams)) {
			/* If we have the transaction for this utxo,
			 * add it to the PSBT as the non-witness-utxo field.
			 * Dual-funded channels and some hardware wallets
			 * require this */
			tx = wallet_transaction_get(ctx, wallet,
						    &utxos[i]->outpoint.txid);
			if (tx)
				psbt_input_set_utxo(psbt, psbt->num_inputs-1, tx->wtx);
		}
	}

	return psbt;
}

static struct command_result *finish_psbt(struct command *cmd,
					  struct utxo **utxos,
					  u32 feerate_per_kw,
					  size_t weight,
					  struct amount_sat excess,
					  u32 reserve,
					  u32 *locktime,
					  struct amount_sat change)
{
	struct json_stream *response;
	struct wally_psbt *psbt;
	ssize_t change_outnum;
	u32 current_height = get_block_height(cmd->ld->topology);

	if (!locktime) {
		locktime = tal(cmd, u32);
		*locktime = default_locktime(cmd->ld->topology);
	}

	psbt = psbt_using_utxos(cmd, cmd->ld->wallet, utxos,
				*locktime, BITCOIN_TX_RBF_SEQUENCE,
				NULL);
	assert(psbt->version == 2);

	/* Should we add a change output?  (Iff it can pay for itself!) */
	change = change_amount(change, feerate_per_kw, weight);
	if (amount_sat_greater(change, AMOUNT_SAT(0))) {
		struct pubkey pubkey;
		s64 keyidx;
		u8 *b32script;

		/* Get a change adddress */
		keyidx = wallet_get_newindex(cmd->ld);
		if (keyidx < 0)
			return command_fail(cmd, LIGHTNINGD,
					    "Failed to generate change address."
					    " Keys exhausted.");

		if (chainparams->is_elements) {
			bip32_pubkey(cmd->ld, &pubkey, keyidx);
			b32script = scriptpubkey_p2wpkh(tmpctx, &pubkey);
		} else {
			b32script = p2tr_for_keyidx(tmpctx, cmd->ld, keyidx);
		}
		if (!b32script) {
			return command_fail(cmd, LIGHTNINGD,
					    "Failed to generate change address."
					    " Keys generation failure");
		}
		txfilter_add_scriptpubkey(cmd->ld->owned_txfilter, b32script);

		change_outnum = psbt->num_outputs;
		psbt_append_output(psbt, b32script, change);
		/* Add additional weight of output */
		weight += bitcoin_tx_output_weight(
				chainparams->is_elements ? BITCOIN_SCRIPTPUBKEY_P2WPKH_LEN : BITCOIN_SCRIPTPUBKEY_P2TR_LEN);
	} else {
		change_outnum = -1;
	}

	/* Add a fee output if this is elements */
	if (is_elements(chainparams)) {
		struct amount_sat est_fee =
			amount_tx_fee(feerate_per_kw, weight);
		psbt_append_output(psbt, NULL, est_fee);
		/* Add additional weight of fee output */
		weight += bitcoin_tx_output_weight(0);
	} else {
		/* PSETv0 doesn't exist */
		if (!psbt_set_version(psbt, 0)) {
			return command_fail(cmd, LIGHTNINGD,
						"Failed to set PSBT version number back to 0.");
		}
	}

	response = json_stream_success(cmd);
	json_add_psbt(response, "psbt", psbt);
	json_add_num(response, "feerate_per_kw", feerate_per_kw);
	json_add_num(response, "estimated_final_weight", weight);
	json_add_amount_sat_msat(response, "excess_msat", excess);
	if (change_outnum != -1)
		json_add_num(response, "change_outnum", change_outnum);
	if (reserve)
		reserve_and_report(response, cmd->ld->wallet, current_height,
				   reserve, utxos);
	return command_success(cmd, response);
}

static inline u32 minconf_to_maxheight(u32 minconf, struct lightningd *ld)
{
	/* No confirmations is special, we need to disable the check in the
	 * selection */
	if (minconf == 0)
		return 0;

	/* Avoid wrapping around and suddenly allowing any confirmed
	 * outputs. Since we can't have a coinbase output, and 0 is taken for
	 * the disable case, we can just clamp to 1. */
	if (minconf >= ld->topology->tip->height)
		return 1;
	return ld->topology->tip->height - minconf + 1;
}

/* Returns false if it needed to create change, but couldn't afford. */
static bool change_for_emergency(struct lightningd *ld,
				 bool have_anchor_channel,
				 struct utxo **utxos,
				 u32 feerate_per_kw,
				 u32 weight,
				 struct amount_sat *excess,
				 struct amount_sat *change)
{
	struct amount_sat needed = ld->emergency_sat, fee;

	/* Only needed for anchor channels */
	if (!have_anchor_channel)
		return true;

	/* Fine if rest of wallet has funds.  Otherwise it may reduce
	 * needed amount. */
	if (wallet_has_funds(ld->wallet,
			     cast_const2(const struct utxo **, utxos),
			     get_block_height(ld->topology),
			     &needed))
		return true;

	/* If we can afford the rest with existing change output, great (or
	 * ld->emergency_sat is 0) */
	if (amount_sat_greater_eq(change_amount(*change,
						feerate_per_kw, weight),
				  needed))
		return true;

	/* Try splitting excess to add to change. */
	fee = change_fee(feerate_per_kw, weight);
	if (!amount_sat_sub(excess, *excess, fee)
	    || !amount_sat_sub(excess, *excess, needed))
		return false;

	if (!amount_sat_add(change, *change, fee)
	    || !amount_sat_add(change, *change, needed))
		abort();

	/* We *will* get a change output now! */
	assert(amount_sat_eq(change_amount(*change, feerate_per_kw, weight),
			     needed));
	return true;
}

static struct command_result *json_fundpsbt(struct command *cmd,
					      const char *buffer,
					      const jsmntok_t *obj UNNEEDED,
					      const jsmntok_t *params)
{
	struct utxo **utxos;
	const struct utxo **excluded;
	u32 *feerate_per_kw;
	u32 *minconf, *weight, *min_witness_weight;
	struct amount_sat *amount, input, diff, change;
	bool all, *excess_as_change, *nonwrapped, *keep_emergency_funds;
	u32 *locktime, *reserve, maxheight;
	u32 current_height;

	if (!param_check(cmd, buffer, params,
			 p_req("satoshi", param_sat_or_all, &amount),
			 p_req("feerate", param_feerate, &feerate_per_kw),
			 p_req("startweight", param_number, &weight),
			 p_opt_def("minconf", param_number, &minconf, 1),
			 p_opt_def("reserve", param_number, &reserve,
				   RESERVATION_DEFAULT),
			 p_opt("locktime", param_number, &locktime),
			 p_opt_def("min_witness_weight", param_number,
				   &min_witness_weight, 0),
			 p_opt_def("excess_as_change", param_bool,
				   &excess_as_change, false),
			 p_opt_def("nonwrapped", param_bool,
				   &nonwrapped, false),
			 p_opt_def("opening_anchor_channel", param_bool,
				   &keep_emergency_funds, false),
			 NULL))
		return command_param_failed();

	/* If we have anchor channels, we definitely need to keep
	 * emergency funds.  */
	if (have_anchor_channel(cmd->ld))
		*keep_emergency_funds = true;

	all = amount_sat_eq(*amount, AMOUNT_SAT(-1ULL));
	maxheight = minconf_to_maxheight(*minconf, cmd->ld);

	current_height = get_block_height(cmd->ld->topology);

	/* We keep adding until we meet their output requirements. */
	utxos = tal_arr(cmd, struct utxo *, 0);

	/* Either uneconomical at this feerate, or already included. */
	excluded = tal_arr(cmd, const struct utxo *, 0);

	input = AMOUNT_SAT(0);
	while (!inputs_sufficient(input, *amount, *feerate_per_kw, *weight,
				  &diff)) {
		struct utxo *utxo;
		struct amount_sat fee;
		u32 utxo_weight;

		utxo = wallet_find_utxo(utxos, cmd->ld->wallet,
					current_height,
					&diff,
					*feerate_per_kw,
					maxheight,
					*nonwrapped,
					excluded);

		if (utxo) {
			tal_arr_expand(&excluded, utxo);
			utxo_weight = utxo_spend_weight(utxo,
							*min_witness_weight);
			fee = amount_tx_fee(*feerate_per_kw, utxo_weight);

			/* Uneconomic to add this utxo, skip it */
			if (!all && amount_sat_greater_eq(fee, utxo->amount))
				continue;

			tal_arr_expand(&utxos, utxo);

			/* It supplies more input. */
			if (!amount_sat_add(&input, input, utxo->amount))
				return command_fail(cmd, LIGHTNINGD,
						    "impossible UTXO value");

			/* But also adds weight */
			*weight += utxo_weight;
			continue;
		}

		/* If they said "all", we expect to run out of utxos. */
		if (all && tal_count(utxos))
			break;

		/* Since it's possible the lack of utxos is because we haven't
		 * finished syncing yet, report a sync timing error first */
		if (!topology_synced(cmd->ld->topology))
			return command_fail(cmd,
					    FUNDING_STILL_SYNCING_BITCOIN,
					    "Cannot afford: still syncing with bitcoin network...");

		return command_fail(cmd, FUND_CANNOT_AFFORD,
				    "Could not afford %s using all %zu available UTXOs: %s short",
				    all ? "all"
				    : fmt_amount_sat(tmpctx, *amount),
				    tal_count(utxos),
				    all ? "all"
				    : fmt_amount_sat(tmpctx, diff));
	}

	tal_free(excluded);

	if (all) {
		/* We need to afford one non-dust output, at least. */
		if (!inputs_sufficient(input, AMOUNT_SAT(0),
				       *feerate_per_kw, *weight,
				       &diff)
		    || amount_sat_less(diff, chainparams->dust_limit)) {
			if (!topology_synced(cmd->ld->topology))
				return command_fail(cmd,
						    FUNDING_STILL_SYNCING_BITCOIN,
						    "Cannot afford: still syncing with bitcoin network...");
			return command_fail(cmd, FUND_CANNOT_AFFORD,
					    "All %zu inputs could not afford"
					    " fees",
					    tal_count(utxos));
		}
		*excess_as_change = false;
	}

	/* Turn excess into change. */
	if (*excess_as_change) {
		change = diff;
		diff = AMOUNT_SAT(0);
	} else {
		change = AMOUNT_SAT(0);
	}

	/* If needed, add change output for emergency_sat */
	if (!change_for_emergency(cmd->ld,
				  *keep_emergency_funds,
				  utxos, *feerate_per_kw, *weight,
				  &diff, &change)) {
		return command_fail(cmd, FUND_CANNOT_AFFORD_WITH_EMERGENCY,
				    "We would not have enough left for min-emergency-msat %s",
				    fmt_amount_sat(tmpctx,
						   cmd->ld->emergency_sat));
	}

	if (command_check_only(cmd))
		return command_check_done(cmd);

	return finish_psbt(cmd, utxos, *feerate_per_kw, *weight, diff, *reserve,
			   locktime, change);
}

static const struct json_command fundpsbt_command = {
	"fundpsbt",
	json_fundpsbt,
	false
};
AUTODATA(json_command, &fundpsbt_command);

static struct command_result *json_addpsbtoutput(struct command *cmd,
					    const char *buffer,
					    const jsmntok_t *obj UNNEEDED,
					    const jsmntok_t *params)
{
	struct json_stream *response;
	struct amount_sat *amount;
	struct wally_psbt *psbt;
	u32 *locktime;
	ssize_t outnum;
	u32 weight;
	struct pubkey pubkey;
	s64 keyidx;
	const u8 *b32script;

	if (!param_check(cmd, buffer, params,
			 p_req("satoshi", param_sat, &amount),
			 p_opt("initialpsbt", param_psbt, &psbt),
			 p_opt("locktime", param_number, &locktime),
			 p_opt("destination", param_bitcoin_address,
			       &b32script),
			 NULL))
		return command_param_failed();

	if (!psbt) {
		if (!locktime) {
			locktime = tal(cmd, u32);
			*locktime = default_locktime(cmd->ld->topology);
		}
		psbt = create_psbt(cmd, 0, 0, *locktime);
	} else if (locktime) {
		return command_fail(cmd, FUNDING_PSBT_INVALID,
				    "Can't set locktime of an existing {initialpsbt}");
	}

	if (!validate_psbt(psbt))
		return command_fail(cmd,
				    FUNDING_PSBT_INVALID,
				    "PSBT failed to validate.");

	if (amount_sat_less(*amount, chainparams->dust_limit))
		return command_fail(cmd, FUND_OUTPUT_IS_DUST,
				    "Receive amount is below dust limit (%s)",
				    fmt_amount_sat(tmpctx,
						   chainparams->dust_limit));

	if (command_check_only(cmd))
		return command_check_done(cmd);

	/* Get a change adddress */
	if (!b32script) {
		keyidx = wallet_get_newindex(cmd->ld);
		if (keyidx < 0)
			return command_fail(cmd, LIGHTNINGD,
					    "Failed to generate change address."
					    " Keys exhausted.");

		if (chainparams->is_elements) {
			bip32_pubkey(cmd->ld, &pubkey, keyidx);
			b32script = scriptpubkey_p2wpkh(tmpctx, &pubkey);
		} else {
			b32script = p2tr_for_keyidx(tmpctx, cmd->ld, keyidx);
		}

		if (!b32script) {
			return command_fail(cmd, LIGHTNINGD,
					    "Failed to generate change address."
					    " Keys generation failure");
		}
		txfilter_add_scriptpubkey(cmd->ld->owned_txfilter, b32script);
	}

	outnum = psbt->num_outputs;
	psbt_append_output(psbt, b32script, *amount);
	/* Add additional weight of output */
	weight = bitcoin_tx_output_weight(
			chainparams->is_elements ? BITCOIN_SCRIPTPUBKEY_P2WPKH_LEN : BITCOIN_SCRIPTPUBKEY_P2TR_LEN);

	response = json_stream_success(cmd);
	json_add_psbt(response, "psbt", psbt);
	json_add_num(response, "estimated_added_weight", weight);
	json_add_num(response, "outnum", outnum);
	return command_success(cmd, response);
}

static const struct json_command addpsbtoutput_command = {
	"addpsbtoutput",
	json_addpsbtoutput,
	false
};
AUTODATA(json_command, &addpsbtoutput_command);

static struct command_result *param_txout(struct command *cmd,
					  const char *name,
					  const char *buffer,
					  const jsmntok_t *tok,
					  struct utxo ***utxos)
{
	size_t i;
	const jsmntok_t *curr;

	*utxos = tal_arr(cmd, struct utxo *, tok->size);

	json_for_each_arr(i, curr, tok) {
		struct utxo *utxo;
		jsmntok_t txid_tok, outnum_tok;
		struct bitcoin_outpoint outpoint;

		if (!split_tok(buffer, curr, ':', &txid_tok, &outnum_tok))
			return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
					    "Could not decode the outpoint from \"%s\""
					    " The utxos should be specified as"
					    " 'txid:output_index'.",
					    json_strdup(tmpctx, buffer, curr));

		if (!json_to_txid(buffer, &txid_tok, &outpoint.txid)) {
			return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
					    "Could not get a txid out of \"%s\"",
					    json_strdup(tmpctx, buffer, &txid_tok));
		}
		if (!json_to_number(buffer, &outnum_tok, &outpoint.n)) {
			return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
					    "Could not get a vout out of \"%s\"",
					    json_strdup(tmpctx, buffer, &outnum_tok));
		}

		utxo = wallet_utxo_get(*utxos, cmd->ld->wallet, &outpoint);
		if (!utxo) {
			return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
					    "Unknown UTXO %s",
					    fmt_bitcoin_outpoint(tmpctx,
							   &outpoint));
		}
		if (utxo->status == OUTPUT_STATE_SPENT) {
			return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
					    "Already spent UTXO %s",
					    fmt_bitcoin_outpoint(tmpctx,
							   &outpoint));
		}

		(*utxos)[i] = utxo;
	}

	if (i == 0)
		return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
				    "Please specify an array of 'txid:output_index',"
				    " not \"%.*s\"",
				    tok->end - tok->start,
				    buffer + tok->start);
	return NULL;
}

static struct command_result *json_utxopsbt(struct command *cmd,
					    const char *buffer,
					    const jsmntok_t *obj UNNEEDED,
					    const jsmntok_t *params)
{
	struct utxo **utxos;
	u32 *feerate_per_kw, *weight, *min_witness_weight;
	bool all, *reserved_ok, *excess_as_change, *keep_emergency_funds;
	struct amount_sat *amount, input, excess, change;
	u32 current_height, *locktime, *reserve;

	if (!param_check(cmd, buffer, params,
			 p_req("satoshi", param_sat_or_all, &amount),
			 p_req("feerate", param_feerate, &feerate_per_kw),
			 p_req("startweight", param_number, &weight),
			 p_req("utxos", param_txout, &utxos),
			 p_opt_def("reserve", param_number, &reserve,
				   RESERVATION_DEFAULT),
			 p_opt_def("reservedok", param_bool, &reserved_ok, false),
			 p_opt("locktime", param_number, &locktime),
			 p_opt_def("min_witness_weight", param_number,
				   &min_witness_weight, 0),
			 p_opt_def("excess_as_change", param_bool,
				   &excess_as_change, false),
			 p_opt_def("opening_anchor_channel", param_bool,
				   &keep_emergency_funds, false),
			 NULL))
		return command_param_failed();

	/* If we have anchor channels, we definitely need to keep
	 * emergency funds.  */
	if (have_anchor_channel(cmd->ld))
		*keep_emergency_funds = true;

	all = amount_sat_eq(*amount, AMOUNT_SAT(-1ULL));

	input = AMOUNT_SAT(0);
	current_height = get_block_height(cmd->ld->topology);
	for (size_t i = 0; i < tal_count(utxos); i++) {
		const struct utxo *utxo = utxos[i];

		if (!*reserved_ok && utxo_is_reserved(utxo, current_height))
			return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
					    "UTXO %s already reserved",
					    fmt_bitcoin_outpoint(tmpctx,
							   &utxo->outpoint));
		if (utxo_is_csv_locked(utxo, current_height))
			return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
					    "UTXO %s is csv locked (%u)",
					    fmt_bitcoin_outpoint(tmpctx,
							   &utxo->outpoint),
					    utxo->close_info->csv);


		/* It supplies more input. */
		if (!amount_sat_add(&input, input, utxo->amount))
			return command_fail(cmd, LIGHTNINGD,
					    "impossible UTXO value");

		/* But also adds weight */
		*weight += utxo_spend_weight(utxo, *min_witness_weight);
	}

	if (all) {
		/* We need to afford one non-dust output, at least. */
		if (!inputs_sufficient(input, AMOUNT_SAT(0),
				       *feerate_per_kw, *weight,
				       &excess)
		    || amount_sat_less(excess, chainparams->dust_limit)) {
			return command_fail(cmd, FUND_CANNOT_AFFORD,
					    "Could not afford anything using UTXOs totalling %s with weight %u at feerate %u",
					    fmt_amount_sat(tmpctx, input),
					    *weight, *feerate_per_kw);
		}
		*excess_as_change = false;
	} else {
		if (!inputs_sufficient(input, *amount,
				       *feerate_per_kw, *weight, &excess)) {
			return command_fail(cmd, FUND_CANNOT_AFFORD,
				    "Could not afford %s using UTXOs totalling %s with weight %u at feerate %u",
					    fmt_amount_sat(tmpctx, *amount),
					    fmt_amount_sat(tmpctx, input),
					    *weight, *feerate_per_kw);
		}
	}
	if (*excess_as_change) {
		change = excess;
		excess = AMOUNT_SAT(0);
	} else {
		change = AMOUNT_SAT(0);
	}

	/* If needed, add change output for emergency_sat */
	if (!change_for_emergency(cmd->ld,
				  *keep_emergency_funds,
				  utxos, *feerate_per_kw, *weight,
				  &excess, &change)) {
		return command_fail(cmd, FUND_CANNOT_AFFORD_WITH_EMERGENCY,
				    "We would not have enough left for min-emergency-msat %s",
				    fmt_amount_sat(tmpctx,
						   cmd->ld->emergency_sat));
	}

	if (command_check_only(cmd))
		return command_check_done(cmd);

	return finish_psbt(cmd, utxos, *feerate_per_kw, *weight, excess,
			   *reserve, locktime, change);
}
static const struct json_command utxopsbt_command = {
	"utxopsbt",
	json_utxopsbt,
	false
};
AUTODATA(json_command, &utxopsbt_command);
