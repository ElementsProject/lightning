/* Dealing with reserving UTXOs */
#include <common/json_command.h>
#include <common/json_helpers.h>
#include <common/jsonrpc_errors.h>
#include <common/wallet_tx.h>
#include <lightningd/jsonrpc.h>
#include <lightningd/lightningd.h>
#include <wallet/wallet.h>
#include <wallet/walletrpc.h>

static bool was_reserved(enum output_status oldstatus,
			 const u32 *reserved_til,
			 u32 current_height)
{
	if (oldstatus != output_state_reserved)
		return false;

	return *reserved_til > current_height;
}

static void json_add_reservestatus(struct json_stream *response,
				   const struct utxo *utxo,
				   enum output_status oldstatus,
				   u32 old_res,
				   u32 current_height)
{
	json_object_start(response, NULL);
	json_add_txid(response, "txid", &utxo->txid);
	json_add_u32(response, "vout", utxo->outnum);
	json_add_bool(response, "was_reserved",
		      was_reserved(oldstatus, &old_res, current_height));
	json_add_bool(response, "reserved",
		      is_reserved(utxo, current_height));
	if (utxo->reserved_til)
		json_add_u32(response, "reserved_to_block",
			     *utxo->reserved_til);
	json_object_end(response);
}

/* Reserve these UTXOs and print to JSON */
static void reserve_and_report(struct json_stream *response,
			       struct wallet *wallet,
			       u32 current_height,
			       struct utxo **utxos)
{
	json_array_start(response, "reservations");
	for (size_t i = 0; i < tal_count(utxos); i++) {
		enum output_status oldstatus;
		u32 old_res;

		oldstatus = utxos[i]->status;
		old_res = utxos[i]->reserved_til ? *utxos[i]->reserved_til : 0;

		if (!wallet_reserve_utxo(wallet,
					 utxos[i],
					 current_height)) {
			fatal("Unable to reserve %s:%u!",
			      type_to_string(tmpctx,
					     struct bitcoin_txid,
					     &utxos[i]->txid),
			      utxos[i]->outnum);
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
	u32 current_height;

	if (!param(cmd, buffer, params,
		   p_req("psbt", param_psbt, &psbt),
		   p_opt_def("exclusive", param_bool, &exclusive, true),
		   NULL))
		return command_param_failed();

	current_height = get_block_height(cmd->ld->topology);
	for (size_t i = 0; i < psbt->tx->num_inputs; i++) {
		struct bitcoin_txid txid;
		struct utxo *utxo;

		wally_tx_input_get_txid(&psbt->tx->inputs[i], &txid);
		utxo = wallet_utxo_get(cmd, cmd->ld->wallet,
				       &txid, psbt->tx->inputs[i].index);
		if (!utxo)
			continue;
		if (*exclusive && is_reserved(utxo, current_height)) {
			return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
					    "%s:%u already reserved",
					    type_to_string(tmpctx,
							   struct bitcoin_txid,
							   &utxo->txid),
					    utxo->outnum);
		}
		if (utxo->status == output_state_spent)
			return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
					    "%s:%u already spent",
					    type_to_string(tmpctx,
							   struct bitcoin_txid,
							   &utxo->txid),
					    utxo->outnum);
		tal_arr_expand(&utxos, utxo);
	}

	response = json_stream_success(cmd);
	reserve_and_report(response, cmd->ld->wallet, current_height, utxos);
	return command_success(cmd, response);
}

static const struct json_command reserveinputs_command = {
	"reserveinputs",
	"bitcoin",
	json_reserveinputs,
	"Reserve utxos (or increase their reservation)",
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

	if (!param(cmd, buffer, params,
		   p_req("psbt", param_psbt, &psbt),
		   NULL))
		return command_param_failed();

	response = json_stream_success(cmd);
	json_array_start(response, "reservations");
	for (size_t i = 0; i < psbt->tx->num_inputs; i++) {
		struct bitcoin_txid txid;
		struct utxo *utxo;
		enum output_status oldstatus;
		u32 old_res;

		wally_tx_input_get_txid(&psbt->tx->inputs[i], &txid);
		utxo = wallet_utxo_get(cmd, cmd->ld->wallet,
				       &txid, psbt->tx->inputs[i].index);
		if (!utxo || utxo->status != output_state_reserved)
			continue;

		oldstatus = utxo->status;
		old_res = *utxo->reserved_til;

		wallet_unreserve_utxo(cmd->ld->wallet,
				      utxo,
				      get_block_height(cmd->ld->topology));

		json_add_reservestatus(response, utxo, oldstatus, old_res,
				       get_block_height(cmd->ld->topology));
	}
	json_array_end(response);
	return command_success(cmd, response);
}

static const struct json_command unreserveinputs_command = {
	"unreserveinputs",
	"bitcoin",
	json_unreserveinputs,
	"Unreserve utxos (or at least, reduce their reservation)",
	false
};
AUTODATA(json_command, &unreserveinputs_command);


static struct command_result *json_fundpsbt(struct command *cmd,
					      const char *buffer,
					      const jsmntok_t *obj UNNEEDED,
					      const jsmntok_t *params)
{
	struct json_stream *response;
	struct utxo **utxos;
	u32 *feerate_per_kw;
	u32 *minconf;
	struct amount_sat *amount, input, needed, excess, total_fee;
	bool all, *reserve;
	u32 locktime, maxheight, current_height;
	struct bitcoin_tx *tx;

	if (!param(cmd, buffer, params,
		   p_req("satoshi", param_sat_or_all, &amount),
		   p_req("feerate", param_feerate_val, &feerate_per_kw),
		   p_opt_def("minconf", param_number, &minconf, 1),
		   p_opt_def("reserve", param_bool, &reserve, true),
		   NULL))
		return command_param_failed();

	all = amount_sat_eq(*amount, AMOUNT_SAT(-1ULL));
	maxheight = minconf_to_maxheight(*minconf, cmd->ld);

	current_height = get_block_height(cmd->ld->topology);

	/* We keep adding until we meet their output requirements. */
	input = AMOUNT_SAT(0);
	utxos = tal_arr(cmd, struct utxo *, 0);
	total_fee = AMOUNT_SAT(0);
	while (amount_sat_sub(&needed, *amount, input)
	       && !amount_sat_eq(needed, AMOUNT_SAT(0))) {
		struct utxo *utxo;

		utxo = wallet_find_utxo(utxos, cmd->ld->wallet,
					cmd->ld->topology->tip->height,
					&needed,
					*feerate_per_kw,
					maxheight,
					cast_const2(const struct utxo **, utxos));
		if (utxo) {
			struct amount_sat fee;
			tal_arr_expand(&utxos, utxo);

			/* It supplies more input. */
			if (!amount_sat_add(&input, input, utxo->amount))
				return command_fail(cmd, LIGHTNINGD,
						    "impossible UTXO value");

			/* But increase amount needed, to pay for new input */
			fee = amount_tx_fee(*feerate_per_kw,
					    utxo_spend_weight(utxo));
			if (!amount_sat_add(amount, *amount, fee))
				/* Either they specified "all", or we
				 * will fail anyway. */
				*amount = AMOUNT_SAT(-1ULL);
			if (!amount_sat_add(&total_fee, total_fee, fee))
				return command_fail(cmd, LIGHTNINGD,
						    "impossible fee value");
			continue;
		}

		/* If they said "all", we expect to run out of utxos. */
		if (all) {
			/* If we have none at all though, fail */
			if (!tal_count(utxos))
				return command_fail(cmd, FUND_CANNOT_AFFORD,
						    "No available UTXOs");
			break;
		}

		return command_fail(cmd, FUND_CANNOT_AFFORD,
				    "Could not afford %s using all %zu available UTXOs: %s short",
				    type_to_string(tmpctx,
						   struct amount_sat,
						   amount),
				    tal_count(utxos),
				    type_to_string(tmpctx,
						   struct amount_sat,
						   &needed));
	}

	/* Setting the locktime to the next block to be mined has multiple
	 * benefits:
	 * - anti fee-snipping (even if not yet likely)
	 * - less distinguishable transactions (with this we create
	 *   general-purpose transactions which looks like bitcoind:
	 *   native segwit, nlocktime set to tip, and sequence set to
	 *   0xFFFFFFFD by default. Other wallets are likely to implement
	 *   this too).
	 */
	locktime = current_height;

	/* Eventually fuzz it too. */
	if (locktime > 100 && pseudorand(10) == 0)
		locktime -= pseudorand(100);

	/* FIXME: tx_spending_utxos does more than we need, but there
	 * are other users right now. */
	tx = tx_spending_utxos(cmd, chainparams,
			       cast_const2(const struct utxo **, utxos),
			       cmd->ld->wallet->bip32_base,
			       false, 0, locktime,
			       BITCOIN_TX_RBF_SEQUENCE);

	if (all) {
		/* Count everything not going towards fees as excess. */
		if (!amount_sat_sub(&excess, input, total_fee))
			return command_fail(cmd, FUND_CANNOT_AFFORD,
					    "All %zu inputs could not afford"
					    " %s fees",
					    tal_count(utxos),
					    type_to_string(tmpctx,
							   struct amount_sat,
							   &total_fee));
	} else {
		/* This was the condition of exiting the loop above! */
		if (!amount_sat_sub(&excess, input, *amount))
			abort();
	}

	response = json_stream_success(cmd);
	json_add_psbt(response, "psbt", tx->psbt);
	json_add_amount_sat_only(response, "excess_msat", excess);
	if (*reserve)
		reserve_and_report(response, cmd->ld->wallet, current_height,
				   utxos);
	return command_success(cmd, response);
}

static const struct json_command fundpsbt_command = {
	"fundpsbt",
	"bitcoin",
	json_fundpsbt,
	"Create PSBT using enough utxos to allow an output of {satoshi} at {feerate}",
	false
};
AUTODATA(json_command, &fundpsbt_command);
