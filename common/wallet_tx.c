#include <ccan/ccan/opt/opt.h>
#include <ccan/tal/str/str.h>
#include <common/json_command.h>
#include <common/json_helpers.h>
#include <common/jsonrpc_errors.h>
#include <common/utils.h>
#include <common/wallet_tx.h>
#include <inttypes.h>
#include <wallet/wallet.h>

void wtx_init(struct command *cmd, struct wallet_tx *wtx, struct amount_sat max)
{
	wtx->cmd = cmd;
	wtx->amount = max;
}

struct command_result *param_wtx(struct command *cmd,
				 const char *name,
				 const char *buffer,
				 const jsmntok_t *tok,
				 struct wallet_tx *wtx)
{
	struct amount_sat max = wtx->amount;

	if (json_tok_streq(buffer, tok, "all")) {
		wtx->all_funds = true;
		return NULL;
	}
	wtx->all_funds = false;

	if (!parse_amount_sat(&wtx->amount,
			      buffer + tok->start, tok->end - tok->start))
		return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
					"'%s' should be an amount in satoshis or all, not '%.*s'",
					name,
					tok->end - tok->start,
					buffer + tok->start);

	if (amount_sat_greater(wtx->amount, max))
		return command_fail(wtx->cmd, FUND_MAX_EXCEEDED,
				    "Amount exceeded %s",
				    type_to_string(tmpctx, struct amount_sat,
						   &max));
        return NULL;
}

struct command_result *param_utxos(struct command *cmd,
				 const char *name,
				 const char *buffer,
				 const jsmntok_t *tok,
				 const struct utxo ***utxos)
{
	size_t i;
	const jsmntok_t *curr;
	struct bitcoin_txid **txids = tal_arr(cmd, struct bitcoin_txid*, 0);
	unsigned int **outnums = tal_arr(cmd, unsigned int*, 0);

	json_for_each_arr(i, curr, tok) {
		jsmntok_t txid_tok, outnum_tok;
		if (!split_tok(buffer, curr, ':', &txid_tok, &outnum_tok))
			return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
								"Could not decode the outpoint from \"%s\""
								" The utxos should be specified as"
								" 'txid:output_index'.",
								json_strdup(tmpctx, buffer, curr));

		struct bitcoin_txid *txid = tal(txids, struct bitcoin_txid);
		unsigned int *outnum = tal(txids, unsigned int);
		if (!json_to_txid(buffer, (const jsmntok_t*)&txid_tok, txid)) {
			return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
								"Could not get a txid out of \"%s\"",
								json_strdup(tmpctx, buffer, &txid_tok));
		}
		if (!json_to_number(buffer, (const jsmntok_t*)&outnum_tok, outnum))
			return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
								"Could not get a vout out of \"%s\"",
								json_strdup(tmpctx, buffer, &outnum_tok));

		tal_arr_expand(&txids, txid);
		tal_arr_expand(&outnums, outnum);
	}

	if (!tal_count(txids) || !tal_count(outnums))
		return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
							"Please specify an array of 'txid:output_index',"
							" not \"%.*s\"",
							tok->end - tok->start,
							buffer + tok->start);

	*utxos = wallet_select_specific(cmd, cmd->ld->wallet, txids, outnums);
	tal_free(txids);
	tal_free(outnums);

	if (!*utxos)
		return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
							"Could not decode all of the outpoints. The utxos"
							" should be specified as an array of "
							" 'txid:output_index'.");
	if (tal_count(*utxos) == 0)
		return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
							"No matching utxo was found from the wallet. "
							"You can get a list of the wallet utxos with"
							" the `listfunds` RPC call.");
	return NULL;
}

static struct command_result *check_amount(const struct wallet_tx *wtx,
					   struct amount_sat amount)
{
	if (tal_count(wtx->utxos) == 0) {
		/* Since it's possible the lack of utxos is because we haven't finished
		 * syncing yet, report a sync timing error first */
		if (!topology_synced(wtx->cmd->ld->topology))
			return command_fail(wtx->cmd, FUNDING_STILL_SYNCING_BITCOIN,
					    "Still syncing with bitcoin network");

		return command_fail(wtx->cmd, FUND_CANNOT_AFFORD,
				    "Cannot afford transaction");
	}

	if (amount_sat_less(amount, chainparams->dust_limit)) {
		return command_fail(wtx->cmd, FUND_OUTPUT_IS_DUST,
				    "Output %s would be dust",
				    type_to_string(tmpctx, struct amount_sat,
						   &amount));
	}
	return NULL;
}

struct command_result *wtx_select_utxos(struct wallet_tx *tx,
					u32 fee_rate_per_kw,
					size_t out_len,
					u32 maxheight)
{
	struct command_result *res;
	struct amount_sat fee_estimate;

	if (tx->all_funds) {
		struct amount_sat amount;
		tx->utxos = wallet_select_all(tx, tx->cmd->ld->wallet,
					      fee_rate_per_kw, out_len,
					      maxheight,
					      &amount,
					      &fee_estimate);
		res = check_amount(tx, amount);
		if (res)
			return res;

		/* tx->amount is max permissible */
		if (amount_sat_less_eq(amount, tx->amount)) {
			tx->change = AMOUNT_SAT(0);
			tx->change_key_index = 0;
			tx->amount = amount;
			return NULL;
		}

		/* Too much?  Try again, but ask for limit instead. */
		tx->all_funds = false;
		tx->utxos = tal_free(tx->utxos);
	}

	tx->utxos = wallet_select_coins(tx, tx->cmd->ld->wallet,
					true, tx->amount,
					fee_rate_per_kw, out_len,
					maxheight,
					&fee_estimate, &tx->change);
	if (!tx->utxos) {
		/* Try again, without change this time */
		tx->utxos = wallet_select_coins(tx, tx->cmd->ld->wallet,
						false, tx->amount,
						fee_rate_per_kw, out_len,
						maxheight,
						&fee_estimate, &tx->change);

	}

	res = check_amount(tx, tx->amount);
	if (res)
		return res;

	if (amount_sat_less(tx->change, chainparams->dust_limit)) {
		tx->change = AMOUNT_SAT(0);
		tx->change_key_index = 0;
	} else {
		tx->change_key_index = wallet_get_newindex(tx->cmd->ld);
	}
	return NULL;
}

struct command_result *wtx_from_utxos(struct wallet_tx *tx,
					u32 fee_rate_per_kw,
					size_t out_len,
					u32 maxheight,
					const struct utxo **utxos)
{
	size_t weight;
	struct amount_sat total_amount, fee_estimate;

	tx->change = AMOUNT_SAT(0);
	tx->change_key_index = 0;
	total_amount = AMOUNT_SAT(0);

	/* The transaction has `tal_count(tx.utxos)` inputs and one output */
	/* (version + in count + out count + locktime)  (index + value + script length) */
	/* + segwit marker + flag */
	weight = 4 * (4 + 1 + 1 + 4) + 4 * (8 + 1 + out_len) + 1 + 1;
	for (size_t i = 0; i < tal_count(utxos); i++) {
		if (maxheight > 0 &&
		    (!utxos[i]->blockheight || *utxos[i]->blockheight > maxheight)) {
			tal_arr_remove(&utxos, i);
			continue;
		}
		/* txid + index + sequence + script_len */
		weight += (32 + 4 + 4 + 1) * 4;
		/* P2SH variants include push of <0 <20-byte-key-hash>> */
		if (utxos[i]->is_p2sh)
			weight += 23 * 4;
		/* Account for witness (1 byte count + sig + key) */
		weight += 1 + (1 + 73 + 1 + 33);
		if (!amount_sat_add(&total_amount, total_amount, utxos[i]->amount))
			fatal("Overflow when computing input amount");
	}
	tx->utxos = tal_steal(tx, utxos);

	if (!tx->all_funds && amount_sat_less(tx->amount, total_amount)
			&& !amount_sat_sub(&tx->change, total_amount, tx->amount))
		fatal("Overflow when computing change");

	if (amount_sat_greater_eq(tx->change, chainparams->dust_limit)) {
		/* Add the change output's weight */
		weight += (8 + 1 + out_len) * 4;
	}

	fee_estimate = amount_tx_fee(fee_rate_per_kw, weight);

	if (tx->all_funds || amount_sat_eq(tx->change, AMOUNT_SAT(0))) {
		tx->amount = total_amount;
		if (!amount_sat_sub(&tx->amount, tx->amount, fee_estimate))
			return command_fail(tx->cmd, FUND_CANNOT_AFFORD,
					    "Cannot afford transaction with %s"
					    " sats of fees, make sure to use "
					    "confirmed utxos.",
					    type_to_string(tmpctx, struct amount_sat,
							   &fee_estimate));
	} else {
		if (!amount_sat_sub(&tx->change, tx->change, fee_estimate)) {
			/* Try again without a change output */
			weight -= (8 + 1 + out_len) * 4;
			fee_estimate = amount_tx_fee(fee_rate_per_kw, weight);
			if (!amount_sat_sub(&tx->change, tx->change, fee_estimate))
				return command_fail(tx->cmd, FUND_CANNOT_AFFORD,
						    "Cannot afford transaction with %s"
						    " sats of fees, make sure to use "
						    "confirmed utxos.",
						    type_to_string(tmpctx, struct amount_sat,
								   &fee_estimate));
			tx->change = AMOUNT_SAT(0);
		} else {
			tx->change_key_index = wallet_get_newindex(tx->cmd->ld);
		}
	}

	return check_amount(tx, tx->amount);
}
