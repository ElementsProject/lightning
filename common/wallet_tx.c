#include <common/json_command.h>
#include <common/jsonrpc_errors.h>
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
				    "'%s' should be satoshis or 'all', not '%.*s'",
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

static struct command_result *check_amount(const struct wallet_tx *wtx,
					   struct amount_sat amount)
{
	if (tal_count(wtx->utxos) == 0) {
		return command_fail(wtx->cmd, FUND_CANNOT_AFFORD,
				    "Cannot afford transaction");
	}
	if (amount_sat_less(amount, get_chainparams(wtx->cmd->ld)->dust_limit)) {
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
		tx->utxos = wallet_select_all(tx->cmd, tx->cmd->ld->wallet,
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

	tx->utxos = wallet_select_coins(tx->cmd, tx->cmd->ld->wallet,
					tx->amount,
					fee_rate_per_kw, out_len,
					maxheight,
					&fee_estimate, &tx->change);
	res = check_amount(tx, tx->amount);
	if (res)
		return res;

	if (amount_sat_less(tx->change, get_chainparams(tx->cmd->ld)->dust_limit)) {
		tx->change = AMOUNT_SAT(0);
		tx->change_key_index = 0;
	} else {
		tx->change_key_index = wallet_get_newindex(tx->cmd->ld);
	}
	return NULL;
}
