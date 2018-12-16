#include <common/json_command.h>
#include <common/jsonrpc_errors.h>
#include <common/wallet_tx.h>
#include <inttypes.h>
#include <wallet/wallet.h>

void wtx_init(struct command *cmd, struct wallet_tx * wtx)
{
	wtx->cmd = cmd;
	wtx->amount = 0;
	wtx->change_key_index = 0;
	wtx->utxos = NULL;
	wtx->all_funds = false;
}

static struct command_result *check_amount(const struct wallet_tx *tx,
					   u64 amount)
{
	if (tal_count(tx->utxos) == 0) {
		return command_fail(tx->cmd, FUND_CANNOT_AFFORD,
				    "Cannot afford transaction");
	}
	if (amount < 546) {
		return command_fail(tx->cmd, FUND_OUTPUT_IS_DUST,
				    "Output %"PRIu64" satoshis would be dust",
				    amount);
	}
	return NULL;
}

struct command_result *wtx_select_utxos(struct wallet_tx *tx,
					u32 fee_rate_per_kw,
					size_t out_len)
{
	struct command_result *res;
	u64 fee_estimate;
	if (tx->all_funds) {
		u64 amount;
		tx->utxos = wallet_select_all(tx->cmd, tx->cmd->ld->wallet,
					      fee_rate_per_kw, out_len,
					      &amount,
					      &fee_estimate);
		res = check_amount(tx, amount);
		if (res)
			return res;

		if (amount <= tx->amount) {
			tx->change = 0;
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
					&fee_estimate, &tx->change);
	res = check_amount(tx, tx->amount);
	if (res)
		return res;

	if (tx->change < 546) {
		tx->change = 0;
		tx->change_key_index = 0;
	} else {
		tx->change_key_index = wallet_get_newindex(tx->cmd->ld);
	}
	return NULL;
}
