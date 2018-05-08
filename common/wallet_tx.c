#include <common/wallet_tx.h>
#include <inttypes.h>
#include <lightningd/jsonrpc_errors.h>
#include <wallet/wallet.h>

void wtx_init(struct command *cmd, struct wallet_tx * wtx)
{
	wtx->cmd = cmd;
	wtx->amount = 0;
	wtx->change_key_index = 0;
	wtx->utxos = NULL;
	wtx->all_funds = false;
}

bool wtx_select_utxos(struct wallet_tx * tx, u32 fee_rate_per_kw,
	              size_t out_len)
{
	u64 fee_estimate;
	if (tx->all_funds) {
		tx->utxos = wallet_select_all(tx->cmd, tx->cmd->ld->wallet,
					      fee_rate_per_kw, out_len,
					      &tx->amount,
					      &fee_estimate);
		if (!tx->utxos || tx->amount < 546) {
			command_fail(tx->cmd, "Cannot afford fee %"PRIu64,
				     fee_estimate);
			return false;
		}
		tx->change = 0;
	} else {
		tx->utxos = wallet_select_coins(tx->cmd, tx->cmd->ld->wallet,
						tx->amount,
						fee_rate_per_kw, out_len,
						&fee_estimate, &tx->change);
		if (!tx->utxos || tx->amount < 546) {
			command_fail(tx->cmd,
			"Cannot afford funding transaction");
			return false;
		}
		if (tx->change < 546) {
			tx->change = 0;
			tx->change_key_index = 0;
		} else {
			tx->change_key_index = wallet_get_newindex(tx->cmd->ld);
		}
	}
	return true;
}
