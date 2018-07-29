#ifndef LIGHTNING_COMMON_WALLET_TX_H
#define LIGHTNING_COMMON_WALLET_TX_H
#include "config.h"
#include <ccan/short_types/short_types.h>
#include <lightningd/json.h>
#include <lightningd/jsonrpc.h>
#include <lightningd/lightningd.h>

/* A specification of funds in the wallet used for funding channels and
 * withdrawal.
 */
struct wallet_tx {
	struct command *cmd;
	u64 amount;
	u64 change;
	u32 change_key_index;
	const struct utxo **utxos;

	bool all_funds; /* In this case, amount is a maximum. */
};

void wtx_init(struct command *cmd, struct wallet_tx *wtx);
bool wtx_select_utxos(struct wallet_tx * tx, u32 fee_rate_per_kw,
		      size_t out_len);
#endif /* LIGHTNING_COMMON_WALLET_TX_H */
