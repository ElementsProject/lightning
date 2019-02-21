#ifndef LIGHTNING_COMMON_WALLET_TX_H
#define LIGHTNING_COMMON_WALLET_TX_H
#include "config.h"
#include <ccan/short_types/short_types.h>
#include <common/amount.h>
#include <lightningd/json.h>
#include <lightningd/jsonrpc.h>
#include <lightningd/lightningd.h>

/* A specification of funds in the wallet used for funding channels and
 * withdrawal.
 */
struct wallet_tx {
	struct command *cmd;
	struct amount_sat amount, change;
	u32 change_key_index;
	const struct utxo **utxos;

	bool all_funds; /* In this case, amount is a maximum. */
};

void wtx_init(struct command *cmd, struct wallet_tx *wtx, struct amount_sat max);

struct command_result *param_wtx(struct command *cmd,
				 const char *name,
				 const char *buffer,
				 const jsmntok_t *tok,
				 struct wallet_tx *wtx);

struct command_result *wtx_select_utxos(struct wallet_tx *tx,
					u32 fee_rate_per_kw,
					size_t out_len,
					u32 maxheight);

static inline u32 minconf_to_maxheight(u32 minconf, struct lightningd *ld)
{
	/* No confirmations is special, we need to disable the check in the
	 * selection */
	if (minconf == 0)
		return 0;
	return ld->topology->tip->height - minconf + 1;
}
#endif /* LIGHTNING_COMMON_WALLET_TX_H */
