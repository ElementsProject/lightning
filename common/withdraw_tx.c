#include "withdraw_tx.h"
#include <assert.h>
#include <bitcoin/pubkey.h>
#include <bitcoin/script.h>
#include <ccan/ptrint/ptrint.h>
#include <common/key_derive.h>
#include <common/permute_tx.h>
#include <common/utils.h>
#include <common/utxo.h>
#include <string.h>
#include <wally_bip32.h>

struct bitcoin_tx *withdraw_tx(const tal_t *ctx,
			       const struct chainparams *chainparams,
			       const struct utxo **utxos,
			       struct bitcoin_tx_output **outputs,
			       const struct ext_key *bip32_base,
			       u32 nlocktime)
{
	struct bitcoin_tx *tx;
	int output_count;

	tx = tx_spending_utxos(ctx, chainparams, utxos, bip32_base,
			       false, tal_count(outputs), nlocktime,
			       BITCOIN_TX_DEFAULT_SEQUENCE - 1);

	output_count = bitcoin_tx_add_multi_outputs(tx, outputs);
	assert(output_count == tal_count(outputs));

	permute_outputs(tx, NULL, (const void **)outputs);
	permute_inputs(tx, (const void **)utxos);

	bitcoin_tx_finalize(tx);
	assert(bitcoin_tx_check(tx));
	return tx;
}

