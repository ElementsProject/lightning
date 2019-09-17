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
	struct pubkey key;
	u8 *script;
	size_t i;

	assert(tal_count(utxos) > 0 && tal_count(outputs) > 0);

	tx = bitcoin_tx(ctx, chainparams,
			tal_count(utxos),
			tal_count(outputs),
			nlocktime);

	/* Add our utxo's */
	for (i = 0; i < tal_count(utxos); i++) {
		if (utxos[i]->is_p2sh && bip32_base) {
			bip32_pubkey(bip32_base, &key, utxos[i]->keyindex);
			script = bitcoin_scriptsig_p2sh_p2wpkh(tmpctx, &key);
		} else {
			script = NULL;
		}

		bitcoin_tx_add_input(tx, &utxos[i]->txid, utxos[i]->outnum,
				     BITCOIN_TX_DEFAULT_SEQUENCE - 1,
		 		     utxos[i]->amount, script);
	}

	bitcoin_tx_add_multi_outputs(tx, outputs);
	permute_outputs(tx, NULL, (const void **)outputs);
	permute_inputs(tx, (const void **)utxos);

	bitcoin_tx_finalize(tx);
	assert(bitcoin_tx_check(tx));
	return tx;
}

