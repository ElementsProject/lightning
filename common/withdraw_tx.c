#include "withdraw_tx.h"
#include <assert.h>
#include <bitcoin/pubkey.h>
#include <bitcoin/script.h>
#include <ccan/ptrint/ptrint.h>
#include <common/permute_tx.h>
#include <common/utils.h>
#include <common/utxo.h>
#include <string.h>
#include <wally_bip32.h>

struct bitcoin_tx *withdraw_tx(const tal_t *ctx,
			       const struct chainparams *chainparams,
			       const struct utxo **utxos,
			       struct bitcoin_tx_output **outputs,
			       const struct pubkey *changekey,
			       struct amount_sat change,
			       const struct ext_key *bip32_base,
			       int *change_outnum, u32 nlocktime)
{
	struct bitcoin_tx *tx;
	int output_count;

	tx = tx_spending_utxos(ctx, chainparams, utxos, bip32_base,
			       !amount_sat_eq(change, AMOUNT_SAT(0)),
			       tal_count(outputs), nlocktime,
			       BITCOIN_TX_DEFAULT_SEQUENCE - 1);

	output_count = bitcoin_tx_add_multi_outputs(tx, outputs);
	assert(output_count == tal_count(outputs));

	if (!amount_sat_eq(change, AMOUNT_SAT(0))) {
		/* Add one to the output_count, for the change */
		output_count++;

		const void *map[output_count];
		for (size_t i = 0; i < output_count; i++)
			map[i] = int2ptr(i);

		bitcoin_tx_add_output(tx, scriptpubkey_p2wpkh(tmpctx, changekey),
				      NULL, change);

		assert(tx->wtx->num_outputs == output_count);
		permute_outputs(tx, NULL, map);

		/* The change is the last output added, so the last position
		 * in the map */
		if (change_outnum)
			*change_outnum = ptr2int(map[output_count - 1]);

	} else if (change_outnum)
		*change_outnum = -1;

	permute_inputs(tx, (const void **)utxos);

	bitcoin_tx_finalize(tx);
	assert(bitcoin_tx_check(tx));
	return tx;
}

