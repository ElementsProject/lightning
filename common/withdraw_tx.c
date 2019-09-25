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
			       int *change_outnum)
{
	struct bitcoin_tx *tx;

	tx = tx_spending_utxos(ctx, chainparams, utxos, bip32_base,
			       !amount_sat_eq(change, AMOUNT_SAT(0)),
			       tal_count(outputs));

	bitcoin_tx_add_multi_outputs(tx, outputs);

	if (!amount_sat_eq(change, AMOUNT_SAT(0))) {
		const void *map[2];
		map[0] = int2ptr(0);
		map[1] = int2ptr(1);
		bitcoin_tx_add_output(tx, scriptpubkey_p2wpkh(tmpctx, changekey),
				      change);
		permute_outputs(tx, NULL, map);
		if (change_outnum)
			*change_outnum = ptr2int(map[1]);
	} else if (change_outnum)
		*change_outnum = -1;
	permute_inputs(tx, (const void **)utxos);
	elements_tx_add_fee_output(tx);
	assert(bitcoin_tx_check(tx));
	return tx;
}

