#include "withdraw_tx.h"
#include <assert.h>
#include <bitcoin/pubkey.h>
#include <bitcoin/script.h>
#include <ccan/ptrint/ptrint.h>
#include <common/permute_tx.h>
#include <common/utxo.h>
#include <string.h>
#include <wally_bip32.h>

struct bitcoin_tx *withdraw_tx(const tal_t *ctx,
			       const struct utxo **utxos,
			       u8 *destination,
			       struct amount_sat withdraw_amount,
			       const struct pubkey *changekey,
			       struct amount_sat change,
			       const struct ext_key *bip32_base)
{
	struct bitcoin_tx *tx;

	tx = tx_spending_utxos(ctx, utxos, bip32_base,
			       !amount_sat_eq(change, AMOUNT_SAT(0)));

	bitcoin_tx_add_output(tx, destination, &withdraw_amount);

	if (!amount_sat_eq(change, AMOUNT_SAT(0))) {
		const void *map[2];
		map[0] = int2ptr(0);
		map[1] = int2ptr(1);
		bitcoin_tx_add_output(tx, scriptpubkey_p2wpkh(tx, changekey),
				      &change);
		permute_outputs(tx, NULL, map);
	}
	permute_inputs(tx, (const void **)utxos);
	assert(bitcoin_tx_check(tx));
	return tx;
}

