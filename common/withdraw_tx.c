#include "withdraw_tx.h"
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
			       const u64 withdraw_amount,
			       const struct pubkey *changekey,
			       const u64 changesat,
			       const struct ext_key *bip32_base)
{
	struct bitcoin_tx *tx;

	tx = tx_spending_utxos(ctx, utxos, bip32_base, changesat != 0);

	tx->output[0].amount = withdraw_amount;
	tx->output[0].script = destination;

	if (changesat != 0) {
		const void *map[2];
		map[0] = int2ptr(0);
		map[1] = int2ptr(1);
		tx->output[1].script = scriptpubkey_p2wpkh(tx, changekey);
		tx->output[1].amount = changesat;
		permute_outputs(tx->output, NULL, map);
	}
	permute_inputs(tx->input, (const void **)utxos);
	return tx;
}

