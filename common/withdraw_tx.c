#include "withdraw_tx.h"
#include <bitcoin/pubkey.h>
#include <bitcoin/script.h>
#include <ccan/ptrint/ptrint.h>
#include <common/key_derive.h>
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
	struct bitcoin_tx *tx =
	    bitcoin_tx(ctx, tal_count(utxos), changesat ? 2 : 1);
	for (size_t i = 0; i < tal_count(utxos); i++) {
		tx->input[i].txid = utxos[i]->txid;
		tx->input[i].index = utxos[i]->outnum;
		tx->input[i].amount = tal_dup(tx, u64, &utxos[i]->amount);
		if (utxos[i]->is_p2sh && bip32_base) {
			struct pubkey key;
			bip32_pubkey(bip32_base, &key, utxos[i]->keyindex);
			tx->input[i].script =
				bitcoin_scriptsig_p2sh_p2wpkh(tx, &key);
		}
	}
	tx->output[0].amount = withdraw_amount;
	tx->output[0].script = destination;

	if (changesat != 0) {
		const void *map[2];
		map[0] = int2ptr(0);
		map[1] = int2ptr(1);
		tx->output[1].script = scriptpubkey_p2wpkh(tx, changekey);
		tx->output[1].amount = changesat;
		permute_outputs(tx->output, tal_count(tx->output), map);
	}
	permute_inputs(tx->input, tal_count(tx->input), (const void **)utxos);
	return tx;
}

