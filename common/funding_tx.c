#include "funding_tx.h"
#include <bitcoin/pubkey.h>
#include <bitcoin/script.h>
#include <bitcoin/tx.h>
#include <ccan/ptrint/ptrint.h>
#include <common/key_derive.h>
#include <common/permute_tx.h>
#include <common/utxo.h>

#ifndef SUPERVERBOSE
#define SUPERVERBOSE(...)
#endif

struct bitcoin_tx *funding_tx(const tal_t *ctx,
			      u16 *outnum,
			      const struct utxo **utxomap,
			      u64 funding_satoshis,
			      const struct pubkey *local_fundingkey,
			      const struct pubkey *remote_fundingkey,
			      u64 change_satoshis,
			      const struct pubkey *changekey,
			      const struct ext_key *bip32_base)
{
	struct bitcoin_tx *tx = bitcoin_tx(ctx, tal_count(utxomap),
					   change_satoshis ? 2 : 1);
	u8 *wscript;
	size_t i;

	for (i = 0; i < tal_count(utxomap); i++) {
		tx->input[i].txid = utxomap[i]->txid;
		tx->input[i].index = utxomap[i]->outnum;
		tx->input[i].amount = tal_dup(tx, u64, &utxomap[i]->amount);
		if (utxomap[i]->is_p2sh && bip32_base) {
			struct pubkey key;

			bip32_pubkey(bip32_base, &key, utxomap[i]->keyindex);
			tx->input[i].script
				= bitcoin_scriptsig_p2sh_p2wpkh(tx, &key);
		}
	}

	tx->output[0].amount = funding_satoshis;
	wscript = bitcoin_redeem_2of2(tx, local_fundingkey, remote_fundingkey);
	SUPERVERBOSE("# funding witness script = %s\n",
		     tal_hex(wscript, wscript));
	tx->output[0].script = scriptpubkey_p2wsh(tx, wscript);
	tal_free(wscript);

	if (change_satoshis != 0) {
		const void *map[2];
		map[0] = int2ptr(0);
		map[1] = int2ptr(1);
		tx->output[1].script = scriptpubkey_p2wpkh(tx, changekey);
		tx->output[1].amount = change_satoshis;
		permute_outputs(tx->output, tal_count(tx->output), map);
		*outnum = (map[0] == int2ptr(0) ? 0 : 1);
	} else {
		*outnum = 0;
	}

	permute_inputs(tx->input, tal_count(tx->input), (const void **)utxomap);
	return tx;
}
