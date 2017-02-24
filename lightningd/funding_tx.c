#include "funding_tx.h"
#include <assert.h>
#include <bitcoin/script.h>
#include <bitcoin/tx.h>
#include <ccan/ptrint/ptrint.h>
#include <lightningd/utxo.h>
#include <permute_tx.h>

#ifndef SUPERVERBOSE
#define SUPERVERBOSE(...)
#endif

struct bitcoin_tx *funding_tx(const tal_t *ctx,
			      u32 *outnum,
			      const struct utxo *utxos,
			      u64 funding_satoshis,
			      const struct pubkey *local_fundingkey,
			      const struct pubkey *remote_fundingkey,
			      const struct pubkey *changekey,
			      u64 feerate_per_kw,
			      u64 dust_limit_satoshis)
{
	struct bitcoin_tx *tx = bitcoin_tx(ctx, tal_count(utxos), 2);
	u8 *wscript;
	u64 fee, weight, input_satoshis = 0;
	size_t i;

	for (i = 0; i < tal_count(utxos); i++) {
		tx->input[i].txid = utxos[i].txid;
		tx->input[i].index = utxos[i].outnum;
		tx->input[i].amount = tal_dup(tx, u64, &utxos[i].amount);
		input_satoshis += utxos[i].amount;
	}

	tx->output[0].amount = funding_satoshis;
	wscript = bitcoin_redeem_2of2(tx, local_fundingkey, remote_fundingkey);
	SUPERVERBOSE("# funding witness script = %s\n",
		     tal_hex(wscript, wscript));
	tx->output[0].script = scriptpubkey_p2wsh(tx, wscript);
	tal_free(wscript);

	assert(input_satoshis >= funding_satoshis);
	tx->output[1].script = scriptpubkey_p2wpkh(tx, changekey);

	/* Calculate what weight will be once we've signed. */
	weight = measure_tx_cost(tx) + 4 * (73 + 34);
	fee = weight * feerate_per_kw / 1000;

	/* Too small an output after fee?  Drop it. */
	if (input_satoshis - funding_satoshis < dust_limit_satoshis + fee) {
		tal_resize(&tx->output, 1);
		*outnum = 0;
	} else {
		const void *map[2];
		map[0] = int2ptr(0);
		map[1] = int2ptr(1);
		tx->output[1].amount = input_satoshis - funding_satoshis - fee;
		permute_outputs(tx->output, tal_count(tx->output), map);
		*outnum = (map[0] == int2ptr(0) ? 0 : 1);
	}

	return tx;
}
