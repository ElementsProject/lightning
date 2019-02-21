#include "funding_tx.h"
#include <bitcoin/pubkey.h>
#include <bitcoin/script.h>
#include <bitcoin/tx.h>
#include <ccan/ptrint/ptrint.h>
#include <common/permute_tx.h>
#include <common/utxo.h>

#ifndef SUPERVERBOSE
#define SUPERVERBOSE(...)
#endif

struct bitcoin_tx *funding_tx(const tal_t *ctx,
			      u16 *outnum,
			      const struct utxo **utxomap,
			      struct amount_sat funding,
			      const struct pubkey *local_fundingkey,
			      const struct pubkey *remote_fundingkey,
			      struct amount_sat change,
			      const struct pubkey *changekey,
			      const struct ext_key *bip32_base)
{
	u8 *wscript;
	struct bitcoin_tx *tx;

	tx = tx_spending_utxos(ctx, utxomap, bip32_base,
			       !amount_sat_eq(change, AMOUNT_SAT(0)));

	tx->output[0].amount = funding;
	wscript = bitcoin_redeem_2of2(tx, local_fundingkey, remote_fundingkey);
	SUPERVERBOSE("# funding witness script = %s\n",
		     tal_hex(wscript, wscript));
	tx->output[0].script = scriptpubkey_p2wsh(tx, wscript);
	tal_free(wscript);

	if (!amount_sat_eq(change, AMOUNT_SAT(0))) {
		const void *map[2];
		map[0] = int2ptr(0);
		map[1] = int2ptr(1);
		tx->output[1].script = scriptpubkey_p2wpkh(tx, changekey);
		tx->output[1].amount = change;
		permute_outputs(tx->output, NULL, map);
		*outnum = (map[0] == int2ptr(0) ? 0 : 1);
	} else {
		*outnum = 0;
	}

	permute_inputs(tx->input, (const void **)utxomap);
	return tx;
}
