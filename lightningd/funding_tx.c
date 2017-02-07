#include "funding_tx.h"
#include <assert.h>
#include <bitcoin/script.h>
#include <bitcoin/tx.h>
#include <permute_tx.h>

#ifndef SUPERVERBOSE
#define SUPERVERBOSE(...)
#endif

struct bitcoin_tx *funding_tx(const tal_t *ctx,
			      const struct sha256_double *input_txid,
			      unsigned int input_txout,
			      u64 input_satoshis,
			      u64 funding_satoshis,
			      const struct pubkey *local_fundingkey,
			      const struct pubkey *remote_fundingkey,
			      const struct pubkey *changekey,
			      u64 feerate_per_kw,
			      u64 dust_limit_satoshis)
{
	struct bitcoin_tx *tx = bitcoin_tx(ctx, 1, 2);
	u8 *wscript;
	u64 fee, weight;

	tx->input[0].txid = *input_txid;
	tx->input[0].index = input_txout;
	tx->input[0].amount = tal_dup(tx, u64, &input_satoshis);

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
	if (input_satoshis - funding_satoshis < dust_limit_satoshis + fee)
		tal_resize(&tx->output, 1);
	else {
		tx->output[1].amount = input_satoshis - funding_satoshis - fee;
		permute_outputs(tx->output, tal_count(tx->output), NULL);
	}

	return tx;
}

void sign_funding_tx(struct bitcoin_tx *funding,
		     const struct pubkey *inputkey,
		     const struct privkey *input_privkey)
{
	secp256k1_ecdsa_signature sig;
	u8 *subscript = scriptpubkey_p2pkh(funding, inputkey);

	sign_tx_input(funding, 0, subscript, NULL, input_privkey, inputkey,
		      &sig);
	tal_free(subscript);

	funding->input[0].script = bitcoin_redeem_p2pkh(funding, inputkey, &sig);
}
