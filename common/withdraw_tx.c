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
			       bool allow_rbf,
			       const struct utxo **utxos,
			       struct bitcoin_tx_output **outputs,
			       const struct ext_key *bip32_base,
			       u32 nlocktime)
{
	struct bitcoin_tx *tx;
	int output_count;
	/*
	 * BIP-125: Opt-in Full Replace-by-Fee Signaling
	 *     https://github.com/bitcoin/bips/blob/master/bip-0125.mediawiki
	 * A transaction is considered to have opted in to
	 * allowing replacement of itself if any of its
	 * inputs have an nSequence number less than (0xffffffff - 1).
	 */
	/* A sequence of (0xffffffff - 1) signals to use locktime */
	u32 sequence = BITCOIN_TX_DEFAULT_SEQUENCE - 1;
	if (allow_rbf)
		sequence--;

	tx = tx_spending_utxos(ctx, chainparams, utxos, bip32_base,
			       false, tal_count(outputs), nlocktime,
			       sequence);

	output_count = bitcoin_tx_add_multi_outputs(tx, outputs);
	assert(output_count == tal_count(outputs));

	permute_outputs(tx, NULL, (const void **)outputs);
	permute_inputs(tx, (const void **)utxos);

	bitcoin_tx_finalize(tx);
	assert(bitcoin_tx_check(tx));
	return tx;
}

