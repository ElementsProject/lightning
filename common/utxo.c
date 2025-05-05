#include "config.h"
#include <common/utxo.h>
#include <wire/wire.h>

size_t utxo_spend_weight(const struct utxo *utxo, size_t min_witness_weight)
{
	size_t witness_weight;
	bool p2sh;

	switch (utxo->utxotype) {
	case UTXO_P2SH_P2WPKH:
		witness_weight = bitcoin_tx_simple_input_witness_weight();
		p2sh = true;
		goto have_weight;
	case UTXO_P2WPKH:
		witness_weight = bitcoin_tx_simple_input_witness_weight();
		p2sh = false;
		goto have_weight;
	case UTXO_P2WSH_FROM_CLOSE:
		/* BOLT #3:
		 * #### `to_remote` Output
		 *
		 * If `option_anchors` applies to the commitment
		 * transaction, the `to_remote` output is encumbered by a one
		 * block csv lock.
		 *    <remotepubkey> OP_CHECKSIGVERIFY 1 OP_CHECKSEQUENCEVERIFY
		 *
		 * The output is spent by an input with `nSequence` field set
		 * to `1` and witness: <remote_sig>
		 * Otherwise, this output is a simple P2WPKH to `remotepubkey`.
		 */
		if (utxo->close_info->option_anchors)
			witness_weight = 1 + 33 + 3 + 1 + 64;
		else
			witness_weight = 1 + 64;
		p2sh = false;
		goto have_weight;
	case UTXO_P2TR:
		witness_weight = 1 + 64;
		p2sh = false;
		goto have_weight;
	}
	abort();

have_weight:
	/* If the min is less than what we'd use for a 'normal' tx,
	 * we return the value with the greater added/calculated */
	if (witness_weight < min_witness_weight)
		return bitcoin_tx_input_weight(p2sh,
					       min_witness_weight);

	return bitcoin_tx_input_weight(p2sh, witness_weight);
}

u32 utxo_is_immature(const struct utxo *utxo, u32 blockheight)
{
	if (utxo->is_in_coinbase) {
		/* We got this from a block, it must have a known
		 * blockheight. */
		assert(utxo->blockheight);

		if (blockheight < *utxo->blockheight + 100)
			return *utxo->blockheight + 99 - blockheight;

		else
			return 0;
	} else {
		/* Non-coinbase outputs are always mature. */
		return 0;
	}
}

const char *utxotype_to_str(enum utxotype utxotype)
{
	switch (utxotype) {
	case UTXO_P2SH_P2WPKH:
		return "p2sh_p2wpkh";
	case UTXO_P2WPKH:
		return "p2wpkh";
	case UTXO_P2WSH_FROM_CLOSE:
		return "p2wsh_from_close";
	case UTXO_P2TR:
		return "p2tr";
	}
	abort();
}
