#include "config.h"
#include <common/utxo.h>
#include <wire/wire.h>

size_t utxo_spend_weight(const struct utxo *utxo, size_t min_witness_weight)
{
	size_t wit_weight = bitcoin_tx_simple_input_witness_weight();
	/* If the min is less than what we'd use for a 'normal' tx,
	 * we return the value with the greater added/calculated */
	if (wit_weight < min_witness_weight)
		return bitcoin_tx_input_weight(utxo->is_p2sh,
					       min_witness_weight);

	return bitcoin_tx_input_weight(utxo->is_p2sh, wit_weight);
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
