#include "config.h"
#include <common/utxo.h>

size_t utxo_spend_weight(const struct utxo *utxo, size_t min_witness_weight)
{
	size_t witness_weight;
	bool p2sh = (utxo->utxotype == UTXO_P2SH_P2WPKH);

	witness_weight = bitcoin_tx_input_witness_weight(utxo->utxotype);

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
	case UTXO_P2TR_BIP86:
		return "p2tr_bip86";
	}
	abort();
}
