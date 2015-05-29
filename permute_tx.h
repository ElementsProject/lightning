#ifndef LIGHTNING_PERMUTE_TX_H
#define LIGHTNING_PERMUTE_TX_H
#include "bitcoin_tx.h"

/* Given the two seeds, permute the transaction inputs.
 * map[0] is set to the new index of input 0, etc.
 */
void permute_inputs(uint64_t seed1, uint64_t seed2,
		    size_t transaction_num,
		    struct bitcoin_tx_input *inputs,
		    size_t num_inputs,
		    size_t *map);

void permute_outputs(uint64_t seed1, uint64_t seed2,
		     size_t transaction_num,
		     struct bitcoin_tx_output *outputs,
		     size_t num_outputs,
		     size_t *map);

enum permute_style {
	PERMUTE_INPUT_STYLE = 0,
	PERMUTE_OUTPUT_STYLE = 1
};

#endif /* LIGHTNING_PERMUTE_TX_H */
