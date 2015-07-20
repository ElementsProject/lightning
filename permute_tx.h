#ifndef LIGHTNING_PERMUTE_TX_H
#define LIGHTNING_PERMUTE_TX_H
#include "bitcoin/tx.h"

/* Permute the transaction into BIP69 order.
 * map[0] is set to the new index of input 0, etc.
 */
void permute_inputs(struct bitcoin_tx_input *inputs,
		    size_t num_inputs,
		    size_t *map);

void permute_outputs(struct bitcoin_tx_output *outputs,
		     size_t num_outputs,
		     size_t *map);
#endif /* LIGHTNING_PERMUTE_TX_H */
