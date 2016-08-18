#ifndef LIGHTNING_PERMUTE_TX_H
#define LIGHTNING_PERMUTE_TX_H
#include "config.h"
#include "bitcoin/tx.h"

/* Permute the transaction into BIP69 order. */
void permute_inputs(struct bitcoin_tx_input *inputs, size_t num_inputs);

void permute_outputs(struct bitcoin_tx_output *outputs, size_t num_outputs);
#endif /* LIGHTNING_PERMUTE_TX_H */
