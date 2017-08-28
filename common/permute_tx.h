#ifndef LIGHTNING_COMMON_PERMUTE_TX_H
#define LIGHTNING_COMMON_PERMUTE_TX_H
#include "config.h"
#include "bitcoin/tx.h"

struct htlc;

/* Permute the transaction into BIP69 order. */
void permute_inputs(struct bitcoin_tx_input *inputs, size_t num_inputs,
		    const void **map);

/* If @map is non-NULL, it will be permuted the same as the outputs.
 *
 * So the caller initiates the map with which htlcs are used, it
 * can easily see which htlc (if any) is in output #0 with map[0].
 */
void permute_outputs(struct bitcoin_tx_output *outputs, size_t num_outputs,
		     const void **map);
#endif /* LIGHTNING_COMMON_PERMUTE_TX_H */
