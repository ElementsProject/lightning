#ifndef LIGHTNING_COMMON_PERMUTE_TX_H
#define LIGHTNING_COMMON_PERMUTE_TX_H
#include "config.h"
#include "bitcoin/tx.h"

struct htlc;

/**
 * permute_inputs: permute the transaction inputs into BIP69 order.
 * @inputs: usually bitcoin_tx->inputs, must be tal_arr.
 * @map: if non-NULL, pointers to be permuted the same as the inputs.
 */
void permute_inputs(struct bitcoin_tx_input *inputs, const void **map);

/**
 * permute_outputs: permute the transaction outputs into BIP69 + cltv order.
 * @outputs: usually bitcoin_tx->outputs, must be tal_arr.
 * @cltvs: CLTV delays to use as a tie-breaker, or NULL.
 * @map: if non-NULL, pointers to be permuted the same as the outputs.
 *
 * So the caller initiates the map with which htlcs are used, it
 * can easily see which htlc (if any) is in output #0 with map[0].
 */
void permute_outputs(struct bitcoin_tx_output *outputs,
		     u32 *cltvs,
		     const void **map);
#endif /* LIGHTNING_COMMON_PERMUTE_TX_H */
