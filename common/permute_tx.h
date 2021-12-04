#ifndef LIGHTNING_COMMON_PERMUTE_TX_H
#define LIGHTNING_COMMON_PERMUTE_TX_H
#include "config.h"
#include "bitcoin/tx.h"

struct htlc;

/**
 * permute_outputs: permute the transaction outputs into BIP69 + cltv order.
 * @tx: the transaction whose outputs are to be sorted (outputs must be tal_arr).
 * @cltvs: CLTV delays to use as a tie-breaker, or NULL.
 * @map: if non-NULL, pointers to be permuted the same as the outputs.
 *
 * So the caller initiates the map with which htlcs are used, it
 * can easily see which htlc (if any) is in output #0 with map[0].
 */
void permute_outputs(struct bitcoin_tx *tx, u32 *cltvs, const void **map);
#endif /* LIGHTNING_COMMON_PERMUTE_TX_H */
