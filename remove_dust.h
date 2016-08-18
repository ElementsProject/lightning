#ifndef LIGHTNING_REMOVE_DUST_H
#define LIGHTNING_REMOVE_DUST_H
#include "config.h"
#include "bitcoin/tx.h"

/* Remove all dust outputs from tx */
void remove_dust(struct bitcoin_tx *tx, int *map);

/* Less than this is dust. */
#define DUST_THRESHOLD 546

/**
 * is_dust: is an output of this value considered dust?
 * @satoshis: number of satoshis.
 *
 * Transactions with dust outputs will not be relayed by the bitcoin
 * network.  It's not an exact definition, unfortunately.
 */
static inline bool is_dust(u64 satoshis)
{
	return satoshis < DUST_THRESHOLD;
}
#endif /* LIGHTNING_REMOVE_DUST_H */
