#ifndef LIGHTNING_REMOVE_DUST_H
#define LIGHTNING_REMOVE_DUST_H
#include "config.h"
#include "bitcoin/tx.h"

/* Remove all dust outputs from tx */
void remove_dust(struct bitcoin_tx *tx, int *map);

/* Less than this is dust. */
#define DUST_THRESHOLD 546

static inline bool is_dust(u64 amount)
{
	return amount < DUST_THRESHOLD;
}
#endif /* LIGHTNING_REMOVE_DUST_H */
