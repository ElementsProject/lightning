#ifndef LIGHTNING_FIND_P2SH_OUT_H
#define LIGHTNING_FIND_P2SH_OUT_H
#include "config.h"
#include <ccan/short_types/short_types.h>

struct bitcoin_tx;

/* Routine for finding a specific p2wsh output. */
u32 find_p2wsh_out(const struct bitcoin_tx *tx, const u8 *witnessscript);
#endif /* LIGHTNING_FIND_P2SH_OUT_H */
