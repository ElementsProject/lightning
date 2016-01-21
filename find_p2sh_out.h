#ifndef LIGHTNING_FIND_P2SH_OUT_H
#define LIGHTNING_FIND_P2SH_OUT_H
#include "config.h"
#include <ccan/short_types/short_types.h>

struct bitcoin_tx;

/* Normally we'd simply remember which output of the anchor or commit
 * tx is the one which pays to this script.  But for these examples,
 * we have to figure it out by recreating the output and matching. */
u32 find_p2sh_out(const struct bitcoin_tx *tx, u8 *redeemscript);
#endif /* LIGHTNING_FIND_P2SH_OUT_H */
