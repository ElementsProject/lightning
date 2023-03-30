#ifndef LIGHTNING_WALLET_PSBT_FIXUP_H
#define LIGHTNING_WALLET_PSBT_FIXUP_H
#include "config.h"
#include <ccan/short_types/short_types.h>
#include <ccan/tal/tal.h>

/* If psbtblob cannot be parse, try rewriting to fix signature.
 * Returns NULL if it doesn't parse or was unchanged.
 */
const u8 *psbt_fixup(const tal_t *ctx, const u8 *psbtblob);

#endif /* LIGHTNING_WALLET_PSBT_FIXUP_H */
