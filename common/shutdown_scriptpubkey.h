#ifndef LIGHTNING_COMMON_SHUTDOWN_SCRIPTPUBKEY_H
#define LIGHTNING_COMMON_SHUTDOWN_SCRIPTPUBKEY_H
#include "config.h"
#include <ccan/short_types/short_types.h>

/* BOLT #2:
 *
 * 1. `OP_0` `20` 20-bytes (version 0 pay to witness pubkey hash), OR
 * 2. `OP_0` `32` 32-bytes (version 0 pay to witness script hash), OR
 * 3. if (and only if) `option_shutdown_anysegwit` is negotiated:
 *    * `OP_1` through `OP_16` inclusive, followed by a single push of 2 to 40 bytes
 *    (witness program versions 1 through 16)
 *
 * A receiving node:
 *...
 *  - if the `scriptpubkey` is not in one of the above forms:
 *    - SHOULD send a `warning`
 */
bool valid_shutdown_scriptpubkey(const u8 *scriptpubkey,
				 bool anysegwit,
				 bool anchors);

#endif /* LIGHTNING_COMMON_SHUTDOWN_SCRIPTPUBKEY_H */
