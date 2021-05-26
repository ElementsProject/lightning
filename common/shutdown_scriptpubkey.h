#ifndef LIGHTNING_COMMON_SHUTDOWN_SCRIPTPUBKEY_H
#define LIGHTNING_COMMON_SHUTDOWN_SCRIPTPUBKEY_H
#include "config.h"
#include <ccan/short_types/short_types.h>

/* BOLT #2:
 *
 * 1. `OP_DUP` `OP_HASH160` `20` 20-bytes `OP_EQUALVERIFY` `OP_CHECKSIG`
 *   (pay to pubkey hash), OR
 * 2. `OP_HASH160` `20` 20-bytes `OP_EQUAL` (pay to script hash), OR
 * 3. `OP_0` `20` 20-bytes (version 0 pay to witness pubkey hash), OR
 * 4. `OP_0` `32` 32-bytes (version 0 pay to witness script hash), OR
 * 5. if (and only if) `option_shutdown_anysegwit` is negotiated:
 *    * `OP_1` through `OP_16` inclusive, followed by a single push of 2 to 40 bytes
 *    (witness program versions 1 through 16)
 *
 * A receiving node:
 *...
 *  - if the `scriptpubkey` is not in one of the above forms:
 *    - SHOULD fail the connection.
 */
bool valid_shutdown_scriptpubkey(const u8 *scriptpubkey,
				 bool anysegwit);

#endif /* LIGHTNING_COMMON_SHUTDOWN_SCRIPTPUBKEY_H */
