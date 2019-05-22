#ifndef LIGHTNING_COMMON_ADDR_H
#define LIGHTNING_COMMON_ADDR_H
#include "config.h"
#include <ccan/short_types/short_types.h>
#include <ccan/tal/tal.h>

/* Given a P2WSH or P2WPKH scriptPubkey, return a bech32 encoded address */
char *encode_scriptpubkey_to_addr(const tal_t *ctx,
                                  const char *hrp,
                                  const u8 *scriptPubkey);

#endif /* LIGHTNING_COMMON_ADDR_H */
