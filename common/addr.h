#ifndef LIGHTNING_COMMON_ADDR_H
#define LIGHTNING_COMMON_ADDR_H
#include "config.h"
#include <bitcoin/chainparams.h>
#include <ccan/short_types/short_types.h>
#include <ccan/tal/tal.h>

/* Given a scriptPubkey, return an encoded address */
char *encode_scriptpubkey_to_addr(const tal_t *ctx,
				  const struct chainparams *chainparams,
				  const u8 *scriptPubkey);

#endif /* LIGHTNING_COMMON_ADDR_H */
