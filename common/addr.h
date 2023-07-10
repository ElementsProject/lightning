#ifndef LIGHTNING_COMMON_ADDR_H
#define LIGHTNING_COMMON_ADDR_H
#include "config.h"
#include <bitcoin/chainparams.h>

/* Given a scriptPubkey, return an encoded address for p2pkh/p2w{pkh,sh}/p2tr */
char *encode_scriptpubkey_to_addr(const tal_t *ctx,
				  const struct chainparams *chainparams,
				  const u8 *scriptPubkey);

#endif /* LIGHTNING_COMMON_ADDR_H */
