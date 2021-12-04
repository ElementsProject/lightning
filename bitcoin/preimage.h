#ifndef LIGHTNING_BITCOIN_PREIMAGE_H
#define LIGHTNING_BITCOIN_PREIMAGE_H
#include "config.h"
#include <ccan/short_types/short_types.h>
#include <ccan/structeq/structeq.h>

struct preimage {
	u8 r[32];
};
/* Define preimage_eq */
STRUCTEQ_DEF(preimage, 0, r);

void fromwire_preimage(const u8 **cursor, size_t *max, struct preimage *preimage);
void towire_preimage(u8 **pptr, const struct preimage *preimage);

#endif /* LIGHTNING_BITCOIN_PREIMAGE_H */
