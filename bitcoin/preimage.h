#ifndef LIGHTNING_BITCOIN_PREIMAGE_H
#define LIGHTNING_BITCOIN_PREIMAGE_H
#include "config.h"
#include <ccan/short_types/short_types.h>

struct preimage {
	u8 r[32];
};
#endif /* LIGHTNING_BITCOIN_PREIMAGE_H */
