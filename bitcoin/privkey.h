#ifndef LIGHTNING_BITCOIN_PRIVKEY_H
#define LIGHTNING_BITCOIN_PRIVKEY_H
#include "config.h"
#include <ccan/short_types/short_types.h>

/* This is a private key.  Keep it secret. */
struct privkey {
	u8 secret[32];
};
#endif /* LIGHTNING_BITCOIN_PRIVKEY_H */
