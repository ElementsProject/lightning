#ifndef LIGHTNING_BITCOIN_PRIVKEY_H
#define LIGHTNING_BITCOIN_PRIVKEY_H
#include "config.h"
#include <ccan/short_types/short_types.h>

/* General 256-bit secret, which must be private.  Used in various places. */
struct secret {
	u8 data[32];
};

/* This is a private key.  Keep it secret. */
struct privkey {
	struct secret secret;
};
#endif /* LIGHTNING_BITCOIN_PRIVKEY_H */
