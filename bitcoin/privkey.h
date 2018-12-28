#ifndef LIGHTNING_BITCOIN_PRIVKEY_H
#define LIGHTNING_BITCOIN_PRIVKEY_H
#include "config.h"
#include <ccan/short_types/short_types.h>
#include <ccan/structeq/structeq.h>

/* General 256-bit secret, which must be private.  Used in various places. */
struct secret {
	u8 data[32];
};

/* You probably shouldn't compare secrets in non-const time! */
bool secret_eq_consttime(const struct secret *a, const struct secret *b);

/* This is a private key.  Keep it secret. */
struct privkey {
	struct secret secret;
};
#endif /* LIGHTNING_BITCOIN_PRIVKEY_H */
