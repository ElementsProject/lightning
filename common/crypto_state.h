#ifndef LIGHTNING_COMMON_CRYPTO_STATE_H
#define LIGHTNING_COMMON_CRYPTO_STATE_H
#include "config.h"
#include <bitcoin/privkey.h>
#include <ccan/short_types/short_types.h>
#include <stddef.h>

struct crypto_state {
	/* Received and sent nonces. */
	u64 rn, sn;
	/* Sending and receiving keys. */
	struct secret sk, rk;
	/* Chaining key for re-keying */
	struct secret s_ck, r_ck;
};

void towire_crypto_state(u8 **pptr, const struct crypto_state *cs);
void fromwire_crypto_state(const u8 **ptr, size_t *max, struct crypto_state *cs);

#endif /* LIGHTNING_COMMON_CRYPTO_STATE_H */
