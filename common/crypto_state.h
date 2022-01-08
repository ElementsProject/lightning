#ifndef LIGHTNING_COMMON_CRYPTO_STATE_H
#define LIGHTNING_COMMON_CRYPTO_STATE_H
#include "config.h"
#include <bitcoin/privkey.h>

struct crypto_state {
	/* Received and sent nonces. */
	u64 rn, sn;
	/* Sending and receiving keys. */
	struct secret sk, rk;
	/* Chaining key for re-keying */
	struct secret s_ck, r_ck;
};

#endif /* LIGHTNING_COMMON_CRYPTO_STATE_H */
