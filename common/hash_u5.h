/* bech32 (thus bolt11) deal in 5-bit values */
#ifndef LIGHTNING_COMMON_HASH_U5_H
#define LIGHTNING_COMMON_HASH_U5_H
#include "config.h"
#include <ccan/crypto/sha256/sha256.h>
#include <ccan/short_types/short_types.h>

/* Type to annotate a 5 bit value. */
typedef unsigned char u5;

struct hash_u5 {
	u64 buf;
        unsigned int num_bits;
        struct sha256_ctx hash;
};

void hash_u5_init(struct hash_u5 *hu5, const char *hrp);
void hash_u5(struct hash_u5 *hu5, const u5 *u5, size_t len);
void hash_u5_done(struct hash_u5 *hu5, struct sha256 *res);

#endif /* LIGHTNING_COMMON_HASH_U5_H */
