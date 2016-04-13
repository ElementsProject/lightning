#ifndef LIGHTNING_BITCOIN_SHADOUBLE_H
#define LIGHTNING_BITCOIN_SHADOUBLE_H
#include "config.h"
#include <ccan/crypto/sha256/sha256.h>
#include <ccan/tal/tal.h>

/* To explicitly distinguish between single sha and bitcoin's standard double */
struct sha256_double {
	struct sha256 sha;
};

void sha256_double(struct sha256_double *shadouble, const void *p, size_t len);

void sha256_double_done(struct sha256_ctx *sha256, struct sha256_double *res);

char *sha256_str(const tal_t *ctx, struct sha256 *sha);
char *sha256_double_str(const tal_t *ctx, struct sha256_double *shadouble);

#endif /* LIGHTNING_BITCOIN_SHADOUBLE_H */
