#ifndef LIGHTNING_BITCOIN_SHADOUBLE_H
#define LIGHTNING_BITCOIN_SHADOUBLE_H
#include "config.h"
#include <ccan/crypto/sha256/sha256.h>
#include <ccan/short_types/short_types.h>
#include <ccan/tal/tal.h>

/* To explicitly distinguish between single sha and bitcoin's standard double */
struct sha256_double {
	struct sha256 sha;
};

void sha256_double(struct sha256_double *shadouble, const void *p, size_t len);

void sha256_double_done(struct sha256_ctx *sha256, struct sha256_double *res);

/* marshal/unmarshal functions */
void fromwire_sha256_double(const u8 **cursor, size_t *max,
			    struct sha256_double *sha256d);
void towire_sha256_double(u8 **pptr, const struct sha256_double *sha256d);

char *fmt_sha256_double(const tal_t *ctx, const struct sha256_double *shad);
#endif /* LIGHTNING_BITCOIN_SHADOUBLE_H */
