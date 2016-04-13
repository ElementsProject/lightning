#include "shadouble.h"
#include <ccan/mem/mem.h>
#include <stdio.h>

void sha256_double(struct sha256_double *shadouble, const void *p, size_t len)
{
	sha256(&shadouble->sha, memcheck(p, len), len);
	sha256(&shadouble->sha, &shadouble->sha, sizeof(shadouble->sha));
}

void sha256_double_done(struct sha256_ctx *shactx, struct sha256_double *res)
{
	sha256_done(shactx, &res->sha);
	sha256(&res->sha, &res->sha, sizeof(res->sha));
}

char *sha256_str(const tal_t *ctx, struct sha256 *sha)
{
	const size_t size = sizeof(struct sha256);
	char *hex = tal_arr(ctx, char, size * 2 + 1);
	size_t i = 0;
	for (; i < size; i++) {
		sprintf(hex + i*2, "%02x", sha->u.u8[size - i - 1]);
	}
	*(hex + size*2) = '\0';
	return hex;
}

char *sha256_double_str(const tal_t *ctx, struct sha256_double *shadouble)
{
	return sha256_str(ctx, &shadouble->sha);
}