#include "shadouble.h"

void sha256_double(struct sha256_double *shadouble, const void *p, size_t len)
{
	sha256(&shadouble->sha, p, len);
	sha256(&shadouble->sha, &shadouble->sha, sizeof(shadouble->sha));
}

void sha256_double_done(struct sha256_ctx *shactx, struct sha256_double *res)
{
	sha256_done(shactx, &res->sha);
	sha256(&res->sha, &res->sha, sizeof(res->sha));
}
