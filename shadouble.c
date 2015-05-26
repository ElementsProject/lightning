#include "shadouble.h"

void sha256_double(struct sha256_double *shadouble, const void *p, size_t len)
{
	sha256(&shadouble->sha, (unsigned char *)p, len);
	sha256(&shadouble->sha, &shadouble->sha, 1);
}

void sha256_double_done(struct sha256_ctx *sha256, struct sha256_double *res)
{
	sha256_done(sha256, &res->sha);
	sha256(&res->sha, &res->sha, 1);
}
