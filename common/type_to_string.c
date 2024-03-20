#include "config.h"
#include <assert.h>
#include <bitcoin/preimage.h>
#include <ccan/tal/str/str.h>
#include <common/type_to_string.h>

char *fmt_sha256(const tal_t *ctx, const struct sha256 *sha256)
{
	return tal_hexstr(ctx, sha256, sizeof(*sha256));
}

char *fmt_ripemd160(const tal_t *ctx, const struct ripemd160 *ripemd160)
{
	return tal_hexstr(ctx, ripemd160, sizeof(*ripemd160));
}

/* We need at least one, and these are in CCAN so register it here. */
REGISTER_TYPE_TO_STRING(sha256, fmt_sha256);
REGISTER_TYPE_TO_STRING(ripemd160, fmt_ripemd160);

const char *type_to_string_(const tal_t *ctx,  const char *typename,
			    union printable_types u)
{
	const char *s = NULL;
	size_t i;
	static size_t num_p;
	static struct type_to_string **t = NULL;

	assert(typename != NULL);

	if (!t)
		t = autodata_get(type_to_string, &num_p);

	/* Typenames in registrations don't include "struct " */
	if (strstarts(typename, "struct "))
		typename += strlen("struct ");

	for (i = 0; i < num_p; i++) {
		if (streq(t[i]->typename, typename)) {
			s = t[i]->fmt(ctx, u);
			break;
		}
	}
	/* **BROKEN** makes CI upset, which is what we want! */
	if (!s)
		s = tal_fmt(ctx, "**BROKEN** UNKNOWN TYPE %s", typename);

	return s;
}
