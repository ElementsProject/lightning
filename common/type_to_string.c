#include "config.h"
#include <assert.h>
#include <bitcoin/preimage.h>
#include <ccan/tal/str/str.h>
#include <common/type_to_string.h>

/* We need at least one, and these are in CCAN so register it here. */
REGISTER_TYPE_TO_HEXSTR(sha256);
REGISTER_TYPE_TO_HEXSTR(ripemd160);
/* This one in bitcoin/ but doesn't have its own C file */
REGISTER_TYPE_TO_HEXSTR(preimage);

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
