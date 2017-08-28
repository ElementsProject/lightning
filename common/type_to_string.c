#include <ccan/tal/str/str.h>
#include <common/type_to_string.h>
#include <common/utils.h>
#include <inttypes.h>

/* We need at least one, and this is in CCAN so register it here. */
REGISTER_TYPE_TO_HEXSTR(sha256);

char *type_to_string_(const tal_t *ctx,  const char *typename,
		      union printable_types u)
{
	char *s = NULL;
	size_t i;
	static size_t num_p;
	static struct type_to_string **t = NULL;

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
	if (!s)
		s = tal_fmt(ctx, "UNKNOWN TYPE %s", typename);

	return s;
}
