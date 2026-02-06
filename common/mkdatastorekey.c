#include "config.h"
#include <ccan/tal/str/str.h>
#include <common/mkdatastorekey.h>
#include <common/utils.h>

const char **mkdatastorekey_(const tal_t *ctx, ...)
{
	va_list ap;
	const char *s;
	const char **key = tal_arr(ctx, const char *, 0);

	va_start(ap, ctx);
	while ((s = va_arg(ap, const char *)) != NULL)
		tal_arr_expand(&key, tal_strdup(key, s));
	va_end(ap);

	return key;
}
