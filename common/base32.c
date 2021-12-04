#include "config.h"
#include <ccan/str/base32/base32.h>
#include <common/base32.h>

/* We want lower-case conversion please */
static const char base32_lower[] = "abcdefghijklmnopqrstuvwxyz234567=";

char *b32_encode(const tal_t *ctx, const void *data, size_t len)
{
	char *str = tal_arr(ctx, char, base32_str_size(len));

	base32_chars = base32_lower;
	base32_encode(data, len, str, tal_count(str));
	return str;
}

u8 *b32_decode(const tal_t *ctx, const char *str, size_t len)
{
	u8 *ret = tal_arr(ctx, u8, base32_data_size(str, len));

	base32_chars = base32_lower;
	if (!base32_decode(str, len, ret, tal_count(ret)))
		return tal_free(ret);
	return ret;
}
