#include "config.h"
#include <assert.h>
#include <ccan/base64/base64.h>
#include <common/base64.h>

/* Decode/encode from/to base64, base64 helper functions.*/
char *b64_encode(const tal_t *ctx, const void *data, size_t len)
{
	size_t slen = base64_encoded_length(len), enclen;
	char *str = tal_arr(ctx, char, slen + 1);
	enclen = base64_encode(str, slen, data, len);
	assert(enclen == slen);

	str[enclen] = '\0';
	return str;
}

u8 *b64_decode(const tal_t *ctx, const char *str, size_t len)
{
	size_t dlen = base64_decoded_length(len);
	u8 *ret = tal_arr(ctx, u8, dlen);
	if (base64_decode((char *)ret, dlen, str, len) < 0)
		return tal_free(ret);
	return ret;
}
