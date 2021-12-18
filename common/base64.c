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
