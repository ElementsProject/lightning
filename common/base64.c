#include <ccan/str/base64/base64.h>
#include <common/base64.h>

char *b64_encode(const tal_t *ctx, char *data, size_t len)
{
	char *str = tal_arr(ctx, char, base64_encoded_length(len));

	base64_encode(str, tal_count(str), data , len);
	return str;
}

char *b64_decode(const tal_t *ctx, char *str, size_t len)
{
	char *ret = tal_arr(ctx, char, base64_decoded_length(len));

	if (!base64_decode(ret, tal_count(ret), str, len))
		return tal_free(ret);
	return ret;
}
