#include <common/base64.h>
#include <sodium.h>
#include <sodium/utils.h>

/* Decode/encode from/to base64, base64 helper functions.
 * We import base64 from libsodium to generate tor V3 ED25519-V3 onions from blobs
*/

char *b64_encode(const tal_t *ctx, const u8 *data, size_t len)
{
	char *str = tal_arr(ctx, char, sodium_base64_encoded_len(len, sodium_base64_VARIANT_ORIGINAL) + 1);

	str = sodium_bin2base64(str,  tal_count(str), data,
								len, sodium_base64_VARIANT_ORIGINAL);
	return str;
}

u8 *b64_decode(const tal_t *ctx, const char *str, size_t len)
{
	size_t bin_len = len + 1;

	u8 *ret = tal_arr(ctx, u8, bin_len);

	if (!sodium_base642bin(ret,
				tal_count(ret),
				(const char * const)str,
				len,
				NULL,
				&bin_len,
				NULL,
				sodium_base64_VARIANT_ORIGINAL))
			return tal_free(ret);

	ret[bin_len] = 0;
	tal_resize(&ret, bin_len + 1);
	return ret;
}
