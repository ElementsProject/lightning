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
