/* CC0 license (public domain) - see LICENSE file for details */
#include "base32.h"
#include <assert.h>
#include <ccan/endian/endian.h>
#include <string.h> /* for memcpy, memset */

const char *base32_chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567=";

/* RFC 4648:
 *
 * (1) The final quantum of encoding input is an integral multiple of 40
 *     bits; here, the final unit of encoded output will be an integral
 *     multiple of 8 characters with no "=" padding.
 *
 * (2) The final quantum of encoding input is exactly 8 bits; here, the
 *     final unit of encoded output will be two characters followed by
 *     six "=" padding characters.
 *
 * (3) The final quantum of encoding input is exactly 16 bits; here, the
 *     final unit of encoded output will be four characters followed by
 *     four "=" padding characters.
 *
 * (4) The final quantum of encoding input is exactly 24 bits; here, the
 *     final unit of encoded output will be five characters followed by
 *     three "=" padding characters.
 *
 * (5) The final quantum of encoding input is exactly 32 bits; here, the
 *     final unit of encoded output will be seven characters followed by
 *     one "=" padding character.
 */
static size_t padlen(size_t remainder)
{
	switch (remainder) {
	case 0:
		return 0;
	case 1:
		return 6;
	case 2:
		return 4;
	case 3:
		return 3;
	case 4:
		return 1;
	default:
		abort();
	}
}

size_t base32_str_size(size_t bytes)
{
	return (bytes + 4) / 5 * 8 + 1;
}

size_t base32_data_size(const char *str, size_t strlen)
{
	/* 8 chars == 5 bytes, round up to avoid overflow even though
	 * not required for well-formed strings. */
	size_t max = (strlen + 7) / 8 * 5, padding = 0;

	/* Count trailing padding bytes. */
	while (strlen && str[strlen-1] == base32_chars[32] && padding < 6) {
		strlen--;
		padding++;
	}

	return max - (padding * 5 + 7)  / 8;
}

static bool decode_8_chars(const char c[8], beint64_t *res, int *bytes)
{
	uint64_t acc = 0;
	size_t num_pad = 0;
	for (int i = 0; i < 8; i++) {
		const char *p;

		acc <<= 5;
		p = memchr(base32_chars, c[i], 32);
		if (!p) {
			if (c[i] == base32_chars[32]) {
				num_pad++;
				continue;
			}
			return false;
		}
		/* Can't have padding then non-pad */
		if (num_pad)
			return false;
		acc |= (p - base32_chars);
	}
	*res = cpu_to_be64(acc);

	/* Can't have 2 or 5 padding bytes */
	if (num_pad == 5 || num_pad == 2)
		return false;
	*bytes = (40 - num_pad * 5) / 8;
	return true;
}

bool base32_decode(const char *str, size_t slen, void *buf, size_t bufsize)
{
	while (slen >= 8) {
		beint64_t val;
		int bytes;
		if (!decode_8_chars(str, &val, &bytes))
			return false;
		str += 8;
		slen -= 8;
		/* Copy bytes into dst. */
		if (bufsize < bytes)
			return false;
		memcpy(buf, (char *)&val + 3, bytes);
		buf = (char *)buf + bytes;
		bufsize -= bytes;
	}
	return slen == 0 && bufsize == 0;
}

static void encode_8_chars(char *dest, const uint8_t *buf, int bytes)
{
	beint64_t val = 0;
	uint64_t res;
	int bits = bytes * 8;

	assert(bytes > 0 && bytes <= 5);
	memcpy((char *)&val + 3, buf, bytes);
	res = be64_to_cpu(val);

	while (bits > 0) {
		*dest = base32_chars[(res >> 35) & 0x1F];
		dest++;
		res <<= 5;
		bits -= 5;
	}

	if (bytes != 5)
		memset(dest, base32_chars[32], padlen(bytes));
}

bool base32_encode(const void *buf, size_t bufsize, char *dest, size_t destsize)
{
	while (bufsize) {
		int bytes = 5;

		if (bytes > bufsize)
			bytes = bufsize;

		if (destsize < 8)
			return false;
		encode_8_chars(dest, buf, bytes);
		buf = (const char *)buf + bytes;
		bufsize -= bytes;
		destsize -= 8;
		dest += 8;
	}
	if (destsize != 1)
		return false;
	*dest = '\0';
	return true;
}
