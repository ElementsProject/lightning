#include "config.h"
#include <ccan/endian/endian.h>
#include <common/hash_u5.h>
#include <string.h>

void hash_u5_init(struct hash_u5 *hu5, const char *hrp)
{
	hu5->buf = 0;
	hu5->num_bits = 0;
	sha256_init(&hu5->hash);
	sha256_update(&hu5->hash, hrp, strlen(hrp));
}

void hash_u5(struct hash_u5 *hu5, const u8 *u5, size_t len)
{
	size_t bits = len * 5;

	while (bits) {
		size_t n = 5;

		if (bits < n)
			n = bits;

		hu5->buf <<= n;
		hu5->buf |= (*u5 >> (5-n));
		bits -= n;
		hu5->num_bits += n;

		if (n == 5)
			u5++;

		if (hu5->num_bits >= 32) {
			be32 be32 = cpu_to_be32(hu5->buf >> (hu5->num_bits-32));
			sha256_update(&hu5->hash, &be32, sizeof(be32));
			hu5->num_bits -= 32;
		}
	}
}

void hash_u5_done(struct hash_u5 *hu5, struct sha256 *res)
{
	if (hu5->num_bits) {
		be32 be32 = cpu_to_be32(hu5->buf << (32 - hu5->num_bits));

		sha256_update(&hu5->hash, &be32, (hu5->num_bits + 7) / 8);
	}
	sha256_done(&hu5->hash, res);
}
