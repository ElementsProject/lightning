#ifndef CCAN_CRYPTO_HKDF_SHA256_H
#define CCAN_CRYPTO_HKDF_SHA256_H
/* BSD-MIT - see LICENSE file for details */
#include "config.h"
#include <stdlib.h>

/**
 * hkdf_sha256 - generate a derived key
 * @okm: where to output the key
 * @okm_size: the number of bytes pointed to by @okm (must be less than 255*32)
 * @s: salt
 * @ssize: the number of bytes pointed to by @s
 * @k: pointer to input key
 * @ksize: the number of bytes pointed to by @k
 * @info: pointer to info
 * @isize: the number of bytes pointed to by @info
 */
void hkdf_sha256(void *okm, size_t okm_size,
		 const void *s, size_t ssize,
		 const void *k, size_t ksize,
		 const void *info, size_t isize);
#endif /* CCAN_CRYPTO_HKDF_SHA256_H */
