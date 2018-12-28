#ifndef CCAN_CRYPTO_HMAC_SHA256_H
#define CCAN_CRYPTO_HMAC_SHA256_H
/* BSD-MIT - see LICENSE file for details */
#include "config.h"
#include <stdint.h>
#include <stdlib.h>
#include <ccan/crypto/sha256/sha256.h>

/* Number of bytes per block. */
#define HMAC_SHA256_BLOCKSIZE 64

/**
 * struct hmac_sha256 - structure representing a completed HMAC.
 */
struct hmac_sha256 {
	struct sha256 sha;
};

/**
 * hmac_sha256 - return hmac of an object with a key.
 * @hmac: the hmac to fill in
 * @k: pointer to the key,
 * @ksize: the number of bytes pointed to by @k
 * @d: pointer to memory,
 * @dsize: the number of bytes pointed to by @d
 */
void hmac_sha256(struct hmac_sha256 *hmac,
		 const void *k, size_t ksize,
		 const void *d, size_t dsize);

/**
 * struct hmac_sha256_ctx - structure to store running context for hmac_sha256
 */
struct hmac_sha256_ctx {
	struct sha256_ctx sha;
	uint64_t k_opad[HMAC_SHA256_BLOCKSIZE / sizeof(uint64_t)];
};

/**
 * hmac_sha256_init - initialize an HMAC_SHA256 context.
 * @ctx: the hmac_sha256_ctx to initialize
 * @k: pointer to the key,
 * @ksize: the number of bytes pointed to by @k
 *
 * This must be called before hmac_sha256_update or hmac_sha256_done.
 *
 * If it was already initialized, this forgets anything which was
 * hashed before.
 *
 * Example:
 * static void hmac_all(const char *key,
 *			const char **arr, struct hmac_sha256 *hash)
 * {
 *	size_t i;
 *	struct hmac_sha256_ctx ctx;
 *
 *	hmac_sha256_init(&ctx, key, strlen(key));
 *	for (i = 0; arr[i]; i++)
 *		hmac_sha256_update(&ctx, arr[i], strlen(arr[i]));
 *	hmac_sha256_done(&ctx, hash);
 * }
 */
void hmac_sha256_init(struct hmac_sha256_ctx *ctx,
		      const void *k, size_t ksize);

/**
 * hmac_sha256_update - include some memory in the hash.
 * @ctx: the hmac_sha256_ctx to use
 * @p: pointer to memory,
 * @size: the number of bytes pointed to by @p
 *
 * You can call this multiple times to hash more data, before calling
 * hmac_sha256_done().
 */
void hmac_sha256_update(struct hmac_sha256_ctx *ctx, const void *p, size_t size);

/**
 * hmac_sha256_done - finish HMAC_SHA256 and return the hash
 * @ctx: the hmac_sha256_ctx to complete
 * @res: the hash to return.
 *
 * Note that @ctx is *destroyed* by this, and must be reinitialized.
 * To avoid that, pass a copy instead.
 */
void hmac_sha256_done(struct hmac_sha256_ctx *hmac_sha256, struct hmac_sha256 *res);
#endif /* CCAN_CRYPTO_HMAC_SHA256_H */
