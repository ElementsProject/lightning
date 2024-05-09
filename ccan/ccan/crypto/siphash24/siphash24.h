/* CC0 license (public domain) - see LICENSE file for details */
#ifndef CCAN_CRYPTO_SIPHASH24_H
#define CCAN_CRYPTO_SIPHASH24_H
/* Public domain - see LICENSE file for details */
#include "config.h"
#include <stdint.h>
#include <stdlib.h>

/**
 * struct siphash_seed - random bytes to seed the siphash
 * @u.u8: an unsigned char array.
 * @u.u32: a 32-bit integer array.
 *
 * Other fields may be added to the union in future.
 */
struct siphash_seed {
	union {
		/* Array of chars */
		unsigned char u8[16];
		/* Array of uint32_t */
		uint32_t u32[4];
		/* Array of uint64_t */
		uint64_t u64[2];
	} u;
};

/**
 * siphash24 - return SipHash-2-4 of an object.
 * @seed: the seed for the hash.
 * @p: pointer to memory,
 * @size: the number of bytes pointed to by @p
 *
 * The bytes pointed to by @p is SIPHASH24 hashed into @siphash24,
 * using seed @seed.  This is equivalent to siphash24_init(),
 * siphash24_update() then siphash24_done().
 */
uint64_t siphash24(const struct siphash_seed *seed, const void *p, size_t size);

/**
 * struct siphash24_ctx - structure to store running context for siphash24
 */
struct siphash24_ctx {
	uint64_t v[4];
	uint64_t bytes;
	union {
		uint64_t u64;
		unsigned char u8[8];
	} buf;
};

/**
 * siphash24_init - initialize an SIPHASH24 context.
 * @ctx: the siphash24_ctx to initialize
 * @seed: the siphash_seed.
 *
 * This must be called before siphash24_update or siphash24_done, or
 * alternately you can assign SIPHASH24_INIT.
 *
 * If it was already initialized, this forgets anything which was
 * hashed before.
 *
 * Example:
 * static void hash_all(const char **arr, uint64_t *hash)
 * {
 *	size_t i;
 *	struct siphash24_ctx ctx;
 *	struct siphash_seed seed;
 *
 *	// Use a random seed, not this!
 *	memset(seed.u.u64, 7, sizeof(seed.u.u64));
 *	siphash24_init(&ctx, &seed);
 *	for (i = 0; arr[i]; i++)
 *		siphash24_update(&ctx, arr[i], strlen(arr[i]));
 *	*hash = siphash24_done(&ctx);
 * }
 */
void siphash24_init(struct siphash24_ctx *ctx, const struct siphash_seed *seed);

/**
 * SIPHASH24_INIT - initializer for an SIPHASH24 context.
 * @seed1, @seed2: two 64-bit words for seed.
 *
 * This can be used to staticly initialize an SIPHASH24 context (instead
 * of siphash24_init()).
 *
 * Example:
 * static uint64_t hash_all(const char **arr)
 * {
 *	size_t i;
 *	struct siphash24_ctx ctx = SIPHASH24_INIT(0x0707070707070707ULL,
 *						  0x0707070707070707ULL);
 *
 *	for (i = 0; arr[i]; i++)
 *		siphash24_update(&ctx, arr[i], strlen(arr[i]));
 *	return siphash24_done(&ctx);
 * }
 */
#define SIPHASH24_INIT(seed1, seed2)		\
	{ { 0x736f6d6570736575ULL ^ (seed1),	\
	    0x646f72616e646f6dULL ^ (seed2),	\
	    0x6c7967656e657261ULL ^ (seed1),	\
	    0x7465646279746573ULL ^ (seed2) } }

/**
 * siphash24_update - include some memory in the hash.
 * @ctx: the siphash24_ctx to use
 * @p: pointer to memory,
 * @size: the number of bytes pointed to by @p
 *
 * You can call this multiple times to hash more data, before calling
 * siphash24_done().
 */
void siphash24_update(struct siphash24_ctx *ctx, const void *p, size_t size);

/**
 * siphash24_done - finish SIPHASH24 and return the hash
 * @ctx: the siphash24_ctx to complete
 *
 * Note that @ctx is *destroyed* by this, and must be reinitialized.
 * To avoid that, pass a copy instead.
 */
uint64_t siphash24_done(struct siphash24_ctx *siphash24);

/* Add various types to an SIPHASH24 hash */
void siphash24_u8(struct siphash24_ctx *ctx, uint8_t v);
void siphash24_u16(struct siphash24_ctx *ctx, uint16_t v);
void siphash24_u32(struct siphash24_ctx *ctx, uint32_t v);
void siphash24_u64(struct siphash24_ctx *ctx, uint64_t v);

/* Add as little-endian */
void siphash24_le16(struct siphash24_ctx *ctx, uint16_t v);
void siphash24_le32(struct siphash24_ctx *ctx, uint32_t v);
void siphash24_le64(struct siphash24_ctx *ctx, uint64_t v);

/* Add as big-endian */
void siphash24_be16(struct siphash24_ctx *ctx, uint16_t v);
void siphash24_be32(struct siphash24_ctx *ctx, uint32_t v);
void siphash24_be64(struct siphash24_ctx *ctx, uint64_t v);
#endif /* CCAN_CRYPTO_SIPHASH24_H */
