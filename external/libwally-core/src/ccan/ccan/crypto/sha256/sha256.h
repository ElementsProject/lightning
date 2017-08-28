#ifndef CCAN_CRYPTO_SHA256_H
#define CCAN_CRYPTO_SHA256_H
/* BSD-MIT - see LICENSE file for details */
#include "config.h"
#include <stdint.h>
#include <stdlib.h>

/* Uncomment this to use openssl's SHA256 routines (and link with -lcrypto) */
/*#define CCAN_CRYPTO_SHA256_USE_OPENSSL 1*/

#ifdef CCAN_CRYPTO_SHA256_USE_OPENSSL
#include <openssl/sha.h>
#endif

/**
 * struct sha256 - structure representing a completed SHA256.
 * @u.u8: an unsigned char array.
 * @u.u32: a 32-bit integer array.
 *
 * Other fields may be added to the union in future.
 */
struct sha256 {
	union {
		uint32_t u32[8];
		unsigned char u8[32];
	} u;
};

/**
 * sha256 - return sha256 of an object.
 * @sha256: the sha256 to fill in
 * @p: pointer to memory,
 * @size: the number of bytes pointed to by @p
 *
 * The bytes pointed to by @p is SHA256 hashed into @sha256.  This is
 * equivalent to sha256_init(), sha256_update() then sha256_done().
 */
void sha256(struct sha256 *sha, const void *p, size_t size);

/**
 * struct sha256_ctx - structure to store running context for sha256
 */
struct sha256_ctx {
#ifdef CCAN_CRYPTO_SHA256_USE_OPENSSL
	SHA256_CTX c;
#else
	uint32_t s[8];
	union {
		uint32_t u32[16];
		unsigned char u8[64];
	} buf;
	size_t bytes;
#endif
};

/**
 * sha256_init - initialize an SHA256 context.
 * @ctx: the sha256_ctx to initialize
 *
 * This must be called before sha256_update or sha256_done, or
 * alternately you can assign SHA256_INIT.
 *
 * If it was already initialized, this forgets anything which was
 * hashed before.
 *
 * Example:
 * static void hash_all(const char **arr, struct sha256 *hash)
 * {
 *	size_t i;
 *	struct sha256_ctx ctx;
 *
 *	sha256_init(&ctx);
 *	for (i = 0; arr[i]; i++)
 *		sha256_update(&ctx, arr[i], strlen(arr[i]));
 *	sha256_done(&ctx, hash);
 * }
 */
void sha256_init(struct sha256_ctx *ctx);

/**
 * SHA256_INIT - initializer for an SHA256 context.
 *
 * This can be used to staticly initialize an SHA256 context (instead
 * of sha256_init()).
 *
 * Example:
 * static void hash_all(const char **arr, struct sha256 *hash)
 * {
 *	size_t i;
 *	struct sha256_ctx ctx = SHA256_INIT;
 *
 *	for (i = 0; arr[i]; i++)
 *		sha256_update(&ctx, arr[i], strlen(arr[i]));
 *	sha256_done(&ctx, hash);
 * }
 */
#ifdef CCAN_CRYPTO_SHA256_USE_OPENSSL
#define SHA256_INIT							\
	{ { { 0x6a09e667ul, 0xbb67ae85ul, 0x3c6ef372ul, 0xa54ff53aul,	\
	      0x510e527ful, 0x9b05688cul, 0x1f83d9abul, 0x5be0cd19ul }, \
		0x0, 0x0,						\
		{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },	\
			0x0, 0x20 } }
#else
#define SHA256_INIT							\
	{ { 0x6a09e667ul, 0xbb67ae85ul, 0x3c6ef372ul, 0xa54ff53aul,	\
	    0x510e527ful, 0x9b05688cul, 0x1f83d9abul, 0x5be0cd19ul },	\
	  { { 0 } }, 0 }
#endif

/**
 * sha256_update - include some memory in the hash.
 * @ctx: the sha256_ctx to use
 * @p: pointer to memory,
 * @size: the number of bytes pointed to by @p
 *
 * You can call this multiple times to hash more data, before calling
 * sha256_done().
 */
void sha256_update(struct sha256_ctx *ctx, const void *p, size_t size);

/**
 * sha256_done - finish SHA256 and return the hash
 * @ctx: the sha256_ctx to complete
 * @res: the hash to return.
 *
 * Note that @ctx is *destroyed* by this, and must be reinitialized.
 * To avoid that, pass a copy instead.
 */
void sha256_done(struct sha256_ctx *sha256, struct sha256 *res);

/* Add various types to an SHA256 hash */
void sha256_u8(struct sha256_ctx *ctx, uint8_t v);
void sha256_u16(struct sha256_ctx *ctx, uint16_t v);
void sha256_u32(struct sha256_ctx *ctx, uint32_t v);
void sha256_u64(struct sha256_ctx *ctx, uint64_t v);

/* Add as little-endian */
void sha256_le16(struct sha256_ctx *ctx, uint16_t v);
void sha256_le32(struct sha256_ctx *ctx, uint32_t v);
void sha256_le64(struct sha256_ctx *ctx, uint64_t v);

/* Add as big-endian */
void sha256_be16(struct sha256_ctx *ctx, uint16_t v);
void sha256_be32(struct sha256_ctx *ctx, uint32_t v);
void sha256_be64(struct sha256_ctx *ctx, uint64_t v);
#endif /* CCAN_CRYPTO_SHA256_H */
