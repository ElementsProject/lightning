#ifndef CCAN_CRYPTO_RIPEMD160_H
#define CCAN_CRYPTO_RIPEMD160_H
/* BSD-MIT - see LICENSE file for details */
#include "config.h"
#include <stdint.h>
#include <stdlib.h>

/* Uncomment this to use openssl's RIPEMD160 routines (and link with -lcrypto) */
/*#define CCAN_CRYPTO_RIPEMD160_USE_OPENSSL 1*/

#ifdef CCAN_CRYPTO_RIPEMD160_USE_OPENSSL
#include <openssl/ripemd.h>
#endif

/**
 * struct ripemd160 - structure representing a completed RIPEMD160.
 * @u.u8: an unsigned char array.
 * @u.u32: a 32-bit integer array.
 *
 * Other fields may be added to the union in future.
 */
struct ripemd160 {
	union {
		/* Array of chars */
		unsigned char u8[20];
		/* Array of uint32_t */
		uint32_t u32[5];
	} u;
};

/**
 * ripemd160 - return ripemd160 of an object.
 * @ripemd160: the ripemd160 to fill in
 * @p: pointer to memory,
 * @size: the number of bytes pointed to by @p
 *
 * The bytes pointed to by @p is RIPEMD160 hashed into @ripemd160.  This is
 * equivalent to ripemd160_init(), ripemd160_update() then ripemd160_done().
 */
void ripemd160(struct ripemd160 *ripemd, const void *p, size_t size);

/**
 * struct ripemd160_ctx - structure to store running context for ripemd160
 */
struct ripemd160_ctx {
#ifdef CCAN_CRYPTO_RIPEMD160_USE_OPENSSL
	RIPEMD160_CTX c;
#else
	uint32_t s[5];
	uint64_t bytes;
	union {
		uint32_t u32[16];
		unsigned char u8[64];
	} buf;
#endif
};

/**
 * ripemd160_init - initialize an RIPEMD160 context.
 * @ctx: the ripemd160_ctx to initialize
 *
 * This must be called before ripemd160_update or ripemd160_done, or
 * alternately you can assign RIPEMD160_INIT.
 *
 * If it was already initialized, this forgets anything which was
 * hashed before.
 *
 * Example:
 * static void hash_all(const char **arr, struct ripemd160 *hash)
 * {
 *	size_t i;
 *	struct ripemd160_ctx ctx;
 *
 *	ripemd160_init(&ctx);
 *	for (i = 0; arr[i]; i++)
 *		ripemd160_update(&ctx, arr[i], strlen(arr[i]));
 *	ripemd160_done(&ctx, hash);
 * }
 */
void ripemd160_init(struct ripemd160_ctx *ctx);

/**
 * RIPEMD160_INIT - initializer for an RIPEMD160 context.
 *
 * This can be used to staticly initialize an RIPEMD160 context (instead
 * of ripemd160_init()).
 *
 * Example:
 * static void hash_all(const char **arr, struct ripemd160 *hash)
 * {
 *	size_t i;
 *	struct ripemd160_ctx ctx = RIPEMD160_INIT;
 *
 *	for (i = 0; arr[i]; i++)
 *		ripemd160_update(&ctx, arr[i], strlen(arr[i]));
 *	ripemd160_done(&ctx, hash);
 * }
 */
#ifdef CCAN_CRYPTO_RIPEMD160_USE_OPENSSL
#define RIPEMD160_INIT							\
	{ { 0x67452301ul, 0xEFCDAB89ul, 0x98BADCFEul, 0x10325476ul,	\
	    0xC3D2E1F0ul,						\
	    0x0, 0x0,							\
	    { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },		\
	    0 } }
#else
#define RIPEMD160_INIT							\
	{ { 0x67452301ul, 0xEFCDAB89ul, 0x98BADCFEul, 0x10325476ul,	\
	    0xC3D2E1F0ul }, 0, {{ 0 }} }
#endif

/**
 * ripemd160_update - include some memory in the hash.
 * @ctx: the ripemd160_ctx to use
 * @p: pointer to memory,
 * @size: the number of bytes pointed to by @p
 *
 * You can call this multiple times to hash more data, before calling
 * ripemd160_done().
 */
void ripemd160_update(struct ripemd160_ctx *ctx, const void *p, size_t size);

/**
 * ripemd160_done - finish RIPEMD160 and return the hash
 * @ctx: the ripemd160_ctx to complete
 * @res: the hash to return.
 *
 * Note that @ctx is *destroyed* by this, and must be reinitialized.
 * To avoid that, pass a copy instead.
 */
void ripemd160_done(struct ripemd160_ctx *ripemd160, struct ripemd160 *res);

/* Add various types to an RIPEMD160 hash */
void ripemd160_u8(struct ripemd160_ctx *ctx, uint8_t v);
void ripemd160_u16(struct ripemd160_ctx *ctx, uint16_t v);
void ripemd160_u32(struct ripemd160_ctx *ctx, uint32_t v);
void ripemd160_u64(struct ripemd160_ctx *ctx, uint64_t v);

/* Add as little-endian */
void ripemd160_le16(struct ripemd160_ctx *ctx, uint16_t v);
void ripemd160_le32(struct ripemd160_ctx *ctx, uint32_t v);
void ripemd160_le64(struct ripemd160_ctx *ctx, uint64_t v);

/* Add as big-endian */
void ripemd160_be16(struct ripemd160_ctx *ctx, uint16_t v);
void ripemd160_be32(struct ripemd160_ctx *ctx, uint32_t v);
void ripemd160_be64(struct ripemd160_ctx *ctx, uint64_t v);
#endif /* CCAN_CRYPTO_RIPEMD160_H */
