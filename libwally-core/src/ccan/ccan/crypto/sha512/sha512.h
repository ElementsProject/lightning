#ifndef CCAN_CRYPTO_SHA512_H
#define CCAN_CRYPTO_SHA512_H
/* BSD-MIT - see LICENSE file for details */
#include "config.h"
#include <stdint.h>
#include <stdlib.h>

/* Uncomment this to use openssl's SHA512 routines (and link with -lcrypto) */
/*#define CCAN_CRYPTO_SHA512_USE_OPENSSL 1*/

#ifdef CCAN_CRYPTO_SHA512_USE_OPENSSL
#include <openssl/sha.h>
#endif

/**
 * struct sha512 - structure representing a completed SHA512.
 * @u.u8: an unsigned char array.
 * @u.u64: a 64-bit integer array.
 *
 * Other fields may be added to the union in future.
 */
struct sha512 {
	union {
		uint64_t u64[8];
		unsigned char u8[64];
	} u;
};

/**
 * sha512 - return sha512 of an object.
 * @sha512: the sha512 to fill in
 * @p: pointer to memory,
 * @size: the number of bytes pointed to by @p
 *
 * The bytes pointed to by @p is SHA512 hashed into @sha512.  This is
 * equivalent to sha512_init(), sha512_update() then sha512_done().
 */
void sha512(struct sha512 *sha, const void *p, size_t size);

/**
 * struct sha512_ctx - structure to store running context for sha512
 */
struct sha512_ctx {
#ifdef CCAN_CRYPTO_SHA512_USE_OPENSSL
	SHA512_CTX c;
#else
	uint64_t s[8];
	union {
		uint64_t u64[16];
		unsigned char u8[128];
	} buf;
	size_t bytes;
#endif
};

/**
 * sha512_init - initialize an SHA512 context.
 * @ctx: the sha512_ctx to initialize
 *
 * This must be called before sha512_update or sha512_done, or
 * alternately you can assign SHA512_INIT.
 *
 * If it was already initialized, this forgets anything which was
 * hashed before.
 *
 * Example:
 * static void hash_all(const char **arr, struct sha512 *hash)
 * {
 *	size_t i;
 *	struct sha512_ctx ctx;
 *
 *	sha512_init(&ctx);
 *	for (i = 0; arr[i]; i++)
 *		sha512_update(&ctx, arr[i], strlen(arr[i]));
 *	sha512_done(&ctx, hash);
 * }
 */
void sha512_init(struct sha512_ctx *ctx);

/**
 * SHA512_INIT - initializer for an SHA512 context.
 *
 * This can be used to statically initialize an SHA512 context (instead
 * of sha512_init()).
 *
 * Example:
 * static void hash_all(const char **arr, struct sha512 *hash)
 * {
 *	size_t i;
 *	struct sha512_ctx ctx = SHA512_INIT;
 *
 *	for (i = 0; arr[i]; i++)
 *		sha512_update(&ctx, arr[i], strlen(arr[i]));
 *	sha512_done(&ctx, hash);
 * }
 */
#ifdef CCAN_CRYPTO_SHA512_USE_OPENSSL
	{ { { 0x6a09e667f3bcc908ull, 0xbb67ae8584caa73bull,	\
	      0x3c6ef372fe94f82bull, 0xa54ff53a5f1d36f1ull,	\
	      0x510e527fade682d1ull, 0x9b05688c2b3e6c1full,	\
	      0x1f83d9abfb41bd6bull, 0x5be0cd19137e2179ull },	\
	    0, 0,						\
	    { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },	\
	    0, 0x40 } }
#else
#define SHA512_INIT						\
	{ { 0x6a09e667f3bcc908ull, 0xbb67ae8584caa73bull,	\
	    0x3c6ef372fe94f82bull, 0xa54ff53a5f1d36f1ull,	\
	    0x510e527fade682d1ull, 0x9b05688c2b3e6c1full,	\
	    0x1f83d9abfb41bd6bull, 0x5be0cd19137e2179ull },	\
	  { { 0 } }, 0 }
#endif

/**
 * sha512_update - include some memory in the hash.
 * @ctx: the sha512_ctx to use
 * @p: pointer to memory,
 * @size: the number of bytes pointed to by @p
 *
 * You can call this multiple times to hash more data, before calling
 * sha512_done().
 */
void sha512_update(struct sha512_ctx *ctx, const void *p, size_t size);

/**
 * sha512_done - finish SHA512 and return the hash
 * @ctx: the sha512_ctx to complete
 * @res: the hash to return.
 *
 * Note that @ctx is *destroyed* by this, and must be reinitialized.
 * To avoid that, pass a copy instead.
 */
void sha512_done(struct sha512_ctx *sha512, struct sha512 *res);

#endif /* CCAN_CRYPTO_SHA512_H */
