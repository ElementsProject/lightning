/* MIT (BSD) license - see LICENSE file for details */
/* RIPEMD core code translated from the Bitcoin project's C++:
 *
 * src/crypto/ripemd160.cpp commit f914f1a746d7f91951c1da262a4a749dd3ebfa71
 * Copyright (c) 2014 The Bitcoin Core developers
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.
 */
#include <ccan/crypto/ripemd160/ripemd160.h>
#include <ccan/endian/endian.h>
#include <ccan/compiler/compiler.h>
#include <stdbool.h>
#include <assert.h>
#include <string.h>

static void invalidate_ripemd160(struct ripemd160_ctx *ctx)
{
#ifdef CCAN_CRYPTO_RIPEMD160_USE_OPENSSL
	ctx->c.num = -1U;
#else
	ctx->bytes = -1ULL;
#endif
}

static void check_ripemd160(struct ripemd160_ctx *ctx UNUSED)
{
#ifdef CCAN_CRYPTO_RIPEMD160_USE_OPENSSL
	assert(ctx->c.num != -1U);
#else
	assert(ctx->bytes != -1ULL);
#endif
}

#ifdef CCAN_CRYPTO_RIPEMD160_USE_OPENSSL
void ripemd160_init(struct ripemd160_ctx *ctx)
{
	RIPEMD160_Init(&ctx->c);
}

void ripemd160_update(struct ripemd160_ctx *ctx, const void *p, size_t size)
{
	check_ripemd160(ctx);
	RIPEMD160_Update(&ctx->c, p, size);
}

void ripemd160_done(struct ripemd160_ctx *ctx, struct ripemd160 *res)
{
	RIPEMD160_Final(res->u.u8, &ctx->c);
	invalidate_ripemd160(ctx);
}
#else
inline static uint32_t f1(uint32_t x, uint32_t y, uint32_t z) { return x ^ y ^ z; }
inline static uint32_t f2(uint32_t x, uint32_t y, uint32_t z) { return (x & y) | (~x & z); }
inline static uint32_t f3(uint32_t x, uint32_t y, uint32_t z) { return (x | ~y) ^ z; }
inline static uint32_t f4(uint32_t x, uint32_t y, uint32_t z) { return (x & z) | (y & ~z); }
inline static uint32_t f5(uint32_t x, uint32_t y, uint32_t z) { return x ^ (y | ~z); }

/** Initialize RIPEMD-160 state. */
inline static void Initialize(uint32_t* s)
{
    s[0] = 0x67452301ul;
    s[1] = 0xEFCDAB89ul;
    s[2] = 0x98BADCFEul;
    s[3] = 0x10325476ul;
    s[4] = 0xC3D2E1F0ul;
}

inline static uint32_t rol(uint32_t x, int i) { return (x << i) | (x >> (32 - i)); }

inline static void Round(uint32_t *a, uint32_t b UNUSED, uint32_t *c, uint32_t d UNUSED, uint32_t e, uint32_t f, uint32_t x, uint32_t k, int r)
{
    *a = rol(*a + f + x + k, r) + e;
    *c = rol(*c, 10);
}

inline static void R11(uint32_t *a, uint32_t b, uint32_t *c, uint32_t d, uint32_t e, uint32_t x, int r) { Round(a, b, c, d, e, f1(b, *c, d), x, 0, r); }
inline static void R21(uint32_t *a, uint32_t b, uint32_t *c, uint32_t d, uint32_t e, uint32_t x, int r) { Round(a, b, c, d, e, f2(b, *c, d), x, 0x5A827999ul, r); }
inline static void R31(uint32_t *a, uint32_t b, uint32_t *c, uint32_t d, uint32_t e, uint32_t x, int r) { Round(a, b, c, d, e, f3(b, *c, d), x, 0x6ED9EBA1ul, r); }
inline static void R41(uint32_t *a, uint32_t b, uint32_t *c, uint32_t d, uint32_t e, uint32_t x, int r) { Round(a, b, c, d, e, f4(b, *c, d), x, 0x8F1BBCDCul, r); }
inline static void R51(uint32_t *a, uint32_t b, uint32_t *c, uint32_t d, uint32_t e, uint32_t x, int r) { Round(a, b, c, d, e, f5(b, *c, d), x, 0xA953FD4Eul, r); }

inline static void R12(uint32_t *a, uint32_t b, uint32_t *c, uint32_t d, uint32_t e, uint32_t x, int r) { Round(a, b, c, d, e, f5(b, *c, d), x, 0x50A28BE6ul, r); }
inline static void R22(uint32_t *a, uint32_t b, uint32_t *c, uint32_t d, uint32_t e, uint32_t x, int r) { Round(a, b, c, d, e, f4(b, *c, d), x, 0x5C4DD124ul, r); }
inline static void R32(uint32_t *a, uint32_t b, uint32_t *c, uint32_t d, uint32_t e, uint32_t x, int r) { Round(a, b, c, d, e, f3(b, *c, d), x, 0x6D703EF3ul, r); }
inline static void R42(uint32_t *a, uint32_t b, uint32_t *c, uint32_t d, uint32_t e, uint32_t x, int r) { Round(a, b, c, d, e, f2(b, *c, d), x, 0x7A6D76E9ul, r); }
inline static void R52(uint32_t *a, uint32_t b, uint32_t *c, uint32_t d, uint32_t e, uint32_t x, int r) { Round(a, b, c, d, e, f1(b, *c, d), x, 0, r); }

/** Perform a RIPEMD-160 transformation, processing a 64-byte chunk. */
static void Transform(uint32_t *s, const uint32_t *chunk)
{
    uint32_t a1 = s[0], b1 = s[1], c1 = s[2], d1 = s[3], e1 = s[4];
    uint32_t a2 = a1, b2 = b1, c2 = c1, d2 = d1, e2 = e1;
    uint32_t w0 = le32_to_cpu(chunk[0]), w1 = le32_to_cpu(chunk[1]), w2 = le32_to_cpu(chunk[2]), w3 = le32_to_cpu(chunk[3]);
    uint32_t w4 = le32_to_cpu(chunk[4]), w5 = le32_to_cpu(chunk[5]), w6 = le32_to_cpu(chunk[6]), w7 = le32_to_cpu(chunk[7]);
    uint32_t w8 = le32_to_cpu(chunk[8]), w9 = le32_to_cpu(chunk[9]), w10 = le32_to_cpu(chunk[10]), w11 = le32_to_cpu(chunk[11]);
    uint32_t w12 = le32_to_cpu(chunk[12]), w13 = le32_to_cpu(chunk[13]), w14 = le32_to_cpu(chunk[14]), w15 = le32_to_cpu(chunk[15]);
    uint32_t t;

    R11(&a1, b1, &c1, d1, e1, w0, 11);
    R12(&a2, b2, &c2, d2, e2, w5, 8);
    R11(&e1, a1, &b1, c1, d1, w1, 14);
    R12(&e2, a2, &b2, c2, d2, w14, 9);
    R11(&d1, e1, &a1, b1, c1, w2, 15);
    R12(&d2, e2, &a2, b2, c2, w7, 9);
    R11(&c1, d1, &e1, a1, b1, w3, 12);
    R12(&c2, d2, &e2, a2, b2, w0, 11);
    R11(&b1, c1, &d1, e1, a1, w4, 5);
    R12(&b2, c2, &d2, e2, a2, w9, 13);
    R11(&a1, b1, &c1, d1, e1, w5, 8);
    R12(&a2, b2, &c2, d2, e2, w2, 15);
    R11(&e1, a1, &b1, c1, d1, w6, 7);
    R12(&e2, a2, &b2, c2, d2, w11, 15);
    R11(&d1, e1, &a1, b1, c1, w7, 9);
    R12(&d2, e2, &a2, b2, c2, w4, 5);
    R11(&c1, d1, &e1, a1, b1, w8, 11);
    R12(&c2, d2, &e2, a2, b2, w13, 7);
    R11(&b1, c1, &d1, e1, a1, w9, 13);
    R12(&b2, c2, &d2, e2, a2, w6, 7);
    R11(&a1, b1, &c1, d1, e1, w10, 14);
    R12(&a2, b2, &c2, d2, e2, w15, 8);
    R11(&e1, a1, &b1, c1, d1, w11, 15);
    R12(&e2, a2, &b2, c2, d2, w8, 11);
    R11(&d1, e1, &a1, b1, c1, w12, 6);
    R12(&d2, e2, &a2, b2, c2, w1, 14);
    R11(&c1, d1, &e1, a1, b1, w13, 7);
    R12(&c2, d2, &e2, a2, b2, w10, 14);
    R11(&b1, c1, &d1, e1, a1, w14, 9);
    R12(&b2, c2, &d2, e2, a2, w3, 12);
    R11(&a1, b1, &c1, d1, e1, w15, 8);
    R12(&a2, b2, &c2, d2, e2, w12, 6);

    R21(&e1, a1, &b1, c1, d1, w7, 7);
    R22(&e2, a2, &b2, c2, d2, w6, 9);
    R21(&d1, e1, &a1, b1, c1, w4, 6);
    R22(&d2, e2, &a2, b2, c2, w11, 13);
    R21(&c1, d1, &e1, a1, b1, w13, 8);
    R22(&c2, d2, &e2, a2, b2, w3, 15);
    R21(&b1, c1, &d1, e1, a1, w1, 13);
    R22(&b2, c2, &d2, e2, a2, w7, 7);
    R21(&a1, b1, &c1, d1, e1, w10, 11);
    R22(&a2, b2, &c2, d2, e2, w0, 12);
    R21(&e1, a1, &b1, c1, d1, w6, 9);
    R22(&e2, a2, &b2, c2, d2, w13, 8);
    R21(&d1, e1, &a1, b1, c1, w15, 7);
    R22(&d2, e2, &a2, b2, c2, w5, 9);
    R21(&c1, d1, &e1, a1, b1, w3, 15);
    R22(&c2, d2, &e2, a2, b2, w10, 11);
    R21(&b1, c1, &d1, e1, a1, w12, 7);
    R22(&b2, c2, &d2, e2, a2, w14, 7);
    R21(&a1, b1, &c1, d1, e1, w0, 12);
    R22(&a2, b2, &c2, d2, e2, w15, 7);
    R21(&e1, a1, &b1, c1, d1, w9, 15);
    R22(&e2, a2, &b2, c2, d2, w8, 12);
    R21(&d1, e1, &a1, b1, c1, w5, 9);
    R22(&d2, e2, &a2, b2, c2, w12, 7);
    R21(&c1, d1, &e1, a1, b1, w2, 11);
    R22(&c2, d2, &e2, a2, b2, w4, 6);
    R21(&b1, c1, &d1, e1, a1, w14, 7);
    R22(&b2, c2, &d2, e2, a2, w9, 15);
    R21(&a1, b1, &c1, d1, e1, w11, 13);
    R22(&a2, b2, &c2, d2, e2, w1, 13);
    R21(&e1, a1, &b1, c1, d1, w8, 12);
    R22(&e2, a2, &b2, c2, d2, w2, 11);

    R31(&d1, e1, &a1, b1, c1, w3, 11);
    R32(&d2, e2, &a2, b2, c2, w15, 9);
    R31(&c1, d1, &e1, a1, b1, w10, 13);
    R32(&c2, d2, &e2, a2, b2, w5, 7);
    R31(&b1, c1, &d1, e1, a1, w14, 6);
    R32(&b2, c2, &d2, e2, a2, w1, 15);
    R31(&a1, b1, &c1, d1, e1, w4, 7);
    R32(&a2, b2, &c2, d2, e2, w3, 11);
    R31(&e1, a1, &b1, c1, d1, w9, 14);
    R32(&e2, a2, &b2, c2, d2, w7, 8);
    R31(&d1, e1, &a1, b1, c1, w15, 9);
    R32(&d2, e2, &a2, b2, c2, w14, 6);
    R31(&c1, d1, &e1, a1, b1, w8, 13);
    R32(&c2, d2, &e2, a2, b2, w6, 6);
    R31(&b1, c1, &d1, e1, a1, w1, 15);
    R32(&b2, c2, &d2, e2, a2, w9, 14);
    R31(&a1, b1, &c1, d1, e1, w2, 14);
    R32(&a2, b2, &c2, d2, e2, w11, 12);
    R31(&e1, a1, &b1, c1, d1, w7, 8);
    R32(&e2, a2, &b2, c2, d2, w8, 13);
    R31(&d1, e1, &a1, b1, c1, w0, 13);
    R32(&d2, e2, &a2, b2, c2, w12, 5);
    R31(&c1, d1, &e1, a1, b1, w6, 6);
    R32(&c2, d2, &e2, a2, b2, w2, 14);
    R31(&b1, c1, &d1, e1, a1, w13, 5);
    R32(&b2, c2, &d2, e2, a2, w10, 13);
    R31(&a1, b1, &c1, d1, e1, w11, 12);
    R32(&a2, b2, &c2, d2, e2, w0, 13);
    R31(&e1, a1, &b1, c1, d1, w5, 7);
    R32(&e2, a2, &b2, c2, d2, w4, 7);
    R31(&d1, e1, &a1, b1, c1, w12, 5);
    R32(&d2, e2, &a2, b2, c2, w13, 5);

    R41(&c1, d1, &e1, a1, b1, w1, 11);
    R42(&c2, d2, &e2, a2, b2, w8, 15);
    R41(&b1, c1, &d1, e1, a1, w9, 12);
    R42(&b2, c2, &d2, e2, a2, w6, 5);
    R41(&a1, b1, &c1, d1, e1, w11, 14);
    R42(&a2, b2, &c2, d2, e2, w4, 8);
    R41(&e1, a1, &b1, c1, d1, w10, 15);
    R42(&e2, a2, &b2, c2, d2, w1, 11);
    R41(&d1, e1, &a1, b1, c1, w0, 14);
    R42(&d2, e2, &a2, b2, c2, w3, 14);
    R41(&c1, d1, &e1, a1, b1, w8, 15);
    R42(&c2, d2, &e2, a2, b2, w11, 14);
    R41(&b1, c1, &d1, e1, a1, w12, 9);
    R42(&b2, c2, &d2, e2, a2, w15, 6);
    R41(&a1, b1, &c1, d1, e1, w4, 8);
    R42(&a2, b2, &c2, d2, e2, w0, 14);
    R41(&e1, a1, &b1, c1, d1, w13, 9);
    R42(&e2, a2, &b2, c2, d2, w5, 6);
    R41(&d1, e1, &a1, b1, c1, w3, 14);
    R42(&d2, e2, &a2, b2, c2, w12, 9);
    R41(&c1, d1, &e1, a1, b1, w7, 5);
    R42(&c2, d2, &e2, a2, b2, w2, 12);
    R41(&b1, c1, &d1, e1, a1, w15, 6);
    R42(&b2, c2, &d2, e2, a2, w13, 9);
    R41(&a1, b1, &c1, d1, e1, w14, 8);
    R42(&a2, b2, &c2, d2, e2, w9, 12);
    R41(&e1, a1, &b1, c1, d1, w5, 6);
    R42(&e2, a2, &b2, c2, d2, w7, 5);
    R41(&d1, e1, &a1, b1, c1, w6, 5);
    R42(&d2, e2, &a2, b2, c2, w10, 15);
    R41(&c1, d1, &e1, a1, b1, w2, 12);
    R42(&c2, d2, &e2, a2, b2, w14, 8);

    R51(&b1, c1, &d1, e1, a1, w4, 9);
    R52(&b2, c2, &d2, e2, a2, w12, 8);
    R51(&a1, b1, &c1, d1, e1, w0, 15);
    R52(&a2, b2, &c2, d2, e2, w15, 5);
    R51(&e1, a1, &b1, c1, d1, w5, 5);
    R52(&e2, a2, &b2, c2, d2, w10, 12);
    R51(&d1, e1, &a1, b1, c1, w9, 11);
    R52(&d2, e2, &a2, b2, c2, w4, 9);
    R51(&c1, d1, &e1, a1, b1, w7, 6);
    R52(&c2, d2, &e2, a2, b2, w1, 12);
    R51(&b1, c1, &d1, e1, a1, w12, 8);
    R52(&b2, c2, &d2, e2, a2, w5, 5);
    R51(&a1, b1, &c1, d1, e1, w2, 13);
    R52(&a2, b2, &c2, d2, e2, w8, 14);
    R51(&e1, a1, &b1, c1, d1, w10, 12);
    R52(&e2, a2, &b2, c2, d2, w7, 6);
    R51(&d1, e1, &a1, b1, c1, w14, 5);
    R52(&d2, e2, &a2, b2, c2, w6, 8);
    R51(&c1, d1, &e1, a1, b1, w1, 12);
    R52(&c2, d2, &e2, a2, b2, w2, 13);
    R51(&b1, c1, &d1, e1, a1, w3, 13);
    R52(&b2, c2, &d2, e2, a2, w13, 6);
    R51(&a1, b1, &c1, d1, e1, w8, 14);
    R52(&a2, b2, &c2, d2, e2, w14, 5);
    R51(&e1, a1, &b1, c1, d1, w11, 11);
    R52(&e2, a2, &b2, c2, d2, w0, 15);
    R51(&d1, e1, &a1, b1, c1, w6, 8);
    R52(&d2, e2, &a2, b2, c2, w3, 13);
    R51(&c1, d1, &e1, a1, b1, w15, 5);
    R52(&c2, d2, &e2, a2, b2, w9, 11);
    R51(&b1, c1, &d1, e1, a1, w13, 6);
    R52(&b2, c2, &d2, e2, a2, w11, 11);

    t = s[0];
    s[0] = s[1] + c1 + d2;
    s[1] = s[2] + d1 + e2;
    s[2] = s[3] + e1 + a2;
    s[3] = s[4] + a1 + b2;
    s[4] = t + b1 + c2;
}

static void add(struct ripemd160_ctx *ctx, const void *p, size_t len)
{
	const unsigned char *data = p;
	size_t bufsize = ctx->bytes % 64;

	if (bufsize + len >= 64) {
		/* Fill the buffer, and process it. */
		memcpy(ctx->buf.u8 + bufsize, data, 64 - bufsize);
		ctx->bytes += 64 - bufsize;
		data += 64 - bufsize;
		len -= 64 - bufsize;
		Transform(ctx->s, ctx->buf.u32);
		bufsize = 0;
	}

	while (len >= 64) {
		/* Process full chunks directly from the source. */
		if (alignment_ok(data, sizeof(uint32_t)))
			Transform(ctx->s, (const uint32_t *)data);
		else {
			memcpy(ctx->buf.u8, data, sizeof(ctx->buf));
			Transform(ctx->s, ctx->buf.u32);
		}
		ctx->bytes += 64;
		data += 64;
		len -= 64;
	}
	    
	if (len) {
		/* Fill the buffer with what remains. */
		memcpy(ctx->buf.u8 + bufsize, data, len);
		ctx->bytes += len;
	}
}

void ripemd160_init(struct ripemd160_ctx *ctx)
{
	struct ripemd160_ctx init = RIPEMD160_INIT;
	*ctx = init;
}

void ripemd160_update(struct ripemd160_ctx *ctx, const void *p, size_t size)
{
	check_ripemd160(ctx);
	add(ctx, p, size);
}

void ripemd160_done(struct ripemd160_ctx *ctx, struct ripemd160 *res)
{
	static const unsigned char pad[64] = {0x80};
	uint64_t sizedesc;
	size_t i;

	sizedesc = cpu_to_le64(ctx->bytes << 3);
	/* Add '1' bit to terminate, then all 0 bits, up to next block - 8. */
	add(ctx, pad, 1 + ((119 - (ctx->bytes % 64)) % 64));
	/* Add number of bits of data (big endian) */
	add(ctx, &sizedesc, 8);
	for (i = 0; i < sizeof(ctx->s) / sizeof(ctx->s[0]); i++)
		res->u.u32[i] = cpu_to_le32(ctx->s[i]);
	invalidate_ripemd160(ctx);
}
#endif

void ripemd160(struct ripemd160 *ripemd, const void *p, size_t size)
{
	struct ripemd160_ctx ctx;

	ripemd160_init(&ctx);
	ripemd160_update(&ctx, p, size);
	ripemd160_done(&ctx, ripemd);
	CCAN_CLEAR_MEMORY(&ctx, sizeof(ctx));
}
	
void ripemd160_u8(struct ripemd160_ctx *ctx, uint8_t v)
{
	ripemd160_update(ctx, &v, sizeof(v));
}

void ripemd160_u16(struct ripemd160_ctx *ctx, uint16_t v)
{
	ripemd160_update(ctx, &v, sizeof(v));
}

void ripemd160_u32(struct ripemd160_ctx *ctx, uint32_t v)
{
	ripemd160_update(ctx, &v, sizeof(v));
}

void ripemd160_u64(struct ripemd160_ctx *ctx, uint64_t v)
{
	ripemd160_update(ctx, &v, sizeof(v));
}

/* Add as little-endian */
void ripemd160_le16(struct ripemd160_ctx *ctx, uint16_t v)
{
	leint16_t lev = cpu_to_le16(v);
	ripemd160_update(ctx, &lev, sizeof(lev));
}
	
void ripemd160_le32(struct ripemd160_ctx *ctx, uint32_t v)
{
	leint32_t lev = cpu_to_le32(v);
	ripemd160_update(ctx, &lev, sizeof(lev));
}
	
void ripemd160_le64(struct ripemd160_ctx *ctx, uint64_t v)
{
	leint64_t lev = cpu_to_le64(v);
	ripemd160_update(ctx, &lev, sizeof(lev));
}

/* Add as big-endian */
void ripemd160_be16(struct ripemd160_ctx *ctx, uint16_t v)
{
	beint16_t bev = cpu_to_be16(v);
	ripemd160_update(ctx, &bev, sizeof(bev));
}
	
void ripemd160_be32(struct ripemd160_ctx *ctx, uint32_t v)
{
	beint32_t bev = cpu_to_be32(v);
	ripemd160_update(ctx, &bev, sizeof(bev));
}
	
void ripemd160_be64(struct ripemd160_ctx *ctx, uint64_t v)
{
	beint64_t bev = cpu_to_be64(v);
	ripemd160_update(ctx, &bev, sizeof(bev));
}
