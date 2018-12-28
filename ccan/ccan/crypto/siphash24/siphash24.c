/* CC0 license (public domain) - see LICENSE file for details */
/* Based on CC0 reference implementation:
 * https://github.com/veorq/SipHash c03e6bbf6613243bc30788912ad4afbc0b992d47
 */
#include <ccan/crypto/siphash24/siphash24.h>
#include <ccan/endian/endian.h>
#include <stdbool.h>
#include <assert.h>
#include <string.h>

/* default: SipHash-2-4 */
#define cROUNDS 2
#define dROUNDS 4

#define ROTL(x, b) (uint64_t)(((x) << (b)) | ((x) >> (64 - (b))))

#define SIPROUND(v)							\
	do {								\
		v[0] += v[1];						\
		v[1] = ROTL(v[1], 13);					\
		v[1] ^= v[0];						\
		v[0] = ROTL(v[0], 32);					\
		v[2] += v[3];						\
		v[3] = ROTL(v[3], 16);					\
		v[3] ^= v[2];						\
		v[0] += v[3];						\
		v[3] = ROTL(v[3], 21);					\
		v[3] ^= v[0];						\
		v[2] += v[1];						\
		v[1] = ROTL(v[1], 17);					\
		v[1] ^= v[2];						\
		v[2] = ROTL(v[2], 32);					\
	} while (0)

static void invalidate_siphash24(struct siphash24_ctx *ctx)
{
	ctx->bytes = -1ULL;
}

static void check_siphash24(struct siphash24_ctx *ctx)
{
	assert(ctx->bytes != -1ULL);
}

static bool alignment_ok(const void *p, size_t n)
{
#if HAVE_UNALIGNED_ACCESS
	(void)p; (void)n;
	return true;
#else
	return ((size_t)p % n == 0);
#endif
}

static void add_64bits(uint64_t v[4], uint64_t in)
{
	int i;
	uint64_t m = cpu_to_le64(in);
	v[3] ^= m;

	for (i = 0; i < cROUNDS; ++i)
		SIPROUND(v);

	v[0] ^= m;
}

static void add(struct siphash24_ctx *ctx, const void *p, size_t len)
{
	const unsigned char *data = p;
	size_t bufsize = ctx->bytes % sizeof(ctx->buf.u8);

	if (bufsize + len >= sizeof(ctx->buf.u8)) {
		// Fill the buffer, and process it.
		memcpy(ctx->buf.u8 + bufsize, data,
		       sizeof(ctx->buf.u8) - bufsize);
		ctx->bytes += sizeof(ctx->buf.u8) - bufsize;
		data += sizeof(ctx->buf.u8) - bufsize;
		len -= sizeof(ctx->buf.u8) - bufsize;
		add_64bits(ctx->v, ctx->buf.u64);
		bufsize = 0;
	}

	while (len >= sizeof(ctx->buf.u8)) {
		// Process full chunks directly from the source.
		if (alignment_ok(data, sizeof(uint64_t)))
			add_64bits(ctx->v, *(const uint64_t *)data);
		else {
			memcpy(ctx->buf.u8, data, sizeof(ctx->buf));
			add_64bits(ctx->v, ctx->buf.u64);
		}
		ctx->bytes += sizeof(ctx->buf.u8);
		data += sizeof(ctx->buf.u8);
		len -= sizeof(ctx->buf.u8);
	}
	    
	if (len) {
		// Fill the buffer with what remains.
		memcpy(ctx->buf.u8 + bufsize, data, len);
		ctx->bytes += len;
	}
}

void siphash24_init(struct siphash24_ctx *ctx, const struct siphash_seed *seed)
{
	struct siphash24_ctx init = SIPHASH24_INIT(0, 0);
	*ctx = init;
	ctx->v[0] ^= seed->u.u64[0];
	ctx->v[1] ^= seed->u.u64[1];
	ctx->v[2] ^= seed->u.u64[0];
	ctx->v[3] ^= seed->u.u64[1];
}

void siphash24_update(struct siphash24_ctx *ctx, const void *p, size_t size)
{
	check_siphash24(ctx);
	add(ctx, p, size);
}

uint64_t siphash24_done(struct siphash24_ctx *ctx)
{
	uint64_t b;
	int i;

	b = ctx->bytes << 56;

	switch (ctx->bytes % 8) {
	case 7:
		b |= ((uint64_t)ctx->buf.u8[6]) << 48;
	case 6:
		b |= ((uint64_t)ctx->buf.u8[5]) << 40;
	case 5:
		b |= ((uint64_t)ctx->buf.u8[4]) << 32;
	case 4:
		b |= ((uint64_t)ctx->buf.u8[3]) << 24;
	case 3:
		b |= ((uint64_t)ctx->buf.u8[2]) << 16;
	case 2:
		b |= ((uint64_t)ctx->buf.u8[1]) << 8;
	case 1:
		b |= ((uint64_t)ctx->buf.u8[0]);
		break;
	case 0:
		break;
	}

	ctx->v[3] ^= b;

	for (i = 0; i < cROUNDS; ++i)
		SIPROUND(ctx->v);

	ctx->v[0] ^= b;

	ctx->v[2] ^= 0xff;

	for (i = 0; i < dROUNDS; ++i)
		SIPROUND(ctx->v);

	b = ctx->v[0] ^ ctx->v[1] ^ ctx->v[2] ^ ctx->v[3];

	invalidate_siphash24(ctx);
	return cpu_to_le64(b);
}

uint64_t siphash24(const struct siphash_seed *seed, const void *p, size_t size)
{
	struct siphash24_ctx ctx;

	siphash24_init(&ctx, seed);
	siphash24_update(&ctx, p, size);
	return siphash24_done(&ctx);
}
	
void siphash24_u8(struct siphash24_ctx *ctx, uint8_t v)
{
	siphash24_update(ctx, &v, sizeof(v));
}

void siphash24_u16(struct siphash24_ctx *ctx, uint16_t v)
{
	siphash24_update(ctx, &v, sizeof(v));
}

void siphash24_u32(struct siphash24_ctx *ctx, uint32_t v)
{
	siphash24_update(ctx, &v, sizeof(v));
}

void siphash24_u64(struct siphash24_ctx *ctx, uint64_t v)
{
	siphash24_update(ctx, &v, sizeof(v));
}

/* Add as little-endian */
void siphash24_le16(struct siphash24_ctx *ctx, uint16_t v)
{
	leint16_t lev = cpu_to_le16(v);
	siphash24_update(ctx, &lev, sizeof(lev));
}
	
void siphash24_le32(struct siphash24_ctx *ctx, uint32_t v)
{
	leint32_t lev = cpu_to_le32(v);
	siphash24_update(ctx, &lev, sizeof(lev));
}
	
void siphash24_le64(struct siphash24_ctx *ctx, uint64_t v)
{
	leint64_t lev = cpu_to_le64(v);
	siphash24_update(ctx, &lev, sizeof(lev));
}

/* Add as big-endian */
void siphash24_be16(struct siphash24_ctx *ctx, uint16_t v)
{
	beint16_t bev = cpu_to_be16(v);
	siphash24_update(ctx, &bev, sizeof(bev));
}
	
void siphash24_be32(struct siphash24_ctx *ctx, uint32_t v)
{
	beint32_t bev = cpu_to_be32(v);
	siphash24_update(ctx, &bev, sizeof(bev));
}
	
void siphash24_be64(struct siphash24_ctx *ctx, uint64_t v)
{
	beint64_t bev = cpu_to_be64(v);
	siphash24_update(ctx, &bev, sizeof(bev));
}
