#include "config.h"
#include <tests/fuzz/libfuzz.h>
#include <tests/fuzz/wire.h>
#include <wire/peer_wire.h>

struct funding_signed {
	struct channel_id channel_id;
	secp256k1_ecdsa_signature signature;
};

static void *encode(const tal_t *ctx, const struct funding_signed *s)
{
	return towire_funding_signed(ctx, &s->channel_id, &s->signature);
}

static struct funding_signed *decode(const tal_t *ctx, const void *p)
{
	struct funding_signed *s = tal(ctx, struct funding_signed);

	if (fromwire_funding_signed(p, &s->channel_id, &s->signature))
		return s;
	return tal_free(s);
}

static bool equal(const struct funding_signed *x,
		  const struct funding_signed *y)
{
	return memcmp(x, y, sizeof(*x)) == 0;
}

void run(const u8 *data, size_t size)
{
	test_decode_encode(data, size, WIRE_FUNDING_SIGNED,
			   struct funding_signed);
}
