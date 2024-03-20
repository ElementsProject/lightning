#include "config.h"
#include <tests/fuzz/libfuzz.h>
#include <tests/fuzz/wire.h>
#include <wire/peer_wire.h>

struct announcement_signatures {
	struct channel_id channel_id;
	struct short_channel_id short_channel_id;
	secp256k1_ecdsa_signature node_signature;
	secp256k1_ecdsa_signature bitcoin_signature;
};

static void *encode(const tal_t *ctx, const struct announcement_signatures *s)
{
	return towire_announcement_signatures(
	    ctx, &s->channel_id, s->short_channel_id, &s->node_signature,
	    &s->bitcoin_signature);
}

static struct announcement_signatures *decode(const tal_t *ctx, const void *p)
{
	struct announcement_signatures *s =
	    tal(ctx, struct announcement_signatures);

	if (fromwire_announcement_signatures(
		p, &s->channel_id, &s->short_channel_id, &s->node_signature,
		&s->bitcoin_signature))
		return s;
	return tal_free(s);
}

static bool equal(const struct announcement_signatures *x,
		  const struct announcement_signatures *y)
{
	return memcmp(x, y, sizeof(*x)) == 0;
}

void run(const u8 *data, size_t size)
{
	test_decode_encode(data, size, WIRE_ANNOUNCEMENT_SIGNATURES,
			   struct announcement_signatures);
}
