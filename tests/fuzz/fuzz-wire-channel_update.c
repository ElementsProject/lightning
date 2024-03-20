#include "config.h"
#include <tests/fuzz/libfuzz.h>
#include <tests/fuzz/wire.h>
#include <wire/peer_wire.h>

struct channel_update {
	secp256k1_ecdsa_signature signature;
	struct bitcoin_blkid chain_hash;
	struct short_channel_id short_channel_id;
	u32 timestamp;
	u8 message_flags;
	u8 channel_flags;
	u16 cltv_expiry_delta;
	struct amount_msat htlc_minimum_msat;
	u32 fee_base_msat;
	u32 fee_proportional_millionths;
	struct amount_msat htlc_maximum_msat;
};

static void *encode(const tal_t *ctx, const struct channel_update *s)
{
	return towire_channel_update(
	    ctx, &s->signature, &s->chain_hash, s->short_channel_id,
	    s->timestamp, s->message_flags, s->channel_flags,
	    s->cltv_expiry_delta, s->htlc_minimum_msat, s->fee_base_msat,
	    s->fee_proportional_millionths, s->htlc_maximum_msat);
}

static struct channel_update *decode(const tal_t *ctx, const void *p)
{
	struct channel_update *s = tal(ctx, struct channel_update);

	if (fromwire_channel_update(
		p, &s->signature, &s->chain_hash, &s->short_channel_id,
		&s->timestamp, &s->message_flags, &s->channel_flags,
		&s->cltv_expiry_delta, &s->htlc_minimum_msat, &s->fee_base_msat,
		&s->fee_proportional_millionths, &s->htlc_maximum_msat))
		return s;
	return tal_free(s);
}

static bool equal(const struct channel_update *x,
		  const struct channel_update *y)
{
	return memcmp(x, y, sizeof(*x)) == 0;
}

void run(const u8 *data, size_t size)
{
	test_decode_encode(data, size, WIRE_CHANNEL_UPDATE,
			   struct channel_update);
}
