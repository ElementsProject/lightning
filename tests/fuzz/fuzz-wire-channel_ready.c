#include "config.h"
#include <assert.h>
#include <ccan/mem/mem.h>
#include <stdint.h>
#include <tests/fuzz/libfuzz.h>
#include <tests/fuzz/wire.h>
#include <wire/peer_wire.h>

struct channel_ready {
	struct channel_id channel_id;
	struct pubkey second_per_commitment_point;
	struct tlv_channel_ready_tlvs *tlvs;
};

static void *encode(const tal_t *ctx, const struct channel_ready *s)
{
	return towire_channel_ready(ctx, &s->channel_id,
				    &s->second_per_commitment_point, s->tlvs);
}

static struct channel_ready *decode(const tal_t *ctx, const void *p)
{
	struct channel_ready *s = tal(ctx, struct channel_ready);

	if (fromwire_channel_ready(s, p, &s->channel_id,
				   &s->second_per_commitment_point, &s->tlvs))
		return s;
	return tal_free(s);
}

static bool equal(const struct channel_ready *x, const struct channel_ready *y)
{
	size_t upto_tlvs = (uintptr_t)&x->tlvs - (uintptr_t)x;
	if (memcmp(x, y, upto_tlvs) != 0)
		return false;

	assert(x->tlvs && y->tlvs);
	return tal_arr_eq(x->tlvs->short_channel_id, y->tlvs->short_channel_id);
}

void run(const u8 *data, size_t size)
{
	test_decode_encode(data, size, WIRE_CHANNEL_READY,
			   struct channel_ready);
}
