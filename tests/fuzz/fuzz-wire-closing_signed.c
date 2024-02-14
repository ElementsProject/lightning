#include "config.h"
#include <assert.h>
#include <ccan/mem/mem.h>
#include <stdint.h>
#include <tests/fuzz/libfuzz.h>
#include <tests/fuzz/wire.h>
#include <wire/peer_wire.h>

struct closing_signed {
	struct channel_id channel_id;
	struct amount_sat fee_satoshis;
	secp256k1_ecdsa_signature signature;
	struct tlv_closing_signed_tlvs *tlvs;
};

static void *encode(const tal_t *ctx, const struct closing_signed *s)
{
	return towire_closing_signed(ctx, &s->channel_id, s->fee_satoshis,
				     &s->signature, s->tlvs);
}

static struct closing_signed *decode(const tal_t *ctx, const void *p)
{
	struct closing_signed *s = tal(ctx, struct closing_signed);

	if (fromwire_closing_signed(s, p, &s->channel_id, &s->fee_satoshis,
				    &s->signature, &s->tlvs))
		return s;
	return tal_free(s);
}

static bool equal(const struct closing_signed *x,
		  const struct closing_signed *y)
{
	size_t upto_tlvs = (uintptr_t)&x->tlvs - (uintptr_t)x;
	if (memcmp(x, y, upto_tlvs) != 0)
		return false;

	assert(x->tlvs && y->tlvs);
	return tal_arr_eq(x->tlvs->fee_range, y->tlvs->fee_range);
}

void run(const u8 *data, size_t size)
{
	test_decode_encode(data, size, WIRE_CLOSING_SIGNED,
			   struct closing_signed);
}
