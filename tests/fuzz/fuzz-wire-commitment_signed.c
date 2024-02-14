#include "config.h"
#include <assert.h>
#include <ccan/mem/mem.h>
#include <stdint.h>
#include <tests/fuzz/libfuzz.h>
#include <tests/fuzz/wire.h>
#include <wire/peer_wire.h>

struct commitment_signed {
	struct channel_id channel_id;
	secp256k1_ecdsa_signature signature;
	secp256k1_ecdsa_signature *htlc_signature;
	struct tlv_commitment_signed_tlvs *tlvs;
};

static void *encode(const tal_t *ctx, const struct commitment_signed *s)
{
	return towire_commitment_signed(ctx, &s->channel_id, &s->signature,
					s->htlc_signature, s->tlvs);
}

static struct commitment_signed *decode(const tal_t *ctx, const void *p)
{
	struct commitment_signed *s = tal(ctx, struct commitment_signed);

	if (fromwire_commitment_signed(s, p, &s->channel_id, &s->signature,
				       &s->htlc_signature, &s->tlvs))
		return s;
	return tal_free(s);
}

static bool equal(struct commitment_signed *x, struct commitment_signed *y)
{
	size_t upto_htlc_signature =
	    (uintptr_t)&x->htlc_signature - (uintptr_t)x;
	if (memcmp(x, y, upto_htlc_signature) != 0)
		return false;

	if (!tal_arr_eq(x->htlc_signature, y->htlc_signature))
		return false;

	assert(x->tlvs && y->tlvs);
	return tal_arr_eq(x->tlvs->splice_info, y->tlvs->splice_info);
}

void run(const u8 *data, size_t size)
{
	test_decode_encode(data, size, WIRE_COMMITMENT_SIGNED,
			   struct commitment_signed);
}
