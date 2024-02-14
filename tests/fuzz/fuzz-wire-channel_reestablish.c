#include "config.h"
#include <assert.h>
#include <ccan/mem/mem.h>
#include <stdint.h>
#include <tests/fuzz/libfuzz.h>
#include <tests/fuzz/wire.h>
#include <wire/peer_wire.h>

struct channel_reestablish {
	struct channel_id channel_id;
	u64 next_commitment_number;
	u64 next_revocation_number;
	struct secret your_last_per_commitment_secret;
	struct pubkey my_current_per_commitment_point;
	struct tlv_channel_reestablish_tlvs *tlvs;
};

static void *encode(const tal_t *ctx, const struct channel_reestablish *s)
{
	return towire_channel_reestablish(
	    ctx, &s->channel_id, s->next_commitment_number,
	    s->next_revocation_number, &s->your_last_per_commitment_secret,
	    &s->my_current_per_commitment_point, s->tlvs);
}

static struct channel_reestablish *decode(const tal_t *ctx, const void *p)
{
	struct channel_reestablish *s = tal(ctx, struct channel_reestablish);

	if (fromwire_channel_reestablish(
		s, p, &s->channel_id, &s->next_commitment_number,
		&s->next_revocation_number, &s->your_last_per_commitment_secret,
		&s->my_current_per_commitment_point, &s->tlvs))
		return s;
	return tal_free(s);
}

static bool equal(const struct channel_reestablish *x,
		  const struct channel_reestablish *y)
{
	size_t upto_tlvs = (uintptr_t)&x->tlvs - (uintptr_t)x;
	if (memcmp(x, y, upto_tlvs) != 0)
		return false;

	assert(x->tlvs && y->tlvs);

	if (!tal_arr_eq(x->tlvs->next_funding, y->tlvs->next_funding))
		return false;
	if (!tal_arr_eq(x->tlvs->next_to_send, y->tlvs->next_to_send))
		return false;
	if (!tal_arr_eq(x->tlvs->desired_channel_type, y->tlvs->desired_channel_type))
		return false;
	if (!tal_arr_eq(x->tlvs->current_channel_type, y->tlvs->current_channel_type))
		return false;
	return tal_arr_eq(x->tlvs->upgradable_channel_type,
			  y->tlvs->upgradable_channel_type);
}

void run(const u8 *data, size_t size)
{
	test_decode_encode(data, size, WIRE_CHANNEL_REESTABLISH,
			   struct channel_reestablish);
}
