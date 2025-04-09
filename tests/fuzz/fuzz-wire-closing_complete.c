#include "config.h"
#include <assert.h>
#include <ccan/mem/mem.h>
#include <tests/fuzz/libfuzz.h>
#include <tests/fuzz/wire.h>
#include <wire/peer_wire.h>

struct closing_complete {
	struct channel_id channel_id;
	u32 locktime;
	struct amount_sat fee_satoshis;
	u8 *closer_scriptpubkey, *closee_scriptpubkey;
	struct tlv_closing_tlvs *tlvs;
};

static void *encode(const tal_t *ctx, const struct closing_complete *s)
{
	return towire_closing_complete(ctx, &s->channel_id, s->closer_scriptpubkey,
					s->closee_scriptpubkey, s->fee_satoshis, s->locktime, s->tlvs);
}

static struct closing_complete *decode(const tal_t *ctx, const void *p)
{
	struct closing_complete *s = tal(ctx, struct closing_complete);

	if (fromwire_closing_complete(s, p, &s->channel_id, &s->closer_scriptpubkey,
					&s->closee_scriptpubkey, &s->fee_satoshis, &s->locktime, &s->tlvs))
		return s;
	return tal_free(s);
}

static bool equal(const struct closing_complete *x,
		  const struct closing_complete *y)
{
	size_t upto_closer_scriptpubkey = (uintptr_t)&x->closer_scriptpubkey - (uintptr_t)x;
	if (memcmp(x, y, upto_closer_scriptpubkey) != 0)
		return false;

	assert(tal_arr_eq(x->closer_scriptpubkey, y->closer_scriptpubkey));
	assert(tal_arr_eq(x->closee_scriptpubkey, y->closee_scriptpubkey));

	assert(x->tlvs && y->tlvs);
	return tal_arr_eq(x->tlvs->closer_and_closee_outputs, y->tlvs->closer_and_closee_outputs);
}

void run(const u8 *data, size_t size)
{
	test_decode_encode(data, size, WIRE_CLOSING_COMPLETE,
			   struct closing_complete);
}
