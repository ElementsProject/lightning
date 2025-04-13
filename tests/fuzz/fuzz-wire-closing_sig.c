#include "config.h"
#include <assert.h>
#include <ccan/mem/mem.h>
#include <tests/fuzz/libfuzz.h>
#include <tests/fuzz/wire.h>
#include <wire/peer_wire.h>

struct closing_sig {
	struct channel_id channel_id;
	u32 locktime;
	struct amount_sat fee_satoshis;
	u8 *closer_scriptpubkey, *closee_scriptpubkey;
	struct tlv_closing_tlvs *tlvs;
};

static void *encode(const tal_t *ctx, const struct closing_sig *s)
{
	return towire_closing_sig(ctx, &s->channel_id, s->closer_scriptpubkey,
					s->closee_scriptpubkey, s->fee_satoshis, s->locktime, s->tlvs);
}

static struct closing_sig *decode(const tal_t *ctx, const void *p)
{
	struct closing_sig *s = tal(ctx, struct closing_sig);

	if (fromwire_closing_sig(s, p, &s->channel_id, &s->closer_scriptpubkey,
					&s->closee_scriptpubkey, &s->fee_satoshis, &s->locktime, &s->tlvs))
		return s;
	return tal_free(s);
}

static bool equal(const struct closing_sig *x,
		  const struct closing_sig *y)
{
	assert(memcmp(&x->channel_id, &y->channel_id, sizeof(x->channel_id)) == 0);
	assert(x->locktime == y->locktime);
	assert(memcmp(&x->fee_satoshis, &y->fee_satoshis, sizeof(x->fee_satoshis)) == 0);

	assert(tal_arr_eq(x->closer_scriptpubkey, y->closer_scriptpubkey));
	assert(tal_arr_eq(x->closee_scriptpubkey, y->closee_scriptpubkey));

	assert(x->tlvs && y->tlvs);
	assert(tal_arr_eq(x->tlvs->closer_output_only, y->tlvs->closer_output_only));
	assert(tal_arr_eq(x->tlvs->closee_output_only, y->tlvs->closee_output_only));

	return tal_arr_eq(x->tlvs->closer_and_closee_outputs, y->tlvs->closer_and_closee_outputs);
}

void run(const u8 *data, size_t size)
{
	test_decode_encode(data, size, WIRE_CLOSING_SIG, struct closing_sig);
}
