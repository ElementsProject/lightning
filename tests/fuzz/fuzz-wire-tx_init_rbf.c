#include "config.h"
#include <assert.h>
#include <ccan/mem/mem.h>
#include <stdint.h>
#include <tests/fuzz/libfuzz.h>
#include <tests/fuzz/wire.h>
#include <wire/peer_wire.h>

struct tx_init_rbf {
	struct channel_id channel_id;
	u32 locktime;
	u32 feerate;
	struct tlv_tx_init_rbf_tlvs *tlvs;
};

static void *encode(const tal_t *ctx, const struct tx_init_rbf *s)
{
	return towire_tx_init_rbf(ctx, &s->channel_id, s->locktime, s->feerate,
				  s->tlvs);
}

static struct tx_init_rbf *decode(const tal_t *ctx, const void *p)
{
	struct tx_init_rbf *s = tal(ctx, struct tx_init_rbf);

	if (fromwire_tx_init_rbf(s, p, &s->channel_id, &s->locktime,
				 &s->feerate, &s->tlvs))
		return s;
	return tal_free(s);
}

static bool equal(const struct tx_init_rbf *x, const struct tx_init_rbf *y)
{
	size_t upto_tlvs = (uintptr_t)&x->tlvs - (uintptr_t)x;
	if (memcmp(x, y, upto_tlvs) != 0)
		return false;

	assert(x->tlvs && y->tlvs);
	if (!tal_arr_eq(x->tlvs->funding_output_contribution,
			y->tlvs->funding_output_contribution))
		return false;

	return !!x->tlvs->require_confirmed_inputs ==
	       !!y->tlvs->require_confirmed_inputs;
}

void run(const u8 *data, size_t size)
{
	test_decode_encode(data, size, WIRE_TX_INIT_RBF, struct tx_init_rbf);
}
