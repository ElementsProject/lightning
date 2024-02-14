#include "config.h"
#include <assert.h>
#include <ccan/mem/mem.h>
#include <common/channel_id.h>
#include <tests/fuzz/libfuzz.h>
#include <tests/fuzz/wire.h>
#include <wire/peer_wire.h>

struct tx_ack_rbf {
	struct channel_id channel_id;
	struct tlv_tx_ack_rbf_tlvs *tlvs;
};

static void *encode(const tal_t *ctx, const struct tx_ack_rbf *s)
{
	return towire_tx_ack_rbf(ctx, &s->channel_id, s->tlvs);
}

static struct tx_ack_rbf *decode(const tal_t *ctx, const void *p)
{
	struct tx_ack_rbf *s = tal(ctx, struct tx_ack_rbf);

	if (fromwire_tx_ack_rbf(s, p, &s->channel_id, &s->tlvs))
		return s;
	return tal_free(s);
}

static bool equal(const struct tx_ack_rbf *x, const struct tx_ack_rbf *y)
{
	if (!channel_id_eq(&x->channel_id, &y->channel_id))
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
	test_decode_encode(data, size, WIRE_TX_ACK_RBF, struct tx_ack_rbf);
}
