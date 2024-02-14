#include "config.h"
#include <assert.h>
#include <ccan/mem/mem.h>
#include <stdint.h>
#include <tests/fuzz/libfuzz.h>
#include <tests/fuzz/wire.h>
#include <wire/peer_wire.h>

struct tx_signatures {
	struct channel_id channel_id;
	struct bitcoin_txid txid;
	struct witness **witnesses;
	struct tlv_txsigs_tlvs *tlvs;
};

static void *encode(const tal_t *ctx, const struct tx_signatures *s)
{
	return towire_tx_signatures(ctx, &s->channel_id, &s->txid,
				    (const struct witness **)s->witnesses,
				    s->tlvs);
}

static struct tx_signatures *decode(const tal_t *ctx, const void *p)
{
	struct tx_signatures *s = tal(ctx, struct tx_signatures);

	if (fromwire_tx_signatures(s, p, &s->channel_id, &s->txid,
				   &s->witnesses, &s->tlvs))
		return s;
	return tal_free(s);
}

static bool witnesses_equal(struct witness **x, struct witness **y)
{
	if (!x && !y)
		return true;
	if (!x || !y)
		return false;

	if (tal_count(x) != tal_count(y))
		return false;

	for (size_t i = 0; i < tal_count(x); ++i) {
		assert(x[i] && y[i]);
		if (!tal_arr_eq(x[i]->witness_data, y[i]->witness_data))
			return false;
	}
	return true;
}

static bool equal(const struct tx_signatures *x, const struct tx_signatures *y)
{
	size_t upto_witnesses = (uintptr_t)&x->witnesses - (uintptr_t)x;
	if (memcmp(x, y, upto_witnesses) != 0)
		return false;

	if (!witnesses_equal(x->witnesses, y->witnesses))
		return false;

	assert(x->tlvs && y->tlvs);
	return tal_arr_eq(x->tlvs->funding_outpoint_sig,
			  y->tlvs->funding_outpoint_sig);
}

void run(const u8 *data, size_t size)
{
	test_decode_encode(data, size, WIRE_TX_SIGNATURES,
			   struct tx_signatures);
}
