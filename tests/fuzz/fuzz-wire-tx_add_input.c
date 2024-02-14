#include "config.h"
#include <ccan/mem/mem.h>
#include <stdint.h>
#include <tests/fuzz/libfuzz.h>
#include <tests/fuzz/wire.h>
#include <wire/peer_wire.h>

struct tx_add_input {
	struct channel_id channel_id;
	u64 serial_id;
	u32 prevtx_vout;
	u32 sequence;
	u8 *prevtx;
};

static void *encode(const tal_t *ctx, const struct tx_add_input *s)
{
	return towire_tx_add_input(ctx, &s->channel_id, s->serial_id, s->prevtx,
				   s->prevtx_vout, s->sequence);
}

static struct tx_add_input *decode(const tal_t *ctx, const void *p)
{
	struct tx_add_input *s = tal(ctx, struct tx_add_input);

	if (fromwire_tx_add_input(s, p, &s->channel_id, &s->serial_id,
				  &s->prevtx, &s->prevtx_vout, &s->sequence))
		return s;
	return tal_free(s);
}

static bool equal(const struct tx_add_input *x, const struct tx_add_input *y)
{
	size_t upto_prevtx = (uintptr_t)&x->prevtx - (uintptr_t)x;
	if (memcmp(x, y, upto_prevtx) != 0)
		return false;

	return tal_arr_eq(x->prevtx, y->prevtx);
}

void run(const u8 *data, size_t size)
{
	test_decode_encode(data, size, WIRE_TX_ADD_INPUT, struct tx_add_input);
}
