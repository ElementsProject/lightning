#include "config.h"
#include <ccan/mem/mem.h>
#include <common/channel_id.h>
#include <tests/fuzz/libfuzz.h>
#include <tests/fuzz/wire.h>
#include <wire/peer_wire.h>

struct tx_abort {
	struct channel_id channel_id;
	u8 *data;
};

static void *encode(const tal_t *ctx, const struct tx_abort *s)
{
	return towire_tx_abort(ctx, &s->channel_id, s->data);
}

static struct tx_abort *decode(const tal_t *ctx, const void *p)
{
	struct tx_abort *s = tal(ctx, struct tx_abort);

	if (fromwire_tx_abort(s, p, &s->channel_id, &s->data))
		return s;
	return tal_free(s);
}

static bool equal(const struct tx_abort *x, const struct tx_abort *y)
{
	if (!channel_id_eq(&x->channel_id, &y->channel_id))
		return false;
	return tal_arr_eq(x->data, y->data);
}

void run(const u8 *data, size_t size)
{
	test_decode_encode(data, size, WIRE_TX_ABORT, struct tx_abort);
}
