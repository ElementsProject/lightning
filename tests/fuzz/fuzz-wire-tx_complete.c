#include "config.h"
#include <tests/fuzz/libfuzz.h>
#include <tests/fuzz/wire.h>
#include <wire/peer_wire.h>

struct tx_complete {
	struct channel_id channel_id;
};

static void *encode(const tal_t *ctx, const struct tx_complete *s)
{
	return towire_tx_complete(ctx, &s->channel_id);
}

static struct tx_complete *decode(const tal_t *ctx, const void *p)
{
	struct tx_complete *s = tal(ctx, struct tx_complete);

	if (fromwire_tx_complete(p, &s->channel_id))
		return s;
	return tal_free(s);
}

static bool equal(const struct tx_complete *x, const struct tx_complete *y)
{
	return memcmp(x, y, sizeof(*x)) == 0;
}

void run(const u8 *data, size_t size)
{
	test_decode_encode(data, size, WIRE_TX_COMPLETE, struct tx_complete);
}
