#include "config.h"
#include <tests/fuzz/libfuzz.h>
#include <tests/fuzz/wire.h>
#include <wire/peer_wire.h>

struct tx_remove_output {
	struct channel_id channel_id;
	u64 serial_id;
};

static void *encode(const tal_t *ctx, const struct tx_remove_output *s)
{
	return towire_tx_remove_output(ctx, &s->channel_id, s->serial_id);
}

static struct tx_remove_output *decode(const tal_t *ctx, const void *p)
{
	struct tx_remove_output *s = tal(ctx, struct tx_remove_output);

	if (fromwire_tx_remove_output(p, &s->channel_id, &s->serial_id))
		return s;
	return tal_free(s);
}

static bool equal(const struct tx_remove_output *x,
		  const struct tx_remove_output *y)
{
	return memcmp(x, y, sizeof(*x)) == 0;
}

void run(const u8 *data, size_t size)
{
	test_decode_encode(data, size, WIRE_TX_REMOVE_OUTPUT,
			   struct tx_remove_output);
}
