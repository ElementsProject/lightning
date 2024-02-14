#include "config.h"
#include <ccan/mem/mem.h>
#include <stdint.h>
#include <tests/fuzz/libfuzz.h>
#include <tests/fuzz/wire.h>
#include <wire/peer_wire.h>

struct tx_add_output {
	struct channel_id channel_id;
	u64 serial_id;
	u64 sats;
	u8 *script;
};

static void *encode(const tal_t *ctx, const struct tx_add_output *s)
{
	return towire_tx_add_output(ctx, &s->channel_id, s->serial_id, s->sats,
				    s->script);
}

static struct tx_add_output *decode(const tal_t *ctx, const void *p)
{
	struct tx_add_output *s = tal(ctx, struct tx_add_output);

	if (fromwire_tx_add_output(s, p, &s->channel_id, &s->serial_id,
				   &s->sats, &s->script))
		return s;
	return tal_free(s);
}

static bool equal(const struct tx_add_output *x, const struct tx_add_output *y)
{
	size_t upto_script = (uintptr_t)&x->script - (uintptr_t)x;
	if (memcmp(x, y, upto_script) != 0)
		return false;

	return tal_arr_eq(x->script, y->script);
}

void run(const u8 *data, size_t size)
{
	test_decode_encode(data, size, WIRE_TX_ADD_OUTPUT,
			   struct tx_add_output);
}
