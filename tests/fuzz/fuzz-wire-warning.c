#include "config.h"
#include <ccan/mem/mem.h>
#include <common/channel_id.h>
#include <tests/fuzz/libfuzz.h>
#include <tests/fuzz/wire.h>
#include <wire/peer_wire.h>

struct warning {
	struct channel_id channel_id;
	u8 *data;
};

static void *encode(const tal_t *ctx, const struct warning *s)
{
	return towire_warning(ctx, &s->channel_id, s->data);
}

static struct warning *decode(const tal_t *ctx, const void *p)
{
	struct warning *s = tal(ctx, struct warning);

	if (fromwire_warning(s, p, &s->channel_id, &s->data))
		return s;
	return tal_free(s);
}

static bool equal(const struct warning *x, const struct warning *y)
{
	if (!channel_id_eq(&x->channel_id, &y->channel_id))
		return false;
	return tal_arr_eq(x->data, y->data);
}

void run(const u8 *data, size_t size)
{
	test_decode_encode(data, size, WIRE_WARNING, struct warning);
}
