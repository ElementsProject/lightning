#include "config.h"
#include <ccan/mem/mem.h>
#include <common/channel_id.h>
#include <tests/fuzz/libfuzz.h>
#include <tests/fuzz/wire.h>
#include <wire/peer_wire.h>

struct error {
	struct channel_id channel_id;
	u8 *data;
};

static void *encode(const tal_t *ctx, const struct error *s)
{
	return towire_error(ctx, &s->channel_id, s->data);
}

static struct error *decode(const tal_t *ctx, const void *p)
{
	struct error *s = tal(ctx, struct error);

	if (fromwire_error(s, p, &s->channel_id, &s->data))
		return s;
	return tal_free(s);
}

static bool equal(const struct error *x, const struct error *y)
{
	if (!channel_id_eq(&x->channel_id, &y->channel_id))
		return false;
	return tal_arr_eq(x->data, y->data);
}

void run(const u8 *data, size_t size)
{
	test_decode_encode(data, size, WIRE_ERROR, struct error);
}
