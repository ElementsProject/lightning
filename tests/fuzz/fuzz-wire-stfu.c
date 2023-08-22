#include "config.h"
#include <common/channel_id.h>
#include <tests/fuzz/libfuzz.h>
#include <tests/fuzz/wire.h>
#include <wire/peer_wire.h>

struct stfu {
	struct channel_id channel_id;
	u8 initiator;
};

static void *encode(const tal_t *ctx, const struct stfu *s)
{
	return towire_stfu(ctx, &s->channel_id, s->initiator);
}

static struct stfu *decode(const tal_t *ctx, const void *p)
{
	struct stfu *s = tal(ctx, struct stfu);

	if (fromwire_stfu(p, &s->channel_id, &s->initiator))
		return s;
	return tal_free(s);
}

static bool equal(const struct stfu *x, const struct stfu *y)
{
	return channel_id_eq(&x->channel_id, &y->channel_id) &&
	       x->initiator == y->initiator;
}

void run(const u8 *data, size_t size)
{
	test_decode_encode(data, size, WIRE_STFU, struct stfu);
}
