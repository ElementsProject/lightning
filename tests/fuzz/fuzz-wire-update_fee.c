#include "config.h"
#include <common/channel_id.h>
#include <tests/fuzz/libfuzz.h>
#include <tests/fuzz/wire.h>
#include <wire/peer_wire.h>

struct update_fee {
	struct channel_id channel_id;
	u32 feerate_per_kw;
};

static void *encode(const tal_t *ctx, const struct update_fee *s)
{
	return towire_update_fee(ctx, &s->channel_id, s->feerate_per_kw);
}

static struct update_fee *decode(const tal_t *ctx, const void *p)
{
	struct update_fee *s = tal(ctx, struct update_fee);

	if (fromwire_update_fee(p, &s->channel_id, &s->feerate_per_kw))
		return s;
	return tal_free(s);
}

static bool equal(const struct update_fee *x, const struct update_fee *y)
{
	if (!channel_id_eq(&x->channel_id, &y->channel_id))
		return false;
	return x->feerate_per_kw == y->feerate_per_kw;
}

void run(const u8 *data, size_t size)
{
	test_decode_encode(data, size, WIRE_UPDATE_FEE, struct update_fee);
}
