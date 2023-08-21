#include "config.h"
#include <tests/fuzz/libfuzz.h>
#include <tests/fuzz/wire.h>
#include <wire/peer_wire.h>

struct update_fulfill_htlc {
	struct channel_id channel_id;
	u64 id;
	struct preimage payment_preimage;
};

static void *encode(const tal_t *ctx, const struct update_fulfill_htlc *s)
{
	return towire_update_fulfill_htlc(ctx, &s->channel_id, s->id,
					  &s->payment_preimage);
}

static struct update_fulfill_htlc *decode(const tal_t *ctx, const void *p)
{
	struct update_fulfill_htlc *s = tal(ctx, struct update_fulfill_htlc);

	if (fromwire_update_fulfill_htlc(p, &s->channel_id, &s->id,
					 &s->payment_preimage))
		return s;
	return tal_free(s);
}

static bool equal(const struct update_fulfill_htlc *x,
		  const struct update_fulfill_htlc *y)
{
	return memcmp(x, y, sizeof(*x)) == 0;
}

void run(const u8 *data, size_t size)
{
	test_decode_encode(data, size, WIRE_UPDATE_FULFILL_HTLC,
			   struct update_fulfill_htlc);
}
