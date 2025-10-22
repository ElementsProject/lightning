#include "config.h"
#include <tests/fuzz/libfuzz.h>
#include <tests/fuzz/wire.h>
#include <wire/peer_wire.h>

struct fuzzsplice {
	struct channel_id channel_id;
	s64 relative_satoshis;
	u32 funding_feerate_perkw;
	u32 locktime;
	struct pubkey funding_pubkey;
};

static void *encode(const tal_t *ctx, const struct fuzzsplice *s)
{
	return towire_splice(ctx, &s->channel_id,
			     s->relative_satoshis, s->funding_feerate_perkw,
			     s->locktime, &s->funding_pubkey);
}

static struct fuzzsplice *decode(const tal_t *ctx, const void *p)
{
	struct fuzzsplice *s = tal(ctx, struct fuzzsplice);

	if (fromwire_splice(p, &s->channel_id,
			    &s->relative_satoshis, &s->funding_feerate_perkw,
			    &s->locktime, &s->funding_pubkey))
		return s;
	return tal_free(s);
}

static bool equal(const struct fuzzsplice *x, const struct fuzzsplice *y)
{
	return memcmp(x, y, sizeof(*x)) == 0;
}

void run(const u8 *data, size_t size)
{
	test_decode_encode(data, size, WIRE_SPLICE, struct fuzzsplice);
}
