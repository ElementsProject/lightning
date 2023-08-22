#include "config.h"
#include <common/channel_id.h>
#include <tests/fuzz/libfuzz.h>
#include <tests/fuzz/wire.h>
#include <wire/peer_wire.h>

struct update_blockheight {
	struct channel_id channel_id;
	u32 blockheight;
};

static void *encode(const tal_t *ctx, const struct update_blockheight *s)
{
	return towire_update_blockheight(ctx, &s->channel_id, s->blockheight);
}

static struct update_blockheight *decode(const tal_t *ctx, const void *p)
{
	struct update_blockheight *s = tal(ctx, struct update_blockheight);

	if (fromwire_update_blockheight(p, &s->channel_id, &s->blockheight))
		return s;
	return tal_free(s);
}

static bool equal(const struct update_blockheight *x,
		  const struct update_blockheight *y)
{
	return channel_id_eq(&x->channel_id, &y->channel_id) &&
	       x->blockheight == y->blockheight;
}

void run(const u8 *data, size_t size)
{
	test_decode_encode(data, size, WIRE_UPDATE_BLOCKHEIGHT,
			   struct update_blockheight);
}
