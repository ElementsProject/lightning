#include "config.h"
#include <tests/fuzz/libfuzz.h>
#include <tests/fuzz/wire.h>
#include <wire/peer_wire.h>

struct reply_short_channel_ids_end {
	struct bitcoin_blkid chain_hash;
	u8 full_information;
};

static void *encode(const tal_t *ctx,
		    const struct reply_short_channel_ids_end *s)
{
	return towire_reply_short_channel_ids_end(ctx, &s->chain_hash,
						  s->full_information);
}

static struct reply_short_channel_ids_end *decode(const tal_t *ctx,
						  const void *p)
{
	struct reply_short_channel_ids_end *s =
	    tal(ctx, struct reply_short_channel_ids_end);

	if (fromwire_reply_short_channel_ids_end(p, &s->chain_hash,
						 &s->full_information))
		return s;
	return tal_free(s);
}

static bool equal(const struct reply_short_channel_ids_end *x,
		  const struct reply_short_channel_ids_end *y)
{
	if (memcmp(&x->chain_hash, &y->chain_hash, sizeof(x->chain_hash)) != 0)
		return false;
	return x->full_information == y->full_information;
}

void run(const u8 *data, size_t size)
{
	test_decode_encode(data, size, WIRE_REPLY_SHORT_CHANNEL_IDS_END,
			   struct reply_short_channel_ids_end);
}
