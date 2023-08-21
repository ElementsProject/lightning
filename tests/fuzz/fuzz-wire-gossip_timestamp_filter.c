#include "config.h"
#include <tests/fuzz/libfuzz.h>
#include <tests/fuzz/wire.h>
#include <wire/peer_wire.h>

struct gossip_timestamp_filter {
	struct bitcoin_blkid chain_hash;
	u32 first_timestamp;
	u32 timestamp_range;
};

static void *encode(const tal_t *ctx, const struct gossip_timestamp_filter *s)
{
	return towire_gossip_timestamp_filter(
	    ctx, &s->chain_hash, s->first_timestamp, s->timestamp_range);
}

static struct gossip_timestamp_filter *decode(const tal_t *ctx, const void *p)
{
	struct gossip_timestamp_filter *s =
	    tal(ctx, struct gossip_timestamp_filter);

	if (fromwire_gossip_timestamp_filter(
		p, &s->chain_hash, &s->first_timestamp, &s->timestamp_range))
		return s;
	return tal_free(s);
}

static bool equal(const struct gossip_timestamp_filter *x,
		  const struct gossip_timestamp_filter *y)
{
	return memcmp(x, y, sizeof(*x)) == 0;
}

void run(const u8 *data, size_t size)
{
	test_decode_encode(data, size, WIRE_GOSSIP_TIMESTAMP_FILTER,
			   struct gossip_timestamp_filter);
}
