#include "config.h"
#include <assert.h>
#include <ccan/mem/mem.h>
#include <tests/fuzz/libfuzz.h>
#include <tests/fuzz/wire.h>
#include <wire/peer_wire.h>

struct query_channel_range {
	struct bitcoin_blkid chain_hash;
	u32 first_blocknum;
	u32 number_of_blocks;
	struct tlv_query_channel_range_tlvs *tlvs;
};

static void *encode(const tal_t *ctx, const struct query_channel_range *s)
{
	return towire_query_channel_range(ctx, &s->chain_hash,
					  s->first_blocknum,
					  s->number_of_blocks, s->tlvs);
}

static struct query_channel_range *decode(const tal_t *ctx, const void *p)
{
	struct query_channel_range *s = tal(ctx, struct query_channel_range);

	if (fromwire_query_channel_range(s, p, &s->chain_hash,
					 &s->first_blocknum,
					 &s->number_of_blocks, &s->tlvs))
		return s;
	return tal_free(s);
}

static bool equal(const struct query_channel_range *x,
		  const struct query_channel_range *y)
{
	size_t upto_tlvs = (uintptr_t)&x->tlvs - (uintptr_t)x;
	if (memcmp(x, y, upto_tlvs) != 0)
		return false;

	assert(x->tlvs && y->tlvs);
	return tal_arr_eq(x->tlvs->query_option, y->tlvs->query_option);
}

void run(const u8 *data, size_t size)
{
	test_decode_encode(data, size, WIRE_QUERY_CHANNEL_RANGE,
			   struct query_channel_range);
}
