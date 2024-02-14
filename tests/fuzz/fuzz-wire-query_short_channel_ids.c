#include "config.h"
#include <assert.h>
#include <ccan/mem/mem.h>
#include <tests/fuzz/libfuzz.h>
#include <tests/fuzz/wire.h>
#include <wire/peer_wire.h>

struct query_short_channel_ids {
	struct bitcoin_blkid chain_hash;
	u8 *encoded_short_ids;
	struct tlv_query_short_channel_ids_tlvs *tlvs;
};

static void *encode(const tal_t *ctx, const struct query_short_channel_ids *s)
{
	return towire_query_short_channel_ids(ctx, &s->chain_hash,
					      s->encoded_short_ids, s->tlvs);
}

static struct query_short_channel_ids *decode(const tal_t *ctx, const void *p)
{
	struct query_short_channel_ids *s =
	    tal(ctx, struct query_short_channel_ids);

	if (fromwire_query_short_channel_ids(s, p, &s->chain_hash,
					     &s->encoded_short_ids, &s->tlvs))
		return s;
	return tal_free(s);
}

static bool
query_flags_equal(const struct tlv_query_short_channel_ids_tlvs_query_flags *x,
		  const struct tlv_query_short_channel_ids_tlvs_query_flags *y)
{
	if (!x && !y)
		return true;
	if (!x || !y)
		return false;
	if (x->encoding_type != y->encoding_type)
		return false;
	return tal_arr_eq(x->encoded_query_flags, y->encoded_query_flags);
}

static bool equal(const struct query_short_channel_ids *x,
		  const struct query_short_channel_ids *y)
{
	if (memcmp(&x->chain_hash, &y->chain_hash, sizeof(x->chain_hash)) != 0)
		return false;

	if (!tal_arr_eq(x->encoded_short_ids, y->encoded_short_ids))
		return false;

	assert(x->tlvs && y->tlvs);
	return query_flags_equal(x->tlvs->query_flags, y->tlvs->query_flags);
}

void run(const u8 *data, size_t size)
{
	test_decode_encode(data, size, WIRE_QUERY_SHORT_CHANNEL_IDS,
			   struct query_short_channel_ids);
}
