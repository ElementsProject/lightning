#include "config.h"
#include <assert.h>
#include <ccan/mem/mem.h>
#include <stdint.h>
#include <tests/fuzz/libfuzz.h>
#include <tests/fuzz/wire.h>
#include <wire/peer_wire.h>

struct reply_channel_range {
	struct bitcoin_blkid chain_hash;
	u32 first_blocknum;
	u32 number_of_blocks;
	u8 sync_complete;
	u8 *encoded_short_ids;
	struct tlv_reply_channel_range_tlvs *tlvs;
};

static void *encode(const tal_t *ctx, const struct reply_channel_range *s)
{
	return towire_reply_channel_range(
	    ctx, &s->chain_hash, s->first_blocknum, s->number_of_blocks,
	    s->sync_complete, s->encoded_short_ids, s->tlvs);
}

static struct reply_channel_range *decode(const tal_t *ctx, const void *p)
{
	struct reply_channel_range *s = tal(ctx, struct reply_channel_range);

	if (fromwire_reply_channel_range(
		s, p, &s->chain_hash, &s->first_blocknum, &s->number_of_blocks,
		&s->sync_complete, &s->encoded_short_ids, &s->tlvs))
		return s;
	return tal_free(s);
}

static bool timestamps_tlv_equal(
    const struct tlv_reply_channel_range_tlvs_timestamps_tlv *x,
    const struct tlv_reply_channel_range_tlvs_timestamps_tlv *y)
{
	if (!x && !y)
		return true;
	if (!x || !y)
		return false;
	if (x->encoding_type != y->encoding_type)
		return false;
	return tal_arr_eq(x->encoded_timestamps, y->encoded_timestamps);
}

static bool equal(const struct reply_channel_range *x,
		  const struct reply_channel_range *y)
{
	size_t upto_sync_complete = (uintptr_t)&x->sync_complete - (uintptr_t)x;
	if (memcmp(x, y, upto_sync_complete) != 0)
		return false;
	if (x->sync_complete != y->sync_complete)
		return false;

	if (!tal_arr_eq(x->encoded_short_ids,  y->encoded_short_ids))
		return false;

	assert(x->tlvs && y->tlvs);

	if (!timestamps_tlv_equal(x->tlvs->timestamps_tlv,
				  y->tlvs->timestamps_tlv))
		return false;

	return tal_arr_eq(x->tlvs->checksums_tlv, y->tlvs->checksums_tlv);
}

void run(const u8 *data, size_t size)
{
	test_decode_encode(data, size, WIRE_REPLY_CHANNEL_RANGE,
			   struct reply_channel_range);
}
