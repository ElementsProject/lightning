#include "config.h"
#include <assert.h>
#include <ccan/mem/mem.h>
#include <common/channel_id.h>
#include <tests/fuzz/libfuzz.h>
#include <tests/fuzz/wire.h>
#include <wire/peer_wire.h>

struct shutdown {
	struct channel_id channel_id;
	u8 *scriptpubkey;
	struct tlv_shutdown_tlvs *tlvs;
};

static void *encode(const tal_t *ctx, const struct shutdown *s)
{
	return towire_shutdown(ctx, &s->channel_id, s->scriptpubkey, s->tlvs);
}

static struct shutdown *decode(const tal_t *ctx, const void *p)
{
	struct shutdown *s = tal(ctx, struct shutdown);

	if (fromwire_shutdown(s, p, &s->channel_id, &s->scriptpubkey, &s->tlvs))
		return s;
	return tal_free(s);
}

static bool wrong_funding_equal(const struct tlv_shutdown_tlvs_wrong_funding *x,
				const struct tlv_shutdown_tlvs_wrong_funding *y)
{
	if (!x && !y)
		return true;
	if (!x || !y)
		return false;

	return bitcoin_txid_eq(&x->txid, &y->txid) && x->outnum == y->outnum;
}

static bool equal(const struct shutdown *x, const struct shutdown *y)
{
	if (!channel_id_eq(&x->channel_id, &y->channel_id))
		return false;
	if (!tal_arr_eq(x->scriptpubkey, y->scriptpubkey))
		return false;

	assert(x->tlvs && y->tlvs);
	return wrong_funding_equal(x->tlvs->wrong_funding,
				   y->tlvs->wrong_funding);
}

void run(const u8 *data, size_t size)
{
	test_decode_encode(data, size, WIRE_SHUTDOWN, struct shutdown);
}
