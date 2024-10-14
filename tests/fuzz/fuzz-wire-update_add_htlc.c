#include "config.h"
#include <assert.h>
#include <ccan/mem/mem.h>
#include <stdint.h>
#include <tests/fuzz/libfuzz.h>
#include <tests/fuzz/wire.h>
#include <wire/peer_wire.h>

struct update_add_htlc {
	struct channel_id channel_id;
	u64 id;
	struct amount_msat amount_msat;
	struct sha256 payment_hash;
	u32 expiry;
	u8 onion_routing_packet[1366];
	struct tlv_update_add_htlc_tlvs *tlvs;
};

static void *encode(const tal_t *ctx, const struct update_add_htlc *s)
{
	return towire_update_add_htlc(
	    ctx, &s->channel_id, s->id, s->amount_msat, &s->payment_hash,
	    s->expiry, s->onion_routing_packet, s->tlvs);
}

static struct update_add_htlc *decode(const tal_t *ctx, const void *p)
{
	struct update_add_htlc *s = tal(ctx, struct update_add_htlc);

	if (fromwire_update_add_htlc(
		s, p, &s->channel_id, &s->id, &s->amount_msat, &s->payment_hash,
		&s->expiry, s->onion_routing_packet, &s->tlvs))
		return s;
	return tal_free(s);
}

static bool equal(const struct update_add_htlc *x,
		  const struct update_add_htlc *y)
{
	size_t upto_expiry = (uintptr_t)&x->expiry - (uintptr_t)x;
	if (memcmp(x, y, upto_expiry) != 0)
		return false;
	if (x->expiry != y->expiry)
		return false;
	if (memcmp(x->onion_routing_packet, y->onion_routing_packet,
		   sizeof(x->onion_routing_packet)) != 0)
		return false;

	assert(x->tlvs && y->tlvs);
	return tal_arr_eq(x->tlvs->blinded_path, y->tlvs->blinded_path);
}

void run(const u8 *data, size_t size)
{
	test_decode_encode(data, size, WIRE_UPDATE_ADD_HTLC,
			   struct update_add_htlc);
}
