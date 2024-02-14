#include "config.h"
#include <assert.h>
#include <ccan/mem/mem.h>
#include <tests/fuzz/libfuzz.h>
#include <tests/fuzz/wire.h>
#include <wire/peer_wire.h>

struct init {
	u8 *globalfeatures;
	u8 *features;
	struct tlv_init_tlvs *tlvs;
};

static void *encode(const tal_t *ctx, const struct init *s)
{
	return towire_init(ctx, s->globalfeatures, s->features, s->tlvs);
}

static struct init *decode(const tal_t *ctx, const void *p)
{
	struct init *s = tal(ctx, struct init);

	if (fromwire_init(s, p, &s->globalfeatures, &s->features, &s->tlvs))
		return s;
	return tal_free(s);
}

static bool equal(const struct init *x, const struct init *y)
{
	if (!tal_arr_eq(x->globalfeatures, y->globalfeatures))
		return false;
	if (!tal_arr_eq(x->features, y->features))
		return false;

	assert(x->tlvs && y->tlvs);

	if (!tal_arr_eq(x->tlvs->networks, y->tlvs->networks))
		return false;

	return tal_arr_eq(x->tlvs->remote_addr, y->tlvs->remote_addr);
}

void run(const u8 *data, size_t size)
{
	test_decode_encode(data, size, WIRE_INIT, struct init);
}
