#include "config.h"
#include <ccan/mem/mem.h>
#include <stdint.h>
#include <tests/fuzz/libfuzz.h>
#include <tests/fuzz/wire.h>
#include <wire/peer_wire.h>

struct update_fail_htlc {
	struct channel_id channel_id;
	u64 id;
	u8 *reason;
};

static void *encode(const tal_t *ctx, const struct update_fail_htlc *s)
{
	return towire_update_fail_htlc(ctx, &s->channel_id, s->id, s->reason);
}

static struct update_fail_htlc *decode(const tal_t *ctx, const void *p)
{
	struct update_fail_htlc *s = tal(ctx, struct update_fail_htlc);

	if (fromwire_update_fail_htlc(s, p, &s->channel_id, &s->id, &s->reason))
		return s;
	return tal_free(s);
}

static bool equal(const struct update_fail_htlc *x,
		  const struct update_fail_htlc *y)
{
	size_t upto_reason = (uintptr_t)&x->reason - (uintptr_t)x;
	if (memcmp(x, y, upto_reason) != 0)
		return false;

	return tal_arr_eq(x->reason, y->reason);
}

void run(const u8 *data, size_t size)
{
	test_decode_encode(data, size, WIRE_UPDATE_FAIL_HTLC,
			   struct update_fail_htlc);
}
