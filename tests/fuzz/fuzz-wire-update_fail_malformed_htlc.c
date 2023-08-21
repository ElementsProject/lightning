#include "config.h"
#include <stdint.h>
#include <tests/fuzz/libfuzz.h>
#include <tests/fuzz/wire.h>
#include <wire/peer_wire.h>

struct update_fail_malformed_htlc {
	struct channel_id channel_id;
	u64 id;
	struct sha256 sha256_of_onion;
	u16 failure_code;
};

static void *encode(const tal_t *ctx,
		    const struct update_fail_malformed_htlc *s)
{
	return towire_update_fail_malformed_htlc(
	    ctx, &s->channel_id, s->id, &s->sha256_of_onion, s->failure_code);
}

static struct update_fail_malformed_htlc *decode(const tal_t *ctx,
						 const void *p)
{
	struct update_fail_malformed_htlc *s =
	    tal(ctx, struct update_fail_malformed_htlc);

	if (fromwire_update_fail_malformed_htlc(p, &s->channel_id, &s->id,
						&s->sha256_of_onion,
						&s->failure_code))
		return s;
	return tal_free(s);
}

static bool equal(const struct update_fail_malformed_htlc *x,
		  const struct update_fail_malformed_htlc *y)
{
	size_t upto_failure_code = (uintptr_t)&x->failure_code - (uintptr_t)x;
	if (memcmp(x, y, upto_failure_code) != 0)
		return false;
	return x->failure_code == y->failure_code;
}

void run(const u8 *data, size_t size)
{
	test_decode_encode(data, size, WIRE_UPDATE_FAIL_MALFORMED_HTLC,
			   struct update_fail_malformed_htlc);
}
