#include "config.h"
#include <ccan/mem/mem.h>
#include <tests/fuzz/libfuzz.h>
#include <tests/fuzz/wire.h>
#include <wire/peer_wire.h>

struct ping {
	u16 num_pong_bytes;
	u8 *ignored;
};

static void *encode(const tal_t *ctx, const struct ping *s)
{
	return towire_ping(ctx, s->num_pong_bytes, s->ignored);
}

static struct ping *decode(const tal_t *ctx, const void *p)
{
	struct ping *s = tal(ctx, struct ping);

	if (fromwire_ping(s, p, &s->num_pong_bytes, &s->ignored))
		return s;
	return tal_free(s);
}

static bool equal(const struct ping *x, const struct ping *y)
{
	if (x->num_pong_bytes != y->num_pong_bytes)
		return false;
	return tal_arr_eq(x->ignored, y->ignored);
}

void run(const u8 *data, size_t size)
{
	test_decode_encode(data, size, WIRE_PING, struct ping);
}
