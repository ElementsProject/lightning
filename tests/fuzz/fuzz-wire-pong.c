#include "config.h"
#include <ccan/mem/mem.h>
#include <tests/fuzz/libfuzz.h>
#include <tests/fuzz/wire.h>
#include <wire/peer_wire.h>

struct pong {
	u8 *ignored;
};

static void *encode(const tal_t *ctx, const struct pong *s)
{
	return towire_pong(ctx, s->ignored);
}

static struct pong *decode(const tal_t *ctx, const void *p)
{
	struct pong *s = tal(ctx, struct pong);

	if (fromwire_pong(s, p, &s->ignored))
		return s;
	return tal_free(s);
}

static bool equal(const struct pong *x, const struct pong *y)
{
	return tal_arr_eq(x->ignored, y->ignored);
}

void run(const u8 *data, size_t size)
{
	test_decode_encode(data, size, WIRE_PONG, struct pong);
}
