#include "config.h"
#include <ccan/mem/mem.h>
#include <tests/fuzz/libfuzz.h>
#include <tests/fuzz/wire.h>
#include <wire/peer_wire.h>

struct your_peer_storage {
	u8 *blob;
};

static void *encode(const tal_t *ctx, const struct your_peer_storage *s)
{
	return towire_your_peer_storage(ctx, s->blob);
}

static struct your_peer_storage *decode(const tal_t *ctx, const void *p)
{
	struct your_peer_storage *s = tal(ctx, struct your_peer_storage);

	if (fromwire_your_peer_storage(s, p, &s->blob))
		return s;
	return tal_free(s);
}

static bool equal(const struct your_peer_storage *x,
		  const struct your_peer_storage *y)
{
	return tal_arr_eq(x->blob, y->blob);
}

void run(const u8 *data, size_t size)
{
	test_decode_encode(data, size, WIRE_YOUR_PEER_STORAGE,
			   struct your_peer_storage);
}
