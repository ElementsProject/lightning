#include "config.h"
#include <ccan/mem/mem.h>
#include <tests/fuzz/libfuzz.h>
#include <tests/fuzz/wire.h>
#include <wire/peer_wire.h>

struct peer_storage_retrieval {
	u8 *blob;
};

static void *encode(const tal_t *ctx, const struct peer_storage_retrieval *s)
{
	return towire_peer_storage_retrieval(ctx, s->blob);
}

static struct peer_storage_retrieval *decode(const tal_t *ctx, const void *p)
{
	struct peer_storage_retrieval *s = tal(ctx, struct peer_storage_retrieval);

	if (fromwire_peer_storage_retrieval(s, p, &s->blob))
		return s;
	return tal_free(s);
}

static bool equal(const struct peer_storage_retrieval *x,
		  const struct peer_storage_retrieval *y)
{
	return tal_arr_eq(x->blob, y->blob);
}

void run(const u8 *data, size_t size)
{
	test_decode_encode(data, size, WIRE_PEER_STORAGE_RETRIEVAL,
			   struct peer_storage_retrieval);
}
