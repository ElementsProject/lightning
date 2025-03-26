#include "config.h"
#include <tests/fuzz/libfuzz.h>
#include <tests/fuzz/wire.h>
#include <wire/peer_wire.h>

struct splice_locked {
	struct channel_id channel_id;
	struct bitcoin_txid txid;
};

static void *encode(const tal_t *ctx, const struct splice_locked *s)
{
	return towire_splice_locked(ctx, &s->channel_id, &s->txid);
}

static struct splice_locked *decode(const tal_t *ctx, const void *p)
{
	struct splice_locked *s = tal(ctx, struct splice_locked);

	if (fromwire_splice_locked(p, &s->channel_id, &s->txid))
		return s;
	return tal_free(s);
}

static bool equal(const struct splice_locked *x, const struct splice_locked *y)
{
	return memcmp(x, y, sizeof(*x)) == 0;
}

void run(const u8 *data, size_t size)
{
	test_decode_encode(data, size, WIRE_SPLICE_LOCKED,
			   struct splice_locked);
}
