#include "config.h"
#include <tests/fuzz/libfuzz.h>
#include <tests/fuzz/wire.h>
#include <wire/peer_wire.h>

struct splice_ack {
	struct channel_id channel_id;
	s64 relative_satoshis;
	struct pubkey funding_pubkey;
};

static void *encode(const tal_t *ctx, const struct splice_ack *s)
{
	return towire_splice_ack(ctx, &s->channel_id,
				 s->relative_satoshis, &s->funding_pubkey);
}

static struct splice_ack *decode(const tal_t *ctx, const void *p)
{
	struct splice_ack *s = tal(ctx, struct splice_ack);

	if (fromwire_splice_ack(p, &s->channel_id,
				&s->relative_satoshis, &s->funding_pubkey))
		return s;
	return tal_free(s);
}

static bool equal(const struct splice_ack *x, const struct splice_ack *y)
{
	return memcmp(x, y, sizeof(*x)) == 0;
}

void run(const u8 *data, size_t size)
{
	test_decode_encode(data, size, WIRE_SPLICE_ACK, struct splice_ack);
}
