#include "config.h"
#include <tests/fuzz/libfuzz.h>
#include <tests/fuzz/wire.h>
#include <wire/peer_wire.h>

struct revoke_and_ack {
	struct channel_id channel_id;
	struct secret per_commitment_secret;
	struct pubkey next_per_commitment_point;
};

static void *encode(const tal_t *ctx, const struct revoke_and_ack *s)
{
	return towire_revoke_and_ack(ctx, &s->channel_id,
				     &s->per_commitment_secret,
				     &s->next_per_commitment_point);
}

static struct revoke_and_ack *decode(const tal_t *ctx, const void *p)
{
	struct revoke_and_ack *s = tal(ctx, struct revoke_and_ack);

	if (fromwire_revoke_and_ack(p, &s->channel_id,
				    &s->per_commitment_secret,
				    &s->next_per_commitment_point))
		return s;
	return tal_free(s);
}

static bool equal(const struct revoke_and_ack *x,
		  const struct revoke_and_ack *y)
{
	return memcmp(x, y, sizeof(*x)) == 0;
}

void run(const u8 *data, size_t size)
{
	test_decode_encode(data, size, WIRE_REVOKE_AND_ACK,
			   struct revoke_and_ack);
}
