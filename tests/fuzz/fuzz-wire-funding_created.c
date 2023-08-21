#include "config.h"
#include <stdint.h>
#include <tests/fuzz/libfuzz.h>
#include <tests/fuzz/wire.h>
#include <wire/peer_wire.h>

struct funding_created {
	struct channel_id temporary_channel_id;
	struct bitcoin_txid funding_txid;
	secp256k1_ecdsa_signature signature;
	u16 funding_output_index;
};

static void *encode(const tal_t *ctx, const struct funding_created *s)
{
	return towire_funding_created(ctx, &s->temporary_channel_id,
				      &s->funding_txid, s->funding_output_index,
				      &s->signature);
}

static struct funding_created *decode(const tal_t *ctx, const void *p)
{
	struct funding_created *s = tal(ctx, struct funding_created);

	if (fromwire_funding_created(p, &s->temporary_channel_id,
				     &s->funding_txid, &s->funding_output_index,
				     &s->signature))
		return s;
	return tal_free(s);
}

static bool equal(const struct funding_created *x,
		  const struct funding_created *y)
{
	size_t upto_funding_output_index =
	    (uintptr_t)&x->funding_output_index - (uintptr_t)x;
	if (memcmp(x, y, upto_funding_output_index) != 0)
		return false;

	return x->funding_output_index == y->funding_output_index;
}

void run(const u8 *data, size_t size)
{
	test_decode_encode(data, size, WIRE_FUNDING_CREATED,
			   struct funding_created);
}
