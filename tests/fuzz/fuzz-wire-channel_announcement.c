#include "config.h"
#include <ccan/mem/mem.h>
#include <common/node_id.h>
#include <stdint.h>
#include <tests/fuzz/libfuzz.h>
#include <tests/fuzz/wire.h>
#include <wire/peer_wire.h>

struct channel_announcement {
	secp256k1_ecdsa_signature node_signature_1;
	secp256k1_ecdsa_signature node_signature_2;
	secp256k1_ecdsa_signature bitcoin_signature_1;
	secp256k1_ecdsa_signature bitcoin_signature_2;
	struct bitcoin_blkid chain_hash;
	struct short_channel_id short_channel_id;
	struct pubkey bitcoin_key_1;
	struct pubkey bitcoin_key_2;
	struct node_id node_id_1;
	struct node_id node_id_2;
	u8 *features;
};

static void *encode(const tal_t *ctx, const struct channel_announcement *s)
{
	return towire_channel_announcement(
	    ctx, &s->node_signature_1, &s->node_signature_2,
	    &s->bitcoin_signature_1, &s->bitcoin_signature_2, s->features,
	    &s->chain_hash, s->short_channel_id, &s->node_id_1, &s->node_id_2,
	    &s->bitcoin_key_1, &s->bitcoin_key_2);
}

static struct channel_announcement *decode(const tal_t *ctx, const void *p)
{
	struct channel_announcement *s = tal(ctx, struct channel_announcement);
	if (fromwire_channel_announcement(
		s, p, &s->node_signature_1, &s->node_signature_2,
		&s->bitcoin_signature_1, &s->bitcoin_signature_2, &s->features,
		&s->chain_hash, &s->short_channel_id, &s->node_id_1,
		&s->node_id_2, &s->bitcoin_key_1, &s->bitcoin_key_2))
		return s;
	return tal_free(s);
}

static bool equal(const struct channel_announcement *x,
		  const struct channel_announcement *y)
{
	size_t upto_node_id_1 = (uintptr_t)&x->node_id_1 - (uintptr_t)x;
	if (memcmp(x, y, upto_node_id_1) != 0)
		return false;

	if (!node_id_eq(&x->node_id_1, &y->node_id_1))
		return false;
	if (!node_id_eq(&x->node_id_2, &y->node_id_2))
		return false;

	return tal_arr_eq(x->features, y->features);
}

void run(const u8 *data, size_t size)
{
	test_decode_encode(data, size, WIRE_CHANNEL_ANNOUNCEMENT,
			   struct channel_announcement);
}
