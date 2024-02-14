#include "config.h"
#include <assert.h>
#include <ccan/mem/mem.h>
#include <common/node_id.h>
#include <tests/fuzz/libfuzz.h>
#include <tests/fuzz/wire.h>
#include <wire/peer_wire.h>

struct node_announcement {
	secp256k1_ecdsa_signature signature;
	u8 *features;
	u32 timestamp;
	struct node_id node_id;
	u8 rgb_color[3];
	u8 alias[32];
	u8 *addresses;
	struct tlv_node_ann_tlvs *tlvs;
};

static void *encode(const tal_t *ctx, const struct node_announcement *s)
{
	return towire_node_announcement(ctx, &s->signature, s->features,
					s->timestamp, &s->node_id, s->rgb_color,
					s->alias, s->addresses, s->tlvs);
}

static struct node_announcement *decode(const tal_t *ctx, const void *p)
{
	struct node_announcement *s = tal(ctx, struct node_announcement);

	if (fromwire_node_announcement(s, p, &s->signature, &s->features,
				       &s->timestamp, &s->node_id, s->rgb_color,
				       s->alias, &s->addresses, &s->tlvs))
		return s;
	return tal_free(s);
}

static bool lease_rates_equal(const struct lease_rates *x,
			      const struct lease_rates *y)
{
	if (!x && !y)
		return true;
	if (!x || !y)
		return false;

	return x->funding_weight == y->funding_weight &&
	       x->lease_fee_basis == y->lease_fee_basis &&
	       x->channel_fee_max_proportional_thousandths ==
		   y->channel_fee_max_proportional_thousandths &&
	       x->lease_fee_base_sat == y->lease_fee_base_sat &&
	       x->channel_fee_max_base_msat == y->channel_fee_max_base_msat;
}

static bool equal(const struct node_announcement *x,
		  const struct node_announcement *y)
{
	if (memcmp(&x->signature, &y->signature, sizeof(x->signature)) != 0)
		return false;
	if (!tal_arr_eq(x->features, y->features))
		return false;
	if (x->timestamp != y->timestamp)
		return false;
	if (!node_id_eq(&x->node_id, &y->node_id))
		return false;
	if (memcmp(x->rgb_color, y->rgb_color, sizeof(x->rgb_color)) != 0)
		return false;
	if (memcmp(x->alias, y->alias, sizeof(x->alias)) != 0)
		return false;
	if (!tal_arr_eq(x->addresses, y->addresses))
		return false;

	assert(x->tlvs && y->tlvs);

	return lease_rates_equal(x->tlvs->option_will_fund,
				 y->tlvs->option_will_fund);
}

void run(const u8 *data, size_t size)
{
	test_decode_encode(data, size, WIRE_NODE_ANNOUNCEMENT,
			   struct node_announcement);
}
