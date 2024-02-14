#include "config.h"
#include <assert.h>
#include <ccan/mem/mem.h>
#include <stdint.h>
#include <tests/fuzz/libfuzz.h>
#include <tests/fuzz/wire.h>
#include <wire/peer_wire.h>

struct accept_channel {
	struct channel_id temporary_channel_id;
	struct amount_sat dust_limit_satoshis;
	struct amount_msat max_htlc_value_in_flight_msat;
	struct amount_sat channel_reserve_satoshis;
	struct amount_msat htlc_minimum_msat;
	u32 minimum_depth;
	u16 to_self_delay;
	u16 max_accepted_htlcs;
	struct pubkey funding_pubkey;
	struct pubkey revocation_basepoint;
	struct pubkey payment_basepoint;
	struct pubkey delayed_payment_basepoint;
	struct pubkey htlc_basepoint;
	struct pubkey first_per_commitment_point;
	struct tlv_accept_channel_tlvs *tlvs;
};

static void *encode(const tal_t *ctx, const struct accept_channel *s)
{
	return towire_accept_channel(
	    ctx, &s->temporary_channel_id, s->dust_limit_satoshis,
	    s->max_htlc_value_in_flight_msat, s->channel_reserve_satoshis,
	    s->htlc_minimum_msat, s->minimum_depth, s->to_self_delay,
	    s->max_accepted_htlcs, &s->funding_pubkey, &s->revocation_basepoint,
	    &s->payment_basepoint, &s->delayed_payment_basepoint,
	    &s->htlc_basepoint, &s->first_per_commitment_point, s->tlvs);
}

static struct accept_channel *decode(const tal_t *ctx, const void *p)
{
	struct accept_channel *s = tal(ctx, struct accept_channel);

	if (fromwire_accept_channel(
		s, p, &s->temporary_channel_id, &s->dust_limit_satoshis,
		&s->max_htlc_value_in_flight_msat, &s->channel_reserve_satoshis,
		&s->htlc_minimum_msat, &s->minimum_depth, &s->to_self_delay,
		&s->max_accepted_htlcs, &s->funding_pubkey,
		&s->revocation_basepoint, &s->payment_basepoint,
		&s->delayed_payment_basepoint, &s->htlc_basepoint,
		&s->first_per_commitment_point, &s->tlvs))
		return s;
	return tal_free(s);
}

static bool equal(const struct accept_channel *x,
		  const struct accept_channel *y)
{
	size_t upto_tlvs = (uintptr_t)&x->tlvs - (uintptr_t)x;
	if (memcmp(x, y, upto_tlvs) != 0)
		return false;

	assert(x->tlvs && y->tlvs);

	if (!tal_arr_eq(x->tlvs->upfront_shutdown_script,
			y->tlvs->upfront_shutdown_script))
		return false;

	return tal_arr_eq(x->tlvs->channel_type, y->tlvs->channel_type);
}

void run(const u8 *data, size_t size)
{
	test_decode_encode(data, size, WIRE_ACCEPT_CHANNEL,
			   struct accept_channel);
}
