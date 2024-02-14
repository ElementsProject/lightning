#include "config.h"
#include <assert.h>
#include <ccan/mem/mem.h>
#include <stdint.h>
#include <tests/fuzz/libfuzz.h>
#include <tests/fuzz/wire.h>
#include <wire/peer_wire.h>

struct accept_channel2 {
	struct channel_id temporary_channel_id;
	struct amount_sat funding_satoshis;
	struct amount_sat dust_limit_satoshis;
	struct amount_msat max_htlc_value_in_flight_msat;
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
	struct pubkey second_per_commitment_point;
	struct tlv_accept_tlvs *tlvs;
};

static void *encode(const tal_t *ctx, const struct accept_channel2 *s)
{
	return towire_accept_channel2(
	    ctx, &s->temporary_channel_id, s->funding_satoshis,
	    s->dust_limit_satoshis, s->max_htlc_value_in_flight_msat,
	    s->htlc_minimum_msat, s->minimum_depth, s->to_self_delay,
	    s->max_accepted_htlcs, &s->funding_pubkey, &s->revocation_basepoint,
	    &s->payment_basepoint, &s->delayed_payment_basepoint,
	    &s->htlc_basepoint, &s->first_per_commitment_point,
	    &s->second_per_commitment_point, s->tlvs);
}

static struct accept_channel2 *decode(const tal_t *ctx, const void *p)
{
	struct accept_channel2 *s = tal(ctx, struct accept_channel2);

	if (fromwire_accept_channel2(
		s, p, &s->temporary_channel_id, &s->funding_satoshis,
		&s->dust_limit_satoshis, &s->max_htlc_value_in_flight_msat,
		&s->htlc_minimum_msat, &s->minimum_depth, &s->to_self_delay,
		&s->max_accepted_htlcs, &s->funding_pubkey,
		&s->revocation_basepoint, &s->payment_basepoint,
		&s->delayed_payment_basepoint, &s->htlc_basepoint,
		&s->first_per_commitment_point, &s->second_per_commitment_point,
		&s->tlvs))
		return s;
	return tal_free(s);
}

static bool will_fund_equal(const struct tlv_accept_tlvs_will_fund *x,
			    const struct tlv_accept_tlvs_will_fund *y)
{
	const struct lease_rates *xlr, *ylr;

	if (!x && !y)
		return true;
	if (!x || !y)
		return false;

	if (memcmp(&x->signature, &y->signature, sizeof(x->signature)) != 0)
		return false;

	xlr = &x->lease_rates;
	ylr = &y->lease_rates;
	return xlr->funding_weight == ylr->funding_weight &&
	       xlr->lease_fee_basis == ylr->lease_fee_basis &&
	       xlr->channel_fee_max_proportional_thousandths ==
		   ylr->channel_fee_max_proportional_thousandths &&
	       xlr->lease_fee_base_sat == ylr->lease_fee_base_sat &&
	       xlr->channel_fee_max_base_msat == ylr->channel_fee_max_base_msat;
}

static bool equal(const struct accept_channel2 *x,
		  const struct accept_channel2 *y)
{
	size_t upto_tlvs = (uintptr_t)&x->tlvs - (uintptr_t)x;
	if (memcmp(x, y, upto_tlvs) != 0)
		return false;

	assert(x->tlvs && y->tlvs);

	if (!tal_arr_eq(x->tlvs->upfront_shutdown_script,
			y->tlvs->upfront_shutdown_script))
		return false;

	if (!tal_arr_eq(x->tlvs->channel_type, y->tlvs->channel_type))
		return false;

	if (!!x->tlvs->require_confirmed_inputs !=
	    !!y->tlvs->require_confirmed_inputs)
		return false;

	return will_fund_equal(x->tlvs->will_fund, y->tlvs->will_fund);
}

void run(const u8 *data, size_t size)
{
	test_decode_encode(data, size, WIRE_ACCEPT_CHANNEL2,
			   struct accept_channel2);
}
