#include "config.h"
#include <assert.h>
#include <ccan/mem/mem.h>
#include <stdint.h>
#include <tests/fuzz/libfuzz.h>
#include <tests/fuzz/wire.h>
#include <wire/peer_wire.h>

struct open_channel2 {
	struct bitcoin_blkid chain_hash;
	struct channel_id temporary_channel_id;
	u32 funding_feerate_perkw;
	u32 commitment_feerate_perkw;
	struct amount_sat funding_satoshis;
	struct amount_sat dust_limit_satoshis;
	struct amount_msat max_htlc_value_in_flight_msat;
	struct amount_msat htlc_minimum_msat;
	u16 to_self_delay;
	u16 max_accepted_htlcs;
	u32 locktime;
	struct pubkey funding_pubkey;
	struct pubkey revocation_basepoint;
	struct pubkey payment_basepoint;
	struct pubkey delayed_payment_basepoint;
	struct pubkey htlc_basepoint;
	struct pubkey first_per_commitment_point;
	struct pubkey second_per_commitment_point;
	u8 channel_flags;
	struct tlv_opening_tlvs *tlvs;
};

static void *encode(const tal_t *ctx, const struct open_channel2 *s)
{
	return towire_open_channel2(
	    ctx, &s->chain_hash, &s->temporary_channel_id,
	    s->funding_feerate_perkw, s->commitment_feerate_perkw,
	    s->funding_satoshis, s->dust_limit_satoshis,
	    s->max_htlc_value_in_flight_msat, s->htlc_minimum_msat,
	    s->to_self_delay, s->max_accepted_htlcs, s->locktime,
	    &s->funding_pubkey, &s->revocation_basepoint, &s->payment_basepoint,
	    &s->delayed_payment_basepoint, &s->htlc_basepoint,
	    &s->first_per_commitment_point, &s->second_per_commitment_point,
	    s->channel_flags, s->tlvs);
}

static struct open_channel2 *decode(const tal_t *ctx, const void *p)
{
	struct open_channel2 *s = tal(ctx, struct open_channel2);

	if (fromwire_open_channel2(
		s, p, &s->chain_hash, &s->temporary_channel_id,
		&s->funding_feerate_perkw, &s->commitment_feerate_perkw,
		&s->funding_satoshis, &s->dust_limit_satoshis,
		&s->max_htlc_value_in_flight_msat, &s->htlc_minimum_msat,
		&s->to_self_delay, &s->max_accepted_htlcs, &s->locktime,
		&s->funding_pubkey, &s->revocation_basepoint,
		&s->payment_basepoint, &s->delayed_payment_basepoint,
		&s->htlc_basepoint, &s->first_per_commitment_point,
		&s->second_per_commitment_point, &s->channel_flags, &s->tlvs))
		return s;
	return tal_free(s);
}

static bool request_funds_equal(const struct tlv_opening_tlvs_request_funds *x,
				const struct tlv_opening_tlvs_request_funds *y)
{
	if (!x && !y)
		return true;
	if (!x || !y)
		return false;
	return x->requested_sats == y->requested_sats &&
	       x->blockheight == y->blockheight;
}

static bool equal(const struct open_channel2 *x, const struct open_channel2 *y)
{
	size_t upto_channel_flags = (uintptr_t)&x->channel_flags - (uintptr_t)x;
	if (memcmp(x, y, upto_channel_flags) != 0)
		return false;
	if (x->channel_flags != y->channel_flags)
		return false;

	assert(x->tlvs && y->tlvs);

	if (!tal_arr_eq(x->tlvs->upfront_shutdown_script,
			y->tlvs->upfront_shutdown_script))
		return false;

	if (!tal_arr_eq(x->tlvs->channel_type, y->tlvs->channel_type))
		return false;

	if (!request_funds_equal(x->tlvs->request_funds,
				 y->tlvs->request_funds))
		return false;

	return !!x->tlvs->require_confirmed_inputs ==
	       !!y->tlvs->require_confirmed_inputs;
}

void run(const u8 *data, size_t size)
{
	test_decode_encode(data, size, WIRE_OPEN_CHANNEL2,
			   struct open_channel2);
}
