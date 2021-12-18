#include "config.h"
#include <ccan/ccan/tal/str/str.h>
#include <common/lease_rates.h>
#include <common/overflows.h>

bool lease_rates_empty(const struct lease_rates *rates)
{
	/* static means it's zero initialized */
	static const struct lease_rates zero;
	if (!rates)
		return true;

	return lease_rates_eq(rates, &zero);
}

void lease_rates_get_commitment(const struct pubkey *pubkey,
				u32 lease_expiry,
				u32 chan_fee_msat,
				u16 chan_fee_ppt,
				struct sha256 *sha)
{
	struct sha256_ctx sctx = SHA256_INIT;
	u8 der[PUBKEY_CMPR_LEN];
	/* BOLT- #2:
	 * - MUST set `signature` to the ECDSA signature of
	 *   SHA256("option_will_fund"
	 *          || `funding_pubkey`
	 *   	    || `blockheight` + 4032
	 *   	    || `channel_fee_max_base_msat`
	 *   	    || `channel_fee_max_proportional_thousandths`)
	 *   using the node_id key.
	 */
	pubkey_to_der(der, pubkey);
	sha256_update(&sctx, "option_will_fund", strlen("option_will_fund"));
	sha256_update(&sctx, der, PUBKEY_CMPR_LEN);
	sha256_be32(&sctx, lease_expiry);
	sha256_be32(&sctx, chan_fee_msat);
	sha256_be16(&sctx, chan_fee_ppt);
	sha256_done(&sctx, sha);
}

bool lease_rates_calc_fee(const struct lease_rates *rates,
			  struct amount_sat accept_funding_sats,
			  struct amount_sat requested_sats,
			  u32 onchain_feerate,
			  struct amount_sat *fee)
{
	struct amount_sat lease_fee, basis_sat, tx_fee;
	/* BOLT- #2:
	 * The lease fee is calculated as:
	 * `lease_fee_base_sat` +
	 * min(`accept_channel2`.`funding_satoshis`, `open_channel2`.`requested_sats`) * `lease_fee_basis` / 10_000 +
	 * `funding_weight` * `funding_feerate_perkw` / 1000
	 */

	lease_fee = amount_sat(rates->lease_fee_base_sat);
	basis_sat = amount_sat_less(accept_funding_sats, requested_sats)
		? accept_funding_sats : requested_sats;

	if (!amount_sat_scale(&basis_sat, basis_sat,
			      rates->lease_fee_basis))
		return false;

	basis_sat = amount_sat_div(basis_sat, 10000);

	if (!amount_sat_add(&lease_fee, lease_fee, basis_sat))
		return false;

	tx_fee = amount_tx_fee(onchain_feerate, rates->funding_weight);
	if (!amount_sat_add(&lease_fee, lease_fee, tx_fee))
		return false;

	*fee = lease_fee;
	return true;
}

bool lease_rates_set_chan_fee_base_msat(struct lease_rates *rates,
					struct amount_msat amt)
{
	return assign_overflow_u32(&rates->channel_fee_max_base_msat,
				   amt.millisatoshis); /* Raw: conversion */
}

bool lease_rates_set_lease_fee_sat(struct lease_rates *rates,
				   struct amount_sat amt)
{
	return assign_overflow_u32(&rates->lease_fee_base_sat,
				   amt.satoshis); /* Raw: conversion */
}

char *lease_rates_tohex(const tal_t *ctx, const struct lease_rates *rates)
{
	char *hex;
	u8 *data = tal_arr(NULL, u8, 0);
	towire_lease_rates(&data, rates);
	hex = tal_hex(ctx, data);
	tal_free(data);
	return hex;
}

struct lease_rates *lease_rates_fromhex(const tal_t *ctx,
					const char *hexdata, size_t hexlen)
{
	const u8 *data = tal_hexdata(ctx, hexdata, hexlen);
	size_t len = tal_bytelen(data);
	struct lease_rates *ret;

	ret = tal(ctx, struct lease_rates);
	fromwire_lease_rates(&data, &len, ret);

	if (data == NULL || len != 0)
		return tal_free(ret);

	return ret;
}

char *lease_rates_fmt(const tal_t *ctx, const struct lease_rates *rates)
{
	return tal_fmt(ctx, "{channel_fee_max_base_msat=%u,"
		       "channel_fee_max_ppt=%u,"
		       "funding_weight=%u,"
		       "lease_fee_base_sat=%u,"
		       "lease_fee_basis=%u}",
		       rates->channel_fee_max_base_msat,
		       rates->channel_fee_max_proportional_thousandths,
		       rates->funding_weight,
		       rates->lease_fee_base_sat,
		       rates->lease_fee_basis);
}
