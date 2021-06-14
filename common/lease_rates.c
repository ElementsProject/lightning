#include "config.h"
#include <bitcoin/pubkey.h>
#include <ccan/ccan/crypto/sha256/sha256.h>
#include <ccan/ccan/mem/mem.h>
#include <common/amount.h>
#include <common/lease_rates.h>
#include <wire/peer_wire.h>

bool lease_rates_empty(struct lease_rates *rates)
{
	if (!rates)
		return true;

	/* FIXME: why can't i do memeqzero? */
	return rates->funding_weight == 0
		&& rates->channel_fee_max_base_msat == 0
		&& rates->channel_fee_max_proportional_thousandths == 0
		&& rates->lease_fee_base_sat == 0
		&& rates->lease_fee_basis == 0;
}

void lease_rates_get_commitment(struct pubkey *pubkey,
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

bool lease_rates_set_chan_fee_base_msat(struct lease_rates *rates,
					struct amount_msat amt)
{
	rates->channel_fee_max_base_msat = amt.millisatoshis; /* Raw: conversion */
	return rates->channel_fee_max_base_msat == amt.millisatoshis; /* Raw: comparsion */
}

bool lease_rates_set_lease_fee_sat(struct lease_rates *rates,
				   struct amount_sat amt)
{
	rates->lease_fee_base_sat = amt.satoshis; /* Raw: conversion */
	return rates->lease_fee_base_sat == amt.satoshis; /* Raw: comparsion */
}
