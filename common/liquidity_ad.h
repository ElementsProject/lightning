#ifndef LIGHTNING_COMMON_LIQUIDITY_AD_H
#define LIGHTNING_COMMON_LIQUIDITY_AD_H
#include "config.h"
#include <ccan/short_types/short_types.h>
#include <ccan/structeq/structeq.h>
#include <common/amount.h>

struct amount_msat;
struct amount_sat;

struct liquidity_ad {
	u16 lease_basis;
	u16 channel_fee_basis;
	struct amount_sat lease_base_sat;
	struct amount_msat channel_base_msat;
};

/* Define liqudity_ad_eq */
STRUCTEQ_DEF(liquidity_ad, 4,
	     lease_basis,
	     channel_fee_basis,
	     lease_base_sat.satoshis,		/* Raw: comparison */
	     channel_base_msat.millisatoshis);	/* Raw: comparison */

void towire_liquidity_ad(u8 **pptr,
			 const struct liquidity_ad *ad);
struct liquidity_ad *fromwire_liquidity_ad(const tal_t *ctx,
					   const u8 **ptr, size_t *max);

#endif /* LIGHTNING_COMMON_LIQUIDITY_AD_H */
