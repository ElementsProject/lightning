#include "liquidity_ad.h"
#include <wire/wire.h>

void towire_liquidity_ad(u8 **pptr,
			 const struct liquidity_ad *ad)
{
	towire_u16(pptr, ad->lease_basis);
	towire_u16(pptr, ad->channel_fee_basis);
	towire_amount_sat(pptr, ad->lease_base_sat);
	towire_amount_msat(pptr, ad->channel_base_msat);
}

struct liquidity_ad *fromwire_liquidity_ad(const tal_t *ctx,
					   const u8 **pptr, size_t *max)
{
	struct liquidity_ad *ad = tal(ctx, struct liquidity_ad);

	ad->lease_basis = fromwire_u16(pptr, max);
	ad->channel_fee_basis = fromwire_u16(pptr, max);
	ad->lease_base_sat = fromwire_amount_sat(pptr, max);
	ad->channel_base_msat = fromwire_amount_msat(pptr, max);

	return ad;
}


