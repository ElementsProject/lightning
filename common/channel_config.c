#include "config.h"
#include <common/channel_config.h>
#include <wire/wire.h>

void towire_channel_config(u8 **pptr, const struct channel_config *config)
{
	towire_amount_sat(pptr, config->dust_limit);
	towire_amount_msat(pptr, config->max_htlc_value_in_flight);
	towire_amount_sat(pptr, config->channel_reserve);
	towire_amount_msat(pptr, config->htlc_minimum);
	towire_u16(pptr, config->to_self_delay);
	towire_u16(pptr, config->max_accepted_htlcs);
	towire_amount_msat(pptr, config->max_dust_htlc_exposure_msat);
}

void fromwire_channel_config(const u8 **ptr, size_t *max,
			     struct channel_config *config)
{
	config->dust_limit = fromwire_amount_sat(ptr, max);
	config->max_htlc_value_in_flight = fromwire_amount_msat(ptr, max);
	config->channel_reserve = fromwire_amount_sat(ptr, max);
	config->htlc_minimum = fromwire_amount_msat(ptr, max);
	config->to_self_delay = fromwire_u16(ptr, max);
	config->max_accepted_htlcs = fromwire_u16(ptr, max);
	config->max_dust_htlc_exposure_msat = fromwire_amount_msat(ptr, max);
}
