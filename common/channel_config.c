#include <common/channel_config.h>
#include <wire/wire.h>

void towire_channel_config(u8 **pptr, const struct channel_config *config)
{
	towire_u64(pptr, config->dust_limit_satoshis);
	towire_u64(pptr, config->max_htlc_value_in_flight_msat);
	towire_u64(pptr, config->channel_reserve_satoshis);
	towire_u32(pptr, config->htlc_minimum_msat);
	towire_u16(pptr, config->to_self_delay);
	towire_u16(pptr, config->max_accepted_htlcs);
}

void fromwire_channel_config(const u8 **ptr, size_t *max,
			     struct channel_config *config)
{
	config->dust_limit_satoshis = fromwire_u64(ptr, max);
	config->max_htlc_value_in_flight_msat = fromwire_u64(ptr, max);
	config->channel_reserve_satoshis = fromwire_u64(ptr, max);
	config->htlc_minimum_msat = fromwire_u32(ptr, max);
	config->to_self_delay = fromwire_u16(ptr, max);
	config->max_accepted_htlcs = fromwire_u16(ptr, max);
}
