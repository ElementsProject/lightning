#ifndef LIGHTNING_COMMON_CHANNEL_CONFIG_H
#define LIGHTNING_COMMON_CHANNEL_CONFIG_H
#include "config.h"
#include <ccan/short_types/short_types.h>
#include <ccan/tal/tal.h>

/* BOLT #2:
 *
 * 1. type: 32 (`open_channel`)
 * 2. data:
 *    * [`32`:`chain_hash`]
 *    * [`32`:`temporary_channel_id`]
 *    * [`8`:`funding_satoshis`]
 *    * [`8`:`push_msat`]
 *    * [`8`:`dust_limit_satoshis`]
 *    * [`8`:`max_htlc_value_in_flight_msat`]
 *    * [`8`:`channel_reserve_satoshis`]
 *    * [`8`:`htlc_minimum_msat`]
 *    * [`4`:`feerate_per_kw`]
 *    * [`2`:`to_self_delay`]
 *    * [`2`:`max_accepted_htlcs`]
 *...
 * 1. type: 33 (`accept_channel`)
 * 2. data:
 *    * [`32`:`temporary_channel_id`]
 *    * [`8`:`dust_limit_satoshis`]
 *    * [`8`:`max_htlc_value_in_flight_msat`]
 *    * [`8`:`channel_reserve_satoshis`]
 *    * [`8`:`htlc_minimum_msat`]
 *    * [`4`:`minimum_depth`]
 *    * [`2`:`to_self_delay`]
 *    * [`2`:`max_accepted_htlcs`]
 */
struct channel_config {
	/* Database ID */
	u64 id;
	u64 dust_limit_satoshis;
	u64 max_htlc_value_in_flight_msat;
	u64 channel_reserve_satoshis;
	u64 htlc_minimum_msat;
	u16 to_self_delay;
	u16 max_accepted_htlcs;
};

void towire_channel_config(u8 **pptr, const struct channel_config *config);
void fromwire_channel_config(const u8 **ptr, size_t *max,
			     struct channel_config *config);
#endif /* LIGHTNING_COMMON_CHANNEL_CONFIG_H */
