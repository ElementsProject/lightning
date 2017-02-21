#ifndef LIGHTNING_LIGHTNINGD_CHANNEL_CONFIG_H
#define LIGHTNING_LIGHTNINGD_CHANNEL_CONFIG_H
#include "config.h"
#include <ccan/short_types/short_types.h>
#include <ccan/tal/tal.h>

/* BOLT #2:
 *
 * 1. type: 32 (`open_channel`)
 * 2. data:
 *    * [8:temporary-channel-id]
 *    * [8:funding-satoshis]
 *    * [8:push-msat]
 *    * [8:dust-limit-satoshis]
 *    * [8:max-htlc-value-in-flight-msat]
 *    * [8:channel-reserve-satoshis]
 *    * [4:htlc-minimum-msat]
 *    * [4:feerate-per-kw]
 *    * [2:to-self-delay]
 *    * [2:max-accepted-htlcs]
 *...
 * 1. type: 33 (`accept_channel`)
 * 2. data:
 *    * [8:temporary-channel-id]
 *    * [8:dust-limit-satoshis]
 *    * [8:max-htlc-value-in-flight-msat]
 *    * [8:channel-reserve-satoshis]
 *    * [4:minimum-depth]
 *    * [4:htlc-minimum-msat]
 *    * [2:to-self-delay]
 *    * [2:max-accepted-htlcs]
 */
struct channel_config {
	u64 dust_limit_satoshis;
	u64 max_htlc_value_in_flight_msat;
	u64 channel_reserve_satoshis;
	u32 minimum_depth;
	u32 htlc_minimum_msat;
	u16 to_self_delay;
	u16 max_accepted_htlcs;
};

void towire_channel_config(u8 **pptr, const struct channel_config *config);
void fromwire_channel_config(const u8 **ptr, size_t *max,
			     struct channel_config *config);
#endif /* LIGHTNING_LIGHTNINGD_CHANNEL_CONFIG_H */
