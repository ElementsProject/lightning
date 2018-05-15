#ifndef LIGHTNING_COMMON_ROUTE_INFO_H
#define LIGHTNING_COMMON_ROUTE_INFO_H
#include "config.h"

#include <bitcoin/pubkey.h>
#include <bitcoin/short_channel_id.h>
#include <ccan/short_types/short_types.h>

/* BOLT #11:
 *   * `pubkey` (264 bits)
 *   * `short_channel_id` (64 bits)
 *   * `fee_base_msat` (32 bits, big-endian)
 *   * `fee_proportional_millionths` (32 bits, big-endian)
 *   * `cltv_expiry_delta` (16 bits, big-endian)
 */

struct route_info {
	struct pubkey pubkey;
	struct short_channel_id short_channel_id;
	u32 fee_base_msat, fee_proportional_millionths;
	u16 cltv_expiry_delta;
};

/* Serialization of route_info. */
bool fromwire_route_info(const u8 **cursor, size_t *max,
			 struct route_info *route_info);
void towire_route_info(u8 **pptr, const struct route_info *route_info);

#endif /* LIGHTNING_COMMON_ROUTE_INFO_H */
