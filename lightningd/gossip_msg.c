#include "config.h"
#include <ccan/array_size/array_size.h>
#include <common/bolt11.h>
#include <common/wireaddr.h>
#include <lightningd/gossip_msg.h>
#include <wire/peer_wire.h>

void fromwire_route_info(const u8 **pptr, size_t *max, struct route_info *entry)
{
	fromwire_node_id(pptr, max, &entry->pubkey);
	fromwire_short_channel_id(pptr, max, &entry->short_channel_id);
	entry->fee_base_msat = fromwire_u32(pptr, max);
	entry->fee_proportional_millionths = fromwire_u32(pptr, max);
	entry->cltv_expiry_delta = fromwire_u16(pptr, max);
}

void towire_route_info(u8 **pptr, const struct route_info *entry)
{
	towire_node_id(pptr, &entry->pubkey);
	towire_short_channel_id(pptr, &entry->short_channel_id);
	towire_u32(pptr, entry->fee_base_msat);
	towire_u32(pptr, entry->fee_proportional_millionths);
	towire_u16(pptr, entry->cltv_expiry_delta);
}
