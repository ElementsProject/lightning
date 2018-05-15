#include <common/route_info.h>
#include <wire/wire.h>

bool fromwire_route_info(const u8 **cursor, size_t *max,
			 struct route_info *route_info)
{
        fromwire_pubkey(cursor, max, &route_info->pubkey);
        fromwire_short_channel_id(cursor, max, &route_info->short_channel_id);
        route_info->fee_base_msat = fromwire_u32(cursor, max);
        route_info->fee_proportional_millionths = fromwire_u32(cursor, max);
        route_info->cltv_expiry_delta = fromwire_u16(cursor, max);
        return *cursor != NULL;
}

void towire_route_info(u8 **pptr, const struct route_info *route_info)
{
        towire_pubkey(pptr, &route_info->pubkey);
        towire_short_channel_id(pptr, &route_info->short_channel_id);
        towire_u32(pptr, route_info->fee_base_msat);
        towire_u32(pptr, route_info->fee_proportional_millionths);
        towire_u16(pptr, route_info->cltv_expiry_delta);
}

