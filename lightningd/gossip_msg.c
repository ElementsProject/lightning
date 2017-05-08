#include <lightningd/gossip_msg.h>
#include <wire/wire.h>

void fromwire_gossip_getnodes_entry(const tal_t *ctx, const u8 **pptr, size_t *max, struct gossip_getnodes_entry *entry)
{
	u8 numaddresses, i;
	fromwire_pubkey(pptr, max, &entry->nodeid);
	numaddresses = fromwire_u8(pptr, max);

	entry->addresses = tal_arr(ctx, struct ipaddr, numaddresses);
	for (i=0; i<numaddresses; i++) {
		fromwire_ipaddr(pptr, max, entry->addresses);
	}
}
void towire_gossip_getnodes_entry(u8 **pptr, const struct gossip_getnodes_entry *entry)
{
	u8 i, numaddresses = tal_count(entry->addresses);
	towire_pubkey(pptr, &entry->nodeid);
	towire_u8(pptr, numaddresses);

	for (i=0; i<numaddresses; i++) {
		towire_ipaddr(pptr, &entry->addresses[i]);
	}
}

void fromwire_route_hop(const u8 **pptr, size_t *max, struct route_hop *entry)
{
	fromwire_pubkey(pptr, max, &entry->nodeid);
	fromwire_short_channel_id(pptr, max, &entry->channel_id);
	entry->amount = fromwire_u32(pptr, max);
	entry->delay = fromwire_u32(pptr, max);
}
void towire_route_hop(u8 **pptr, const struct route_hop *entry)
{
	towire_pubkey(pptr, &entry->nodeid);
	towire_short_channel_id(pptr, &entry->channel_id);
	towire_u32(pptr, entry->amount);
	towire_u32(pptr, entry->delay);
}

void fromwire_gossip_getchannels_entry(const u8 **pptr, size_t *max,
				      struct gossip_getchannels_entry *entry)
{
	fromwire_short_channel_id(pptr, max, &entry->short_channel_id);
	fromwire_pubkey(pptr, max, &entry->source);
	fromwire_pubkey(pptr, max, &entry->destination);
	entry->active = fromwire_bool(pptr, max);
	entry->fee_per_kw = fromwire_u32(pptr, max);
	entry->delay = fromwire_u32(pptr, max);
	entry->last_update_timestamp = fromwire_u32(pptr, max);
	entry->flags = fromwire_u16(pptr, max);
}

void towire_gossip_getchannels_entry(
    u8 **pptr, const struct gossip_getchannels_entry *entry)
{
	towire_short_channel_id(pptr, &entry->short_channel_id);
	towire_pubkey(pptr, &entry->source);
	towire_pubkey(pptr, &entry->destination);
	towire_bool(pptr, entry->active);
	towire_u32(pptr, entry->fee_per_kw);
	towire_u32(pptr, entry->delay);
	towire_u32(pptr, entry->last_update_timestamp);
	towire_u16(pptr, entry->flags);
}
