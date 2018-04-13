#include <common/wireaddr.h>
#include <lightningd/gossip_msg.h>
#include <wire/wire.h>

struct gossip_getnodes_entry *fromwire_gossip_getnodes_entry(const tal_t *ctx, const u8 **pptr, size_t *max)
{
	u8 numaddresses, i;
	struct gossip_getnodes_entry *entry;

	entry = tal(ctx, struct gossip_getnodes_entry);
	fromwire_pubkey(pptr, max, &entry->nodeid);
	entry->last_timestamp = fromwire_u64(pptr, max);

	if (entry->last_timestamp < 0) {
		entry->addresses = NULL;
		entry->alias = NULL;
		return entry;
	}
	numaddresses = fromwire_u8(pptr, max);

	entry->addresses = tal_arr(entry, struct wireaddr, numaddresses);
	for (i=0; i<numaddresses; i++) {
		/* Gossipd doesn't hand us addresses we can't understand. */
		if (!fromwire_wireaddr(pptr, max, entry->addresses)) {
			fromwire_fail(pptr, max);
			return NULL;
		}
	}
	entry->alias = tal_arr(entry, u8, fromwire_u8(pptr, max));
	fromwire(pptr, max, entry->alias, tal_len(entry->alias));
	fromwire(pptr, max, entry->color, sizeof(entry->color));
	return entry;
}

void towire_gossip_getnodes_entry(u8 **pptr, const struct gossip_getnodes_entry *entry)
{
	u8 i, numaddresses = tal_count(entry->addresses);
	towire_pubkey(pptr, &entry->nodeid);
	towire_u64(pptr, entry->last_timestamp);

	if (entry->last_timestamp < 0)
		return;

	towire_u8(pptr, numaddresses);
	for (i=0; i<numaddresses; i++) {
		towire_wireaddr(pptr, &entry->addresses[i]);
	}
	towire_u8(pptr, tal_len(entry->alias));
	towire(pptr, entry->alias, tal_len(entry->alias));
	towire(pptr, entry->color, sizeof(entry->color));
}

void fromwire_route_hop(const u8 **pptr, size_t *max, struct route_hop *entry)
{
	fromwire_pubkey(pptr, max, &entry->nodeid);
	fromwire_short_channel_id(pptr, max, &entry->channel_id);
	entry->amount = fromwire_u64(pptr, max);
	entry->delay = fromwire_u32(pptr, max);
}
void towire_route_hop(u8 **pptr, const struct route_hop *entry)
{
	towire_pubkey(pptr, &entry->nodeid);
	towire_short_channel_id(pptr, &entry->channel_id);
	towire_u64(pptr, entry->amount);
	towire_u32(pptr, entry->delay);
}

void fromwire_gossip_getchannels_entry(const u8 **pptr, size_t *max,
				      struct gossip_getchannels_entry *entry)
{
	fromwire_short_channel_id(pptr, max, &entry->short_channel_id);
	fromwire_pubkey(pptr, max, &entry->source);
	fromwire_pubkey(pptr, max, &entry->destination);
	entry->satoshis = fromwire_u64(pptr, max);
	entry->active = fromwire_bool(pptr, max);
	entry->flags = fromwire_u16(pptr, max);
	entry->public = fromwire_bool(pptr, max);
	entry->last_update_timestamp = fromwire_u64(pptr, max);
	if (entry->last_update_timestamp >= 0) {
		entry->base_fee_msat = fromwire_u32(pptr, max);
		entry->fee_per_millionth = fromwire_u32(pptr, max);
		entry->delay = fromwire_u32(pptr, max);
	}
}

void towire_gossip_getchannels_entry(
    u8 **pptr, const struct gossip_getchannels_entry *entry)
{
	towire_short_channel_id(pptr, &entry->short_channel_id);
	towire_pubkey(pptr, &entry->source);
	towire_pubkey(pptr, &entry->destination);
	towire_u64(pptr, entry->satoshis);
	towire_bool(pptr, entry->active);
	towire_u16(pptr, entry->flags);
	towire_bool(pptr, entry->public);
	towire_u64(pptr, entry->last_update_timestamp);
	if (entry->last_update_timestamp >= 0) {
		towire_u32(pptr, entry->base_fee_msat);
		towire_u32(pptr, entry->fee_per_millionth);
		towire_u32(pptr, entry->delay);
	}
}
