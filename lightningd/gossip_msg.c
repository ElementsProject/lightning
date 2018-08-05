#include <common/wireaddr.h>
#include <lightningd/gossip_msg.h>
#include <wire/wire.h>

struct gossip_getnodes_entry *fromwire_gossip_getnodes_entry(const tal_t *ctx,
	const u8 **pptr, size_t *max)
{
	u8 numaddresses, i;
	struct gossip_getnodes_entry *entry;
	u16 flen;

	entry = tal(ctx, struct gossip_getnodes_entry);
	fromwire_pubkey(pptr, max, &entry->nodeid);

	flen = fromwire_u16(pptr, max);
	entry->global_features = tal_arr(entry, u8, flen);
	fromwire_u8_array(pptr, max, entry->global_features, flen);

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
		if (!fromwire_wireaddr(pptr, max, &entry->addresses[i])) {
			fromwire_fail(pptr, max);
			return NULL;
		}
	}
	/* Make sure alias is NUL terminated */
	entry->alias = tal_arrz(entry, u8, fromwire_u8(pptr, max)+1);
	fromwire(pptr, max, entry->alias, tal_count(entry->alias)-1);
	fromwire(pptr, max, entry->color, sizeof(entry->color));

	return entry;
}

void towire_gossip_getnodes_entry(u8 **pptr,
				  const struct gossip_getnodes_entry *entry)
{
	u8 i, numaddresses = tal_count(entry->addresses);
	towire_pubkey(pptr, &entry->nodeid);
	towire_u16(pptr, tal_count(entry->global_features));
	towire_u8_array(pptr, entry->global_features,
			tal_count(entry->global_features));
	towire_u64(pptr, entry->last_timestamp);

	if (entry->last_timestamp < 0)
		return;

	towire_u8(pptr, numaddresses);
	for (i=0; i<numaddresses; i++) {
		towire_wireaddr(pptr, &entry->addresses[i]);
	}
	towire_u8(pptr, tal_count(entry->alias));
	towire(pptr, entry->alias, tal_count(entry->alias));
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
	entry->flags = fromwire_u16(pptr, max);
	entry->public = fromwire_bool(pptr, max);
	entry->local_disabled = fromwire_bool(pptr, max);
	entry->last_update_timestamp = fromwire_u32(pptr, max);
	entry->base_fee_msat = fromwire_u32(pptr, max);
	entry->fee_per_millionth = fromwire_u32(pptr, max);
	entry->delay = fromwire_u32(pptr, max);
}

void towire_gossip_getchannels_entry(u8 **pptr,
				     const struct gossip_getchannels_entry *entry)
{
	towire_short_channel_id(pptr, &entry->short_channel_id);
	towire_pubkey(pptr, &entry->source);
	towire_pubkey(pptr, &entry->destination);
	towire_u64(pptr, entry->satoshis);
	towire_u16(pptr, entry->flags);
	towire_bool(pptr, entry->public);
	towire_bool(pptr, entry->local_disabled);
	towire_u32(pptr, entry->last_update_timestamp);
	towire_u32(pptr, entry->base_fee_msat);
	towire_u32(pptr, entry->fee_per_millionth);
	towire_u32(pptr, entry->delay);
}

struct peer_features *
fromwire_peer_features(const tal_t *ctx, const u8 **pptr, size_t *max)
{
	struct peer_features *pf = tal(ctx, struct peer_features);
	size_t len;

	len = fromwire_u16(pptr, max);
	pf->local_features = tal_arr(pf, u8, len);
	fromwire_u8_array(pptr, max, pf->local_features, len);

	len = fromwire_u16(pptr, max);
	pf->global_features = tal_arr(pf, u8, len);
	fromwire_u8_array(pptr, max, pf->global_features, len);
	return pf;
}

void towire_peer_features(u8 **pptr, const struct peer_features *pf)
{
	towire_u16(pptr, tal_count(pf->local_features));
	towire_u8_array(pptr, pf->local_features, tal_count(pf->local_features));
	towire_u16(pptr, tal_count(pf->global_features));
	towire_u8_array(pptr, pf->global_features, tal_count(pf->global_features));
}
