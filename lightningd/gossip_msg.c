#include <ccan/array_size/array_size.h>
#include <common/bolt11.h>
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
	fromwire(pptr, max, entry->nodeid, sizeof(entry->nodeid));

	entry->last_timestamp = fromwire_u64(pptr, max);
	if (entry->last_timestamp < 0) {
		entry->addresses = NULL;
		return entry;
	}

	flen = fromwire_u16(pptr, max);
	entry->globalfeatures = tal_arr(entry, u8, flen);
	fromwire_u8_array(pptr, max, entry->globalfeatures, flen);

	numaddresses = fromwire_u8(pptr, max);

	entry->addresses = tal_arr(entry, struct wireaddr, numaddresses);
	for (i=0; i<numaddresses; i++) {
		/* Gossipd doesn't hand us addresses we can't understand. */
		if (!fromwire_wireaddr(pptr, max, &entry->addresses[i])) {
			fromwire_fail(pptr, max);
			return NULL;
		}
	}
	fromwire(pptr, max, entry->alias, ARRAY_SIZE(entry->alias));
	fromwire(pptr, max, entry->color, ARRAY_SIZE(entry->color));

	return entry;
}

void towire_gossip_getnodes_entry(u8 **pptr,
				  const struct gossip_getnodes_entry *entry)
{
	towire(pptr, entry->nodeid, sizeof(entry->nodeid));
	towire_u64(pptr, entry->last_timestamp);

	if (entry->last_timestamp < 0)
		return;

	towire_u16(pptr, tal_count(entry->globalfeatures));
	towire_u8_array(pptr, entry->globalfeatures,
			tal_count(entry->globalfeatures));
	towire_u8(pptr, tal_count(entry->addresses));
	for (size_t i = 0; i < tal_count(entry->addresses); i++) {
		towire_wireaddr(pptr, &entry->addresses[i]);
	}
	towire(pptr, entry->alias, ARRAY_SIZE(entry->alias));
	towire(pptr, entry->color, ARRAY_SIZE(entry->color));
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

void fromwire_route_info(const u8 **pptr, size_t *max, struct route_info *entry)
{
	fromwire_pubkey(pptr, max, &entry->pubkey);
	fromwire_short_channel_id(pptr, max, &entry->short_channel_id);
	entry->fee_base_msat = fromwire_u32(pptr, max);
	entry->fee_proportional_millionths = fromwire_u32(pptr, max);
	entry->cltv_expiry_delta = fromwire_u16(pptr, max);
}

void towire_route_info(u8 **pptr, const struct route_info *entry)
{
	towire_pubkey(pptr, &entry->pubkey);
	towire_short_channel_id(pptr, &entry->short_channel_id);
	towire_u32(pptr, entry->fee_base_msat);
	towire_u32(pptr, entry->fee_proportional_millionths);
	towire_u16(pptr, entry->cltv_expiry_delta);
}

void fromwire_gossip_getchannels_entry(const u8 **pptr, size_t *max,
				       struct gossip_getchannels_entry *entry)
{
	fromwire_short_channel_id(pptr, max, &entry->short_channel_id);
	fromwire(pptr, max, entry->source, sizeof(entry->source));
	fromwire(pptr, max, entry->destination, sizeof(entry->destination));
	entry->satoshis = fromwire_u64(pptr, max);
	entry->message_flags = fromwire_u8(pptr, max);
	entry->channel_flags = fromwire_u8(pptr, max);
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
	towire(pptr, entry->source, sizeof(entry->source));
	towire(pptr, entry->destination, sizeof(entry->destination));
	towire_u64(pptr, entry->satoshis);
	towire_u8(pptr, entry->message_flags);
	towire_u8(pptr, entry->channel_flags);
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
	pf->localfeatures = tal_arr(pf, u8, len);
	fromwire_u8_array(pptr, max, pf->localfeatures, len);

	len = fromwire_u16(pptr, max);
	pf->globalfeatures = tal_arr(pf, u8, len);
	fromwire_u8_array(pptr, max, pf->globalfeatures, len);
	return pf;
}

void towire_peer_features(u8 **pptr, const struct peer_features *pf)
{
	towire_u16(pptr, tal_count(pf->localfeatures));
	towire_u8_array(pptr, pf->localfeatures, tal_count(pf->localfeatures));
	towire_u16(pptr, tal_count(pf->globalfeatures));
	towire_u8_array(pptr, pf->globalfeatures, tal_count(pf->globalfeatures));
}
