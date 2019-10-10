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
	fromwire_node_id(pptr, max, &entry->nodeid);

	entry->last_timestamp = fromwire_u64(pptr, max);
	if (entry->last_timestamp < 0) {
		entry->addresses = NULL;
		return entry;
	}

	flen = fromwire_u16(pptr, max);
	entry->features = tal_arr(entry, u8, flen);
	fromwire_u8_array(pptr, max, entry->features, flen);

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
	towire_node_id(pptr, &entry->nodeid);
	towire_u64(pptr, entry->last_timestamp);

	if (entry->last_timestamp < 0)
		return;

	towire_u16(pptr, tal_count(entry->features));
	towire_u8_array(pptr, entry->features, tal_count(entry->features));
	towire_u8(pptr, tal_count(entry->addresses));
	for (size_t i = 0; i < tal_count(entry->addresses); i++) {
		towire_wireaddr(pptr, &entry->addresses[i]);
	}
	towire(pptr, entry->alias, ARRAY_SIZE(entry->alias));
	towire(pptr, entry->color, ARRAY_SIZE(entry->color));
}

void fromwire_route_hop(const u8 **pptr, size_t *max, struct route_hop *entry)
{
	fromwire_node_id(pptr, max, &entry->nodeid);
	fromwire_short_channel_id(pptr, max, &entry->channel_id);
	entry->direction = fromwire_u8(pptr, max);
	entry->amount = fromwire_amount_msat(pptr, max);
	entry->delay = fromwire_u32(pptr, max);
}

void towire_route_hop(u8 **pptr, const struct route_hop *entry)
{
	towire_node_id(pptr, &entry->nodeid);
	towire_short_channel_id(pptr, &entry->channel_id);
	towire_u8(pptr, entry->direction);
	towire_amount_msat(pptr, entry->amount);
	towire_u32(pptr, entry->delay);
}

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

static void fromwire_gossip_halfchannel_entry(const u8 **pptr, size_t *max,
					      struct gossip_halfchannel_entry *entry)
{
	entry->message_flags = fromwire_u8(pptr, max);
	entry->channel_flags = fromwire_u8(pptr, max);
	entry->last_update_timestamp = fromwire_u32(pptr, max);
	entry->delay = fromwire_u32(pptr, max);
	entry->base_fee_msat = fromwire_u32(pptr, max);
	entry->fee_per_millionth = fromwire_u32(pptr, max);
	entry->min = fromwire_amount_msat(pptr, max);
	entry->max = fromwire_amount_msat(pptr, max);
}

struct gossip_getchannels_entry *
fromwire_gossip_getchannels_entry(const tal_t *ctx,
				  const u8 **pptr, size_t *max)
{
	struct gossip_getchannels_entry *entry;

	entry= tal(ctx, struct gossip_getchannels_entry);
	fromwire_node_id(pptr, max, &entry->node[0]);
	fromwire_node_id(pptr, max, &entry->node[1]);
	entry->sat = fromwire_amount_sat(pptr, max);
	fromwire_short_channel_id(pptr, max, &entry->short_channel_id);
	entry->public = fromwire_bool(pptr, max);
	entry->local_disabled = fromwire_bool(pptr, max);

	if (fromwire_bool(pptr, max)) {
		entry->e[0] = tal(entry, struct gossip_halfchannel_entry);
		fromwire_gossip_halfchannel_entry(pptr, max, entry->e[0]);
	} else
		entry->e[0] = NULL;
	if (fromwire_bool(pptr, max)) {
		entry->e[1] = tal(entry, struct gossip_halfchannel_entry);
		fromwire_gossip_halfchannel_entry(pptr, max, entry->e[1]);
	} else
		entry->e[1] = NULL;

	return entry;
}

static void towire_gossip_halfchannel_entry(u8 **pptr,
					    const struct gossip_halfchannel_entry *entry)
{
	towire_u8(pptr, entry->message_flags);
	towire_u8(pptr, entry->channel_flags);
	towire_u32(pptr, entry->last_update_timestamp);
	towire_u32(pptr, entry->delay);
	towire_u32(pptr, entry->base_fee_msat);
	towire_u32(pptr, entry->fee_per_millionth);
	towire_amount_msat(pptr, entry->min);
	towire_amount_msat(pptr, entry->max);
}

void towire_gossip_getchannels_entry(u8 **pptr,
				     const struct gossip_getchannels_entry *entry)
{
	towire_node_id(pptr, &entry->node[0]);
	towire_node_id(pptr, &entry->node[1]);
	towire_amount_sat(pptr, entry->sat);
	towire_short_channel_id(pptr, &entry->short_channel_id);
	towire_bool(pptr, entry->public);
	towire_bool(pptr, entry->local_disabled);
	if (entry->e[0]) {
		towire_bool(pptr, true);
		towire_gossip_halfchannel_entry(pptr, entry->e[0]);
	} else
		towire_bool(pptr, false);

	if (entry->e[1]) {
		towire_bool(pptr, true);
		towire_gossip_halfchannel_entry(pptr, entry->e[1]);
	} else
		towire_bool(pptr, false);
}

struct exclude_entry *fromwire_exclude_entry(const tal_t *ctx,
					     const u8 **pptr, size_t *max)
{
	struct exclude_entry *entry = tal(ctx, struct exclude_entry);
	entry->type = fromwire_u8(pptr, max);
	switch (entry->type) {
		case EXCLUDE_CHANNEL:
			fromwire_short_channel_id_dir(pptr, max, &entry->u.chan_id);
			return entry;
		case EXCLUDE_NODE:
			fromwire_node_id(pptr, max, &entry->u.node_id);
			return entry;
		default:
			fromwire_fail(pptr, max);
			return NULL;
	}
}

void towire_exclude_entry(u8 **pptr, const struct exclude_entry *entry)
{
	assert(entry->type == EXCLUDE_CHANNEL ||
	       entry->type == EXCLUDE_NODE);

	towire_u8(pptr, entry->type);
	if (entry->type == EXCLUDE_CHANNEL)
		towire_short_channel_id_dir(pptr, &entry->u.chan_id);
	else
		towire_node_id(pptr, &entry->u.node_id);
}
