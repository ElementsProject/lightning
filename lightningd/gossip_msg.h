#ifndef LIGHTNING_LIGHTNINGD_GOSSIP_MSG_H
#define LIGHTNING_LIGHTNINGD_GOSSIP_MSG_H
#include "config.h"
#include <bitcoin/pubkey.h>
#include <gossipd/routing.h>

struct route_info;

struct gossip_getnodes_entry {
	struct node_id nodeid;
	s64 last_timestamp; /* -1 means never: following fields ignored */
	u8 *features;
	struct wireaddr *addresses;
	u8 alias[32];
	u8 color[3];
};

struct gossip_halfchannel_entry {
	u8 message_flags;
	u8 channel_flags;
	u32 last_update_timestamp;
	u32 delay;
	u32 base_fee_msat;
	u32 fee_per_millionth;
	struct amount_msat min, max;
};

struct gossip_getchannels_entry {
	struct node_id node[2];
	struct amount_sat sat;
	struct short_channel_id short_channel_id;
	bool public;
	bool local_disabled;
	/* NULL if we haven't received an update */
	struct gossip_halfchannel_entry *e[2];
	u8 *features;
};

struct gossip_getnodes_entry *
fromwire_gossip_getnodes_entry(const tal_t *ctx, const u8 **pptr, size_t *max);
void towire_gossip_getnodes_entry(u8 **pptr,
				  const struct gossip_getnodes_entry *entry);

struct route_hop *fromwire_route_hop(const tal_t *ctx,
				     const u8 **pptr, size_t *max);
void towire_route_hop(u8 **pprt, const struct route_hop *entry);

void fromwire_route_info(const u8 **pprt, size_t *max, struct route_info *entry);
void towire_route_info(u8 **pprt, const struct route_info *entry);

struct gossip_getchannels_entry *
fromwire_gossip_getchannels_entry(const tal_t *ctx,
				  const u8 **pptr, size_t *max);
void towire_gossip_getchannels_entry(
    u8 **pptr, const struct gossip_getchannels_entry *entry);

#endif /* LIGHTNING_LIGHTNINGD_GOSSIP_MSG_H */
