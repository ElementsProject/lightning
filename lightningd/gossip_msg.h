#ifndef LIGHTNING_LIGHTNINGD_GOSSIP_MSG_H
#define LIGHTNING_LIGHTNINGD_GOSSIP_MSG_H
#include "config.h"
#include <bitcoin/pubkey.h>
#include <gossipd/routing.h>

struct route_info;
struct lease_rates;

struct gossip_getnodes_entry {
	struct node_id nodeid;
	s64 last_timestamp; /* -1 means never: following fields ignored */
	u8 *features;
	struct wireaddr *addresses;
	u8 alias[32];
	u8 color[3];
	struct lease_rates *rates;
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

void fromwire_route_info(const u8 **pprt, size_t *max, struct route_info *entry);
void towire_route_info(u8 **pprt, const struct route_info *entry);

#endif /* LIGHTNING_LIGHTNINGD_GOSSIP_MSG_H */
