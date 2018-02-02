#ifndef LIGHTNING_LIGHTNINGD_GOSSIP_MSG_H
#define LIGHTNING_LIGHTNINGD_GOSSIP_MSG_H
#include "config.h"
#include <bitcoin/pubkey.h>
#include <gossipd/routing.h>

struct gossip_getnodes_entry {
	struct pubkey nodeid;
	s64 last_timestamp; /* -1 means never: following fields ignored */
	struct wireaddr *addresses;
	u8 *alias;
	u8 color[3];
};

struct gossip_getchannels_entry {
	struct pubkey source, destination;
	bool active;
	struct short_channel_id short_channel_id;
	u16 flags;
	bool public;
	s64 last_update_timestamp; /* -1 means never */
	/* These are only set if last_update_timestamp >= 0 */
	u32 delay;
	u32 base_fee_msat;
	u32 fee_per_millionth;
};

struct gossip_getnodes_entry *
fromwire_gossip_getnodes_entry(const tal_t *ctx, const u8 **pptr, size_t *max);
void towire_gossip_getnodes_entry(u8 **pptr,
				  const struct gossip_getnodes_entry *entry);

void fromwire_route_hop(const u8 **pprt, size_t *max, struct route_hop *entry);
void towire_route_hop(u8 **pprt, const struct route_hop *entry);

void fromwire_gossip_getchannels_entry(const u8 **pptr, size_t *max,
				       struct gossip_getchannels_entry *entry);
void towire_gossip_getchannels_entry(
    u8 **pptr, const struct gossip_getchannels_entry *entry);

#endif /* LIGHTNING_LIGHTNINGD_GOSSIP_MSG_H */
