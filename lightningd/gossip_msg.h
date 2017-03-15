#ifndef LIGHTNING_LIGHTNINGD_GOSSIP_MSG_H
#define LIGHTNING_LIGHTNINGD_GOSSIP_MSG_H
#include "config.h"
#include <bitcoin/pubkey.h>
#include <daemon/routing.h>

struct gossip_getnodes_entry {
	struct pubkey nodeid;
	char *hostname;
	u16 port;
};

void fromwire_gossip_getnodes_entry(const tal_t *ctx, const u8 **pptr, size_t *max, struct gossip_getnodes_entry *entry);
void towire_gossip_getnodes_entry(u8 **pptr, const struct gossip_getnodes_entry *entry);

void fromwire_route_hop(const u8 **pprt, size_t *max, struct route_hop *entry);
void towire_route_hop(u8 **pprt, const struct route_hop *entry);

#endif /* LIGHTNING_LIGHTGNINGD_GOSSIP_MSG_H */
