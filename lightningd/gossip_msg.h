#ifndef LIGHTNING_LIGHTNINGD_GOSSIP_MSG_H
#define LIGHTNING_LIGHTNINGD_GOSSIP_MSG_H
#include "config.h"
#include <bitcoin/pubkey.h>

struct gossip_getnodes_entry {
	struct pubkey nodeid;
	char *hostname;
	u16 port;
};

void fromwire_gossip_getnodes_entry(const tal_t *ctx, const u8 **pptr, size_t *max, struct gossip_getnodes_entry *entry);
void towire_gossip_getnodes_entry(u8 **pptr, const struct gossip_getnodes_entry *entry);

#endif /* LIGHTNING_LIGHTGNINGD_GOSSIP_MSG_H */
