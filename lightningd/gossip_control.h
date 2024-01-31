#ifndef LIGHTNING_LIGHTNINGD_GOSSIP_CONTROL_H
#define LIGHTNING_LIGHTNINGD_GOSSIP_CONTROL_H
#include "config.h"
#include <bitcoin/short_channel_id.h>
#include <ccan/short_types/short_types.h>
#include <stdbool.h>

struct channel;
struct lightningd;

void gossip_init(struct lightningd *ld, int connectd_fd);

void gossipd_notify_spends(struct lightningd *ld,
			   u32 blockheight,
			   const struct short_channel_id *scids);

void gossip_notify_new_block(struct lightningd *ld, u32 blockheight);

#endif /* LIGHTNING_LIGHTNINGD_GOSSIP_CONTROL_H */
