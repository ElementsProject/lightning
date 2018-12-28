#ifndef LIGHTNING_LIGHTNINGD_GOSSIP_CONTROL_H
#define LIGHTNING_LIGHTNINGD_GOSSIP_CONTROL_H
#include "config.h"
#include <bitcoin/short_channel_id.h>
#include <ccan/short_types/short_types.h>
#include <stdbool.h>

struct lightningd;

void gossip_init(struct lightningd *ld, int connectd_fd);

void gossipd_notify_spend(struct lightningd *ld,
			  const struct short_channel_id *scid);

#endif /* LIGHTNING_LIGHTNINGD_GOSSIP_CONTROL_H */
