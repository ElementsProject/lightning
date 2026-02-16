#ifndef LIGHTNING_LIGHTNINGD_GOSSIP_CONTROL_H
#define LIGHTNING_LIGHTNINGD_GOSSIP_CONTROL_H
#include "config.h"
#include <bitcoin/short_channel_id.h>

struct channel;
struct lightningd;

void gossip_init(struct lightningd *ld, int connectd_fd);

void gossipd_notify_spends(struct lightningd *ld,
			   u32 blockheight,
			   const struct short_channel_id *scids);

void gossip_notify_new_block(struct lightningd *ld);

/**
 * gossip_notify_blockheight - Notify gossipd of a specific block height
 *
 * Used when bwatch processes a block; the authoritative height comes from
 * bwatch's block_processed, not chaintopology.
 */
void gossip_notify_blockheight(struct lightningd *ld, u32 blockheight);

#endif /* LIGHTNING_LIGHTNINGD_GOSSIP_CONTROL_H */
