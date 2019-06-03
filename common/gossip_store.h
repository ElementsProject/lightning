#ifndef LIGHTNING_COMMON_GOSSIP_STORE_H
#define LIGHTNING_COMMON_GOSSIP_STORE_H
#include "config.h"
#include <ccan/short_types/short_types.h>
#include <ccan/tal/tal.h>

struct per_peer_state;

/**
 * gossip_store -- On-disk storage related information
 */
#define GOSSIP_STORE_VERSION 5

/**
 * Bit of length we use to mark a deleted record.
 */
#define GOSSIP_STORE_LEN_DELETED_BIT 0x80000000U

/**
 * Direct store accessor: loads gossip msg from store.
 *
 * Returns NULL and resets time_to_next_gossip(pps) if there are no
 * more gossip msgs.
 */
u8 *gossip_store_next(const tal_t *ctx, struct per_peer_state *pps);

/**
 * Switches the gossip store fd, and gets to the correct offset.
 */
void gossip_store_switch_fd(struct per_peer_state *pps,
			    int newfd, u64 offset_shorter);

#endif /* LIGHTNING_COMMON_GOSSIP_STORE_H */
