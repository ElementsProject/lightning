#ifndef LIGHTNING_GOSSIPD_GOSSIP_STORE_H
#define LIGHTNING_GOSSIPD_GOSSIP_STORE_H

#include "config.h"

#include <bitcoin/short_channel_id.h>
#include <ccan/short_types/short_types.h>
#include <ccan/tal/tal.h>
#include <gossipd/routing.h>

/**
 * gossip_store -- On-disk storage related information
 */
struct gossip_store;
struct routing_state;

struct gossip_store *gossip_store_new(const tal_t *ctx);

/**
 * Load the initial gossip store, if any.
 *
 * @param rstate The routing state to load init.
 * @param gs  The `gossip_store` to read from
 */
void gossip_store_load(struct routing_state *rstate, struct gossip_store *gs);

/**
 * Store a channel_announcement with all its extra data
 */
void gossip_store_add_channel_announcement(struct gossip_store *gs,
					   const u8 *gossip_msg, u64 satoshis);

/**
 * Store a channel_update with its associated data in the gossip_store
 */
void gossip_store_add_channel_update(struct gossip_store *gs,
				     const u8 *gossip_msg);

/**
 * Store a node_announcement with its associated data in the gossip_store
 */
void gossip_store_add_node_announcement(struct gossip_store *gs,
					const u8 *gossip_msg);

/**
 * Remember that we deleted a channel as a result of its outpoint being spent
 */
void gossip_store_add_channel_delete(struct gossip_store *gs,
				     const struct short_channel_id *scid);

#endif /* LIGHTNING_GOSSIPD_GOSSIP_STORE_H */
