#ifndef GOSSIPD_GOSSIP_STORE_H
#define GOSSIPD_GOSSIP_STORE_H

#include "config.h"

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
 * Retrieve the next gossip message if any
 *
 * @param ctx The context to allocate the message from
 * @param gs  The `gossip_store` to read from
 * @return whether a message was read from the store. False means that all
 * messages have been processed.
 */
bool gossip_store_read_next(struct routing_state *rstate,
			    struct gossip_store *gs);

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

#endif /* GOSSIPD_GOSSIP_STORE_H */
