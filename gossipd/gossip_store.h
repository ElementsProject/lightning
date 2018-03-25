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
 * Write an incoming message to the `gossip_store`
 *
 * @param gs  The gossip_store to write to
 * @param msg The message to write
 * @return The newly created and initialized `gossip_store`
 */
void gossip_store_append(struct gossip_store *gs, const u8 *msg);

/**
 * Retrieve the next gossip message if any
 *
 * @param ctx The context to allocate the message from
 * @param gs  The `gossip_store` to read from
 * @return The gossip message allocated from `ctx`, `NULL` if no more messages are
 *         available.
 */
const u8 *gossip_store_read_next(const tal_t *ctx, struct routing_state *rstate,
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
