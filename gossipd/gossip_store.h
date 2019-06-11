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

struct gossip_store *gossip_store_new(struct routing_state *rstate,
				      struct list_head *peers);

/**
 * Load the initial gossip store, if any.
 *
 * @param rstate The routing state to load init.
 * @param gs  The `gossip_store` to read from
 *
 * Returns true if the store seems fully populated.
 */
bool gossip_store_load(struct routing_state *rstate, struct gossip_store *gs);

/**
 * Add a private channel_update message to the gossip_store
 */
u64 gossip_store_add_private_update(struct gossip_store *gs, const u8 *update);

/**
 * Add a gossip message to the gossip_store (and optional addendum)
 */
u64 gossip_store_add(struct gossip_store *gs, const u8 *gossip_msg,
		     u32 timestamp, const u8 *addendum);


/**
 * Delete the broadcast associated with this (if any).
 *
 * In developer mode, checks that type is correct.
 */
void gossip_store_delete(struct gossip_store *gs,
			 struct broadcastable *bcast,
			 int type);

/**
 * Direct store accessor: loads gossip msg back from store.
 *
 * Caller must ensure offset != 0.  Never returns NULL.
 */
const u8 *gossip_store_get(const tal_t *ctx,
			   struct gossip_store *gs,
			   u64 offset);

/**
 * Direct store accessor: loads private gossip msg back from store.
 *
 * Caller must ensure offset != 0.  Never returns NULL.
 */
const u8 *gossip_store_get_private_update(const tal_t *ctx,
					  struct gossip_store *gs,
					  u64 offset);

/* Exposed for dev-compact-gossip-store to force compaction. */
bool gossip_store_compact(struct gossip_store *gs);

/**
 * Get a readonly fd for the gossip_store.
 * @gs: the gossip store.
 *
 * Returns -1 on failure, and sets errno.
 */
int gossip_store_readonly_fd(struct gossip_store *gs);

/* Callback inside gossipd when store is compacted */
void update_peers_broadcast_index(struct list_head *peers, u32 offset);

#endif /* LIGHTNING_GOSSIPD_GOSSIP_STORE_H */
