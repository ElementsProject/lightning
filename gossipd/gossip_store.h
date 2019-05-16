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

struct broadcast_state;
struct gossip_store;
struct routing_state;

struct gossip_store *gossip_store_new(struct routing_state *rstate);

/**
 * Load the initial gossip store, if any.
 *
 * @param rstate The routing state to load init.
 * @param gs  The `gossip_store` to read from
 */
void gossip_store_load(struct routing_state *rstate, struct gossip_store *gs);

/**
 * Add a gossip message to the gossip_store (and optional addendum)
 */
u64 gossip_store_add(struct gossip_store *gs, const u8 *gossip_msg,
		     const u8 *addendum);


/**
 * Remember that we deleted a channel as a result of its outpoint being spent
 */
void gossip_store_add_channel_delete(struct gossip_store *gs,
				     const struct short_channel_id *scid);

/**
 * Direct store accessor: loads gossip msg back from store.
 *
 * Caller must ensure offset != 0.  Never returns NULL.
 */
const u8 *gossip_store_get(const tal_t *ctx,
			   struct gossip_store *gs,
			   u64 offset);

/**
 * If we need to compact the gossip store, do so.
 * @gs: the gossip store.
 * @bs: a pointer to the broadcast state: replaced if we compact it.
 * @offset: the change in the store, if any.
 *
 * If return value is true, caller must update peers.
 */
bool gossip_store_maybe_compact(struct gossip_store *gs,
				struct broadcast_state **bs,
				u32 *offset);


/* Expose for dev-compact-gossip-store to force compaction. */
bool gossip_store_compact(struct gossip_store *gs,
			  struct broadcast_state **bs,
			  u32 *offset);

/**
 * Get a readonly fd for the gossip_store.
 * @gs: the gossip store.
 *
 * Returns -1 on failure, and sets errno.
 */
int gossip_store_readonly_fd(struct gossip_store *gs);

#endif /* LIGHTNING_GOSSIPD_GOSSIP_STORE_H */
