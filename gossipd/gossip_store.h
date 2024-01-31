#ifndef LIGHTNING_GOSSIPD_GOSSIP_STORE_H
#define LIGHTNING_GOSSIPD_GOSSIP_STORE_H

#include "config.h"

#include <bitcoin/short_channel_id.h>
#include <ccan/list/list.h>
#include <ccan/short_types/short_types.h>
#include <ccan/tal/tal.h>

/**
 * gossip_store -- On-disk storage related information
 */

struct gossip_store;
struct daemon;

/* For channels we find dying in the store, on load.  They are < 12
 * blocks closed. */
struct chan_dying {
	struct short_channel_id scid;
	/* Offset of dying marker in the gossip_store */
	u64 gossmap_offset;
	/* Blockheight where it's supposed to be deleted. */
	u32 deadline;
};

/**
 * Load the gossip_store
 * @ctx: the context to allocate from
 * @daemon: the daemon context
 * @populated: set to false if store is empty/obviously partial.
 * @dying: an array of channels we found dying markers for.
 */
struct gossip_store *gossip_store_new(const tal_t *ctx,
				      struct daemon *daemon,
				      bool *populated,
				      struct chan_dying **dying);

/**
 * Get the fd from the gossip_store.
 * @gs: the gossip_store.
 *
 * Used by gossmap_manage to create a gossmap.
 */
int gossip_store_get_fd(const struct gossip_store *gs);

/**
 * Get the (refreshed!) gossmap from the gossip_store.
 * @gs: gossip store
 */
struct gossmap *gossip_store_gossmap(struct gossip_store *gs);

/**
 * Append a gossip message to the gossip_store
 * @gs: gossip store
 * @gossip_msg: the gossip message to insert.
 * @timestamp: the timestamp for filtering of this messsage.
 */
u64 gossip_store_add(struct gossip_store *gs,
		     const u8 *gossip_msg,
		     u32 timestamp);


/**
 * Delete the record at this offset (offset is that of
 * record, not header, unlike bcast->index!).
 *
 * In developer mode, checks that type is correct.
 */
void gossip_store_del(struct gossip_store *gs,
		      u64 offset,
		      int type);

/**
 * Add a flag the record at this offset (offset is that of
 * record!).  Returns offset of *next* record.
 *
 * In developer mode, checks that type is correct.
 */
u64 gossip_store_set_flag(struct gossip_store *gs,
		       u64 offset, u16 flag, int type);

/**
 * Direct store accessor: get timestamp header for a record.
 *
 * Offset is *after* the header.
 */
u32 gossip_store_get_timestamp(struct gossip_store *gs, u64 offset);

/**
 * Direct store accessor: set timestamp header for a record.
 *
 * Offset is *after* the header.
 */
void gossip_store_set_timestamp(struct gossip_store *gs, u64 offset, u32 timestamp);

#endif /* LIGHTNING_GOSSIPD_GOSSIP_STORE_H */
