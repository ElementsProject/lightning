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
struct broadcastable;
struct daemon;
struct routing_state;

struct gossip_store *gossip_store_new(struct daemon *daemon);

/**
 * Load the initial gossip store, if any.
 *
 * @param gs  The `gossip_store` to read from
 *
 * Returns the last-modified time of the store, or 0 if it was created new.
 */
u32 gossip_store_load(struct gossip_store *gs);

/**
 * Add a gossip message to the gossip_store (and optional addendum)
 * @gs: gossip store
 * @gossip_msg: the gossip message to insert.
 * @timestamp: the timestamp for filtering of this messsage.
 * @dying: true if this message is for a dying channel.
 * @addendum: another message to append immediately after this
 *            (for appending amounts to channel_announcements for internal use).
 */
u64 gossip_store_add(struct gossip_store *gs, const u8 *gossip_msg,
		     u32 timestamp, bool dying,
		     const u8 *addendum);


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
 * record, not header, unlike bcast->index!).
 *
 * In developer mode, checks that type is correct.
 */
void gossip_store_flag(struct gossip_store *gs,
		       u64 offset,
		       u16 flag,
		       int type);

/**
 * Mark that the channel is about to be deleted, for convenience of
 * others mapping the gossip_store.
 */
void gossip_store_mark_channel_deleted(struct gossip_store *gs,
				       const struct short_channel_id *scid);

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
