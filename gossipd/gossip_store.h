#ifndef LIGHTNING_GOSSIPD_GOSSIP_STORE_H
#define LIGHTNING_GOSSIPD_GOSSIP_STORE_H

#include "config.h"

#include <bitcoin/short_channel_id.h>
#include <ccan/list/list.h>
#include <ccan/short_types/short_types.h>
#include <ccan/tal/tal.h>
#include <gossipd/routing.h>

/**
 * gossip_store -- On-disk storage related information
 */

struct gossip_store;
struct routing_state;

struct gossip_store *gossip_store_new(struct routing_state *rstate);

/**
 * Load the initial gossip store, if any.
 *
 * @param rstate The routing state to load init.
 * @param gs  The `gossip_store` to read from
 *
 * Returns the last-modified time of the store, or 0 if it was created new.
 */
u32 gossip_store_load(struct routing_state *rstate, struct gossip_store *gs);

/**
 * Add a gossip message to the gossip_store (and optional addendum)
 * @gs: gossip store
 * @gossip_msg: the gossip message to insert.
 * @timestamp: the timestamp for filtering of this messsage.
 * @zombie: true if this channel is missing a current channel_update.
 * @spam: true if this message is rate-limited and squelched to peers.
 * @dying: true if this message is for a dying channel.
 * @addendum: another message to append immediately after this
 *            (for appending amounts to channel_announcements for internal use).
 */
u64 gossip_store_add(struct gossip_store *gs, const u8 *gossip_msg,
		     u32 timestamp, bool zombie, bool spam, bool dying,
		     const u8 *addendum);


/**
 * Delete the broadcast associated with this (if any).
 *
 * In developer mode, checks that type is correct.
 */
void gossip_store_delete(struct gossip_store *gs,
			 struct broadcastable *bcast,
			 int type);

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

/*
 * Marks the length field of a channel announcement with a zombie flag bit.
 * This allows the channel_announcement to be retained in the store while
 * waiting for channel updates to reactivate it.
 */
void gossip_store_mark_channel_zombie(struct gossip_store *gs,
				      struct broadcastable *bcast);

void gossip_store_mark_cupdate_zombie(struct gossip_store *gs,
				      struct broadcastable *bcast);

/**
 * Mark this channel_announcement/channel_update as dying.
 *
 * We'll clean it up in 12 blocks, but this tells connectd not to gossip
 * about it.
 */
void gossip_store_mark_dying(struct gossip_store *gs,
			     const struct broadcastable *bcast,
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

/* Exposed for dev-compact-gossip-store to force compaction. */
bool gossip_store_compact(struct gossip_store *gs);

/**
 * Get a readonly fd for the gossip_store.
 * @gs: the gossip store.
 *
 * Returns -1 on failure, and sets errno.
 */
int gossip_store_readonly_fd(struct gossip_store *gs);

#endif /* LIGHTNING_GOSSIPD_GOSSIP_STORE_H */
