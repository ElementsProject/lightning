#ifndef LIGHTNING_GOSSIPD_BROADCAST_H
#define LIGHTNING_GOSSIPD_BROADCAST_H
#include "config.h"

#include <ccan/intmap/intmap.h>
#include <ccan/list/list.h>
#include <ccan/short_types/short_types.h>
#include <ccan/tal/tal.h>

/* Common functionality to implement staggered broadcasts with replacement. */

struct routing_state;

struct broadcast_state {
	UINTMAP(struct queued_message *) broadcasts;
	size_t count;
	struct gossip_store *gs;
};

/* This is nested inside a node, chan or half_chan; rewriting the store can
 * cause it to change! */
struct broadcastable {
	/* This is also the offset within the gossip_store; even with 1M
	 * channels we still have a factor of 8 before this wraps. */
	u32 index;
	u32 timestamp;
};

static inline void broadcastable_init(struct broadcastable *bcast)
{
	bcast->index = 0;
}

struct broadcast_state *new_broadcast_state(struct routing_state *rstate);


/* Append a queued message for broadcast.  Must be explicitly deleted.
 * Also adds it to the gossip store. */
void insert_broadcast(struct broadcast_state **bstate,
		      const u8 *msg,
		      struct broadcastable *bcast);

/* Add to broadcast, but not store: for gossip store compaction. */
void insert_broadcast_nostore(struct broadcast_state *bstate,
			      const u8 *msg,
			      struct broadcastable *bcast);

/* Delete a broadcast: not usually needed, since destructor does it */
void broadcast_del(struct broadcast_state *bstate,
		   struct broadcastable *bcast);

/* Return the broadcast with index >= *last_index, timestamp >= min and <= max
 * and update *last_index.
 * There's no broadcast with index 0. */
const u8 *next_broadcast(struct broadcast_state *bstate,
			 u32 timestamp_min, u32 timestamp_max,
			 u32 *last_index);

/* index of last entry. */
u64 broadcast_final_index(const struct broadcast_state *bstate);

/* Return and remove first element: used by gossip_store_compact */
const u8 *pop_first_broadcast(struct broadcast_state *bstate,
			      struct broadcastable **bcast);

/* Returns b if all OK, otherwise aborts if abortstr non-NULL, otherwise returns
 * NULL. */
struct broadcast_state *broadcast_state_check(struct broadcast_state *b,
					      const char *abortstr);

#endif /* LIGHTNING_GOSSIPD_BROADCAST_H */
