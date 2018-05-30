#ifndef LIGHTNING_GOSSIPD_BROADCAST_H
#define LIGHTNING_GOSSIPD_BROADCAST_H
#include "config.h"

#include <ccan/intmap/intmap.h>
#include <ccan/list/list.h>
#include <ccan/short_types/short_types.h>
#include <ccan/tal/tal.h>

/* Common functionality to implement staggered broadcasts with replacement. */

struct broadcast_state {
	u64 next_index;
	UINTMAP(struct queued_message *) broadcasts;
	size_t count;
};

struct broadcast_state *new_broadcast_state(tal_t *ctx);

/* Append a queued message for broadcast.  Freeing the msg will remove it. */
u64 insert_broadcast(struct broadcast_state *bstate, const u8 *msg,
		     u32 timestamp);

/* Manually delete a broadcast: not usually needed, since destructor does it */
void broadcast_del(struct broadcast_state *bstate, u64 index, const u8 *payload);

/* Return the broadcast with index >= *last_index, timestamp >= min and <= max
 * and update *last_index.
 * There's no broadcast with index 0. */
const u8 *next_broadcast(struct broadcast_state *bstate,
			 u32 timestamp_min, u32 timestamp_max,
			 u64 *last_index);

/* Returns b if all OK, otherwise aborts if abortstr non-NULL, otherwise returns
 * NULL. */
struct broadcast_state *broadcast_state_check(struct broadcast_state *b,
					      const char *abortstr);
#endif /* LIGHTNING_GOSSIPD_BROADCAST_H */
