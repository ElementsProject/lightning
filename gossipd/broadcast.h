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
};

struct broadcast_state *new_broadcast_state(tal_t *ctx);

/* Append a queued message for broadcast.  Freeing the msg will remove it. */
void insert_broadcast(struct broadcast_state *bstate, const u8 *msg);

/* Return the broadcast with index >= *last_index, and update *last_index.
 * There's no broadcast with index 0. */
const u8 *next_broadcast(struct broadcast_state *bstate, u64 *last_index);
#endif /* LIGHTNING_GOSSIPD_BROADCAST_H */
