#ifndef LIGHTNING_DAEMON_BROADCAST_H
#define LIGHTNING_DAEMON_BROADCAST_H
#include "config.h"

#include <ccan/intmap/intmap.h>
#include <ccan/list/list.h>
#include <ccan/short_types/short_types.h>
#include <ccan/tal/tal.h>

/* Common functionality to implement staggered broadcasts with replacement. */

struct queued_message {
	int type;

	/* Unique tag specifying the msg origin */
	void *tag;

	/* Serialized payload */
	u8 *payload;
};

struct broadcast_state {
u32 next_index;
UINTMAP(struct queued_message *) broadcasts;
};

struct broadcast_state *new_broadcast_state(tal_t *ctx);

/* Queue a new message to be broadcast and replace any outdated
 * broadcast. Replacement is done by comparing the `type` and the
 * `tag`, if both match the old message is dropped from the queue. The
 * new message is added to the top of the broadcast queue. */
void queue_broadcast(struct broadcast_state *bstate,
			     const int type,
			     const u8 *tag,
			     const u8 *payload);

struct queued_message *next_broadcast_message(struct broadcast_state *bstate, u64 *last_index);

#endif /* LIGHTNING_DAEMON_BROADCAST_H */
