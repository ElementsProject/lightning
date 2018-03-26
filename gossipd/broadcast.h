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

/* Replace a queued message with @index, if it matches the type and
 * tag for the new message. The new message will be queued with the
 * next highest index. @index is updated to hold the index of the
 * newly queued message*/
bool replace_broadcast(const tal_t *ctx,
		       struct broadcast_state *bstate,
		       u64 *index,
		       const u8 *payload TAKES);


const u8 *next_broadcast(struct broadcast_state *bstate, u64 *last_index);

const u8 *get_broadcast(struct broadcast_state *bstate, u64 msgidx);
#endif /* LIGHTNING_GOSSIPD_BROADCAST_H */
