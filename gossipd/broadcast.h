#ifndef LIGHTNING_GOSSIPD_BROADCAST_H
#define LIGHTNING_GOSSIPD_BROADCAST_H
#include "config.h"

#include <ccan/short_types/short_types.h>

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
#endif /* LIGHTNING_GOSSIPD_BROADCAST_H */
