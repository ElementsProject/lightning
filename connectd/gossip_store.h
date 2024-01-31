#ifndef LIGHTNING_CONNECTD_GOSSIP_STORE_H
#define LIGHTNING_CONNECTD_GOSSIP_STORE_H
#include "config.h"
#include <common/gossip_store.h>

/**
 * Direct store accessor: loads gossip msg from store.
 *
 * Returns NULL if there are no more gossip msgs.
 * Updates *end if the known end of file has moved.
 * Updates *gossip_store_fd if file has been compacted.
 */
u8 *gossip_store_next(const tal_t *ctx,
		      int *gossip_store_fd,
		      u32 timestamp_min, u32 timestamp_max,
		      size_t *off, size_t *end);

/**
 * Return offset of first entry >= this timestamp.
 */
size_t find_gossip_store_by_timestamp(int gossip_store_fd,
				      size_t off,
				      u32 timestamp);

#endif /* LIGHTNING_CONNECTD_GOSSIP_STORE_H */
