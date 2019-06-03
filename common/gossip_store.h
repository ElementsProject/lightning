#ifndef LIGHTNING_COMMON_GOSSIP_STORE_H
#define LIGHTNING_COMMON_GOSSIP_STORE_H
#include "config.h"
#include <ccan/short_types/short_types.h>
#include <ccan/tal/tal.h>

/**
 * gossip_store -- On-disk storage related information
 */
#define GOSSIP_STORE_VERSION 5

/**
 * Bit of length we use to mark a deleted record.
 */
#define GOSSIP_STORE_LEN_DELETED_BIT 0x80000000U

/**
 * Direct store accessor: loads gossip msg from store.
 *
 * Doesn't return; status_failed() on error.
 */
u8 *gossip_store_read(const tal_t *ctx, int gossip_store_fd, u64 offset);

#endif /* LIGHTNING_COMMON_GOSSIP_STORE_H */
