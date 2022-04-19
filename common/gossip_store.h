#ifndef LIGHTNING_COMMON_GOSSIP_STORE_H
#define LIGHTNING_COMMON_GOSSIP_STORE_H
#include "config.h"
#include <ccan/endian/endian.h>
#include <ccan/short_types/short_types.h>
#include <ccan/tal/tal.h>

struct gossip_state;
struct gossip_rcvd_filter;

/**
 * gossip_store -- On-disk storage related information
 */
#define GOSSIP_STORE_VERSION 9

/**
 * Bit of length we use to mark a deleted record.
 */
#define GOSSIP_STORE_LEN_DELETED_BIT 0x80000000U

/**
 * Bit of length we use to mark an important record.
 */
#define GOSSIP_STORE_LEN_PUSH_BIT 0x40000000U

/* Mask for extracting just the length part of len field */
#define GOSSIP_STORE_LEN_MASK \
	(~(GOSSIP_STORE_LEN_PUSH_BIT | GOSSIP_STORE_LEN_DELETED_BIT))

/**
 * gossip_hdr -- On-disk format header.
 */
struct gossip_hdr {
	beint32_t len; /* Length of message after header. */
	beint32_t crc; /* crc of message of timestamp, after header. */
	beint32_t timestamp; /* timestamp of msg. */
};

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
		      bool push_only,
		      size_t *off, size_t *end);

/**
 * Gossipd will be writing to this, and it's not atomic!  Safest
 * way to find the "end" is to walk through.
 * @old_end: 1 if no previous end.
 */
size_t find_gossip_store_end(int gossip_store_fd, size_t old_end);

#endif /* LIGHTNING_COMMON_GOSSIP_STORE_H */
