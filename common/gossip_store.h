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

/* First byte of file is the version.
 *
 * Top three bits mean incompatible change.
 * As of this writing, major == 0, minor == 13.
 */
#define GOSSIP_STORE_MAJOR_VERSION_MASK 0xE0
#define GOSSIP_STORE_MINOR_VERSION_MASK 0x1F

/* Extract version from first byte */
#define GOSSIP_STORE_MAJOR_VERSION(verbyte) (((u8)(verbyte)) >> 5)
#define GOSSIP_STORE_MINOR_VERSION(verbyte) ((verbyte) & GOSSIP_STORE_MINOR_VERSION_MASK)

/**
 * Bit of flags we use to mark a deleted record.
 */
#define GOSSIP_STORE_DELETED_BIT 0x8000U

/**
 * Bit of flags we use to mark an important record.
 */
#define GOSSIP_STORE_PUSH_BIT 0x4000U

/**
 * Bit of flags used to mark a channel announcement closed (not deleted for 12 blocks)
 */
#define GOSSIP_STORE_DYING_BIT 0x0800U


/**
 * gossip_hdr -- On-disk format header.
 */
struct gossip_hdr {
	beint16_t flags; /* GOSSIP_STORE_xxx_BIT flags. */
	beint16_t len; /* Length of message after header. */
	beint32_t crc; /* crc of message of timestamp, after header. */
	beint32_t timestamp; /* timestamp of msg. */
};

/**
 * Direct store accessor: read gossip msg hdr from store.
 * @gossip_store_fd: the readable file descriptor
 * @off: the offset to read
 * @len (out): the length of the message (not including header)
 * @timestamp (out): if non-NULL, set to the timestamp.
 * @flags (out): if non-NULL, set to the flags.
 * @type (out): if non-NULL, set to the msg type.
 *
 * Returns false if there are no more gossip msgs.  If you
 * want to read the message, use gossip_store_next, if you
 * want to skip, simply add sizeof(gossip_hdr) + *len to *off.
 * Note: it's possible that entire record isn't there yet,
 * so gossip_store_next can fail.
 */
bool gossip_store_readhdr(int gossip_store_fd, size_t off,
			  size_t *len,
			  u32 *timestamp,
			  u16 *flags,
			  u16 *type);

/**
 * Gossipd will be writing to this, and it's not atomic!  Safest
 * way to find the "end" is to walk through.
 * @old_end: 1 if no previous end.
 */
size_t find_gossip_store_end(int gossip_store_fd, size_t old_end);
#endif /* LIGHTNING_COMMON_GOSSIP_STORE_H */
