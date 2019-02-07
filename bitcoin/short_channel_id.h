#ifndef LIGHTNING_BITCOIN_SHORT_CHANNEL_ID_H
#define LIGHTNING_BITCOIN_SHORT_CHANNEL_ID_H
#include "config.h"
#include <ccan/short_types/short_types.h>
#include <ccan/structeq/structeq.h>
#include <ccan/tal/tal.h>
#include <stdbool.h>
#include <stddef.h>

/* Short Channel ID is composed of 3 bytes for the block height, 3
 * bytes of tx index in block and 2 bytes of output index. */
struct short_channel_id {
	u64 u64;
};
/* Define short_channel_id_eq (no padding) */
STRUCTEQ_DEF(short_channel_id, 0, u64);

/* BOLT #7:
 *
 * - MUST set `node_id_1` and `node_id_2` to the public keys of the two nodes
 * operating the channel, such that `node_id_1` is the numerically-lesser of the
 * two DER-encoded keys sorted in ascending numerical order.
 *...
 *   - if the origin node is `node_id_1` in the message:
 *     - MUST set the `direction` bit of `channel_flags` to 0.
 *   - otherwise:
 *     - MUST set the `direction` bit of `channel_flags` to 1.
 */
struct short_channel_id_dir {
	struct short_channel_id scid;
	/* 0 == from lesser id node, 1 == to lesser id node */
	int dir;
};

static inline u32 short_channel_id_blocknum(const struct short_channel_id *scid)
{
	return scid->u64 >> 40;
}

static inline u32 short_channel_id_txnum(const struct short_channel_id *scid)
{
	return (scid->u64 >> 16) & 0x00FFFFFF;
}

static inline u16 short_channel_id_outnum(const struct short_channel_id *scid)
{
	return scid->u64 & 0xFFFF;
}

/* Returns false if blocknum, txnum or outnum require too many bits */
bool WARN_UNUSED_RESULT mk_short_channel_id(struct short_channel_id *scid,
					    u64 blocknum, u64 txnum, u64 outnum);

/* may_be_deprecated_form allows : separators if COMPAT defined */
bool WARN_UNUSED_RESULT short_channel_id_from_str(const char *str, size_t strlen,
						  struct short_channel_id *dst,
						  bool may_be_deprecated_form);

char *short_channel_id_to_str(const tal_t *ctx, const struct short_channel_id *scid);

bool WARN_UNUSED_RESULT short_channel_id_dir_from_str(const char *str, size_t strlen,
						      struct short_channel_id_dir *scidd,
						      bool may_be_deprecated_form);

char *short_channel_id_dir_to_str(const tal_t *ctx,
				  const struct short_channel_id_dir *scidd);

#endif /* LIGHTNING_BITCOIN_SHORT_CHANNEL_ID_H */
