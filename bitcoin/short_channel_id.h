#ifndef LIGHTNING_BITCOIN_SHORT_CHANNEL_ID_H
#define LIGHTNING_BITCOIN_SHORT_CHANNEL_ID_H
#include "config.h"
#include <ccan/compiler/compiler.h>
#include <ccan/short_types/short_types.h>
#include <ccan/tal/tal.h>
#include <common/gossip_constants.h>

/* Short Channel ID is composed of 3 bytes for the block height, 3
 * bytes of tx index in block and 2 bytes of output index. */
struct short_channel_id {
	u64 u64;
};

static inline bool short_channel_id_eq(struct short_channel_id a,
				       struct short_channel_id b)
{
	return a.u64 == b.u64;
}

static inline size_t short_channel_id_hash(struct short_channel_id scid)
{
	/* scids cost money to generate, so simple hash works here */
	return (scid.u64 >> 32) ^ (scid.u64 >> 16) ^ scid.u64;
}

/* BOLT #7:
 *
 * - MUST set `node_id_1` and `node_id_2` to the public keys of the two nodes
 * operating the channel, such that `node_id_1` is the lexicographically-lesser of the
 * two compressed keys sorted in ascending lexicographic order.
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

static inline bool short_channel_id_dir_eq(const struct short_channel_id_dir *a,
					   const struct short_channel_id_dir *b)
{
	return short_channel_id_eq(a->scid, b->scid) && a->dir == b->dir;
}

static inline u32 short_channel_id_blocknum(struct short_channel_id scid)
{
	return scid.u64 >> 40;
}

static inline bool is_stub_scid(struct short_channel_id scid)
{
	return scid.u64 >> 40 == 1 &&
		((scid.u64 >> 16) & 0x00FFFFFF) == 1 &&
		(scid.u64 & 0xFFFF) == 1;
}

static inline u32 short_channel_id_txnum(struct short_channel_id scid)
{
	return (scid.u64 >> 16) & 0x00FFFFFF;
}

static inline u16 short_channel_id_outnum(struct short_channel_id scid)
{
	return scid.u64 & 0xFFFF;
}

/* Subtly, at block N, depth is 1, hence the -1 here. eg. 103x1x0 is announceable
 * when height is 108. */
static inline bool
is_scid_depth_announceable(struct short_channel_id scid,
			  unsigned int height)
{
	return short_channel_id_blocknum(scid) + ANNOUNCE_MIN_DEPTH - 1
		<= height;
}

/* Returns false if blocknum, txnum or outnum require too many bits */
bool WARN_UNUSED_RESULT mk_short_channel_id(struct short_channel_id *scid,
					    u64 blocknum, u64 txnum, u64 outnum);

bool WARN_UNUSED_RESULT short_channel_id_from_str(const char *str, size_t strlen,
						  struct short_channel_id *dst);

bool WARN_UNUSED_RESULT short_channel_id_dir_from_str(const char *str, size_t strlen,
						      struct short_channel_id_dir *scidd);

char *fmt_short_channel_id(const tal_t *ctx, struct short_channel_id scid);
char *fmt_short_channel_id_dir(const tal_t *ctx,
			       const struct short_channel_id_dir *scidd);

/* Marshal/unmarshal */
void towire_short_channel_id(u8 **pptr,
			     struct short_channel_id short_channel_id);
struct short_channel_id fromwire_short_channel_id(const u8 **cursor, size_t *max);

#endif /* LIGHTNING_BITCOIN_SHORT_CHANNEL_ID_H */
