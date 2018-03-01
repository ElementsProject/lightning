#ifndef LIGHTNING_BITCOIN_SHORT_CHANNEL_ID_H
#define LIGHTNING_BITCOIN_SHORT_CHANNEL_ID_H
#include "config.h"
#include <ccan/short_types/short_types.h>
#include <ccan/tal/tal.h>
#include <stdbool.h>
#include <stddef.h>

/* Short Channel ID is composed of 3 bytes for the block height, 3
 * bytes of tx index in block and 2 bytes of output index. The
 * bitfield is mainly for unit tests where it is nice to be able to
 * just memset them and not have to take care about the extra byte for
 * u32 */
struct short_channel_id {
	u64 u64;
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

void mk_short_channel_id(struct short_channel_id *scid,
			 u32 blocknum, u32 txnum, u16 outnum);

bool short_channel_id_from_str(const char *str, size_t strlen,
			       struct short_channel_id *dst);

/* Fast, platform dependent, way to convert from a short_channel_id to u64 */
static inline u64 short_channel_id_to_uint(const struct short_channel_id *scid)
{
	return scid->u64;
}

char *short_channel_id_to_str(const tal_t *ctx, const struct short_channel_id *scid);

#endif /* LIGHTNING_BITCOIN_SHORT_CHANNEL_ID_H */
