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
	u32 blocknum : 24;
	u32 txnum : 24;
	u16 outnum;
};

bool short_channel_id_from_str(const char *str, size_t strlen,
			       struct short_channel_id *dst);

bool short_channel_id_eq(const struct short_channel_id *a,
			 const struct short_channel_id *b);

char *short_channel_id_to_str(const tal_t *ctx, const struct short_channel_id *scid);

/* Fast, platform dependent, way to convert from a short_channel_id to u64 */
u64 short_channel_id_to_uint(const struct short_channel_id *scid);

#endif /* LIGHTNING_BITCOIN_SHORT_CHANNEL_ID_H */
