#ifndef LIGHTNING_COMMON_DECODE_SHORT_CHANNEL_IDS_H
#define LIGHTNING_COMMON_DECODE_SHORT_CHANNEL_IDS_H
#include "config.h"
#include <ccan/short_types/short_types.h>
#include <ccan/tal/tal.h>

/* BOLT #7:
 *
 * Encoding types:
 * * `0`: uncompressed array of `short_channel_id` types, in ascending order.
 * * `1`: array of `short_channel_id` types, in ascending order, compressed with zlib deflate<sup>[1](#reference-1)</sup>
 */
enum scid_encode_types {
	SHORTIDS_UNCOMPRESSED = 0,
	SHORTIDS_ZLIB = 1
};

struct short_channel_id *decode_short_ids(const tal_t *ctx, const u8 *encoded);
#endif /* LIGHTNING_COMMON_DECODE_SHORT_CHANNEL_IDS_H */
