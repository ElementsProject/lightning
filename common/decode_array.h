#ifndef LIGHTNING_COMMON_DECODE_ARRAY_H
#define LIGHTNING_COMMON_DECODE_ARRAY_H
#include "config.h"
#include <ccan/tal/tal.h>
#include <common/bigsize.h>

struct tlv_query_short_channel_ids_tlvs_query_flags;
struct tlv_reply_channel_range_tlvs_timestamps_tlv;

/* BOLT #7:
 *
 * Encoding types:
 * * `0`: uncompressed array of `short_channel_id` types, in ascending order.
 * * `1`: array of `short_channel_id` types, in ascending order, compressed with zlib deflate<sup>[1](#reference-1)</sup>
 */
enum arr_encode_types {
	ARR_UNCOMPRESSED = 0,
	ARR_ZLIB = 1
};

struct short_channel_id *decode_short_ids(const tal_t *ctx, const u8 *encoded);

/* BOLT #7:
 *
 * `encoded_query_flags` is an array of bitfields, one bigsize per bitfield,
 * one bitfield for each `short_channel_id`. Bits have the following meaning:
 *
 * | Bit Position  | Meaning                                  |
 * | ------------- | ---------------------------------------- |
 * | 0             | Sender wants `channel_announcement`      |
 * | 1             | Sender wants `channel_update` for node 1 |
 * | 2             | Sender wants `channel_update` for node 2 |
 * | 3             | Sender wants `node_announcement` for node 1 |
 * | 4             | Sender wants `node_announcement` for node 2 |
 */
enum scid_query_flag {
	SCID_QF_ANNOUNCE = 0x1,
	SCID_QF_UPDATE1 = 0x2,
	SCID_QF_UPDATE2 = 0x4,
	SCID_QF_NODE1 = 0x8,
	SCID_QF_NODE2 = 0x10,
};

bigsize_t *decode_scid_query_flags(const tal_t *ctx,
				   const struct tlv_query_short_channel_ids_tlvs_query_flags *qf);

struct channel_update_timestamps *decode_channel_update_timestamps(const tal_t *ctx,
				 const struct tlv_reply_channel_range_tlvs_timestamps_tlv *timestamps_tlv);

#endif /* LIGHTNING_COMMON_DECODE_ARRAY_H */
