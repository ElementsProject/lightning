#include "config.h"
#include <ccan/cast/cast.h>
#include <common/decode_array.h>
#include <wire/peer_wire.h>
#include <zlib.h>

static u8 *unzlib(const tal_t *ctx, const u8 *encoded, size_t len)
{
	/* http://www.zlib.net/zlib_tech.html gives 1032:1 as worst-case,
	 * which is 67632120 bytes for us.  But they're not encoding zeroes,
	 * and each scid must be unique.  So 1MB is far more reasonable. */
	unsigned long unclen = 1024*1024;
	int zerr;
	u8 *unc = tal_arr(ctx, u8, unclen);

	zerr = uncompress(unc, &unclen, encoded, len);
	if (zerr != Z_OK)
		return tal_free(unc);

	/* Truncate and return. */
	tal_resize(&unc, unclen);
	return unc;
}

struct short_channel_id *decode_short_ids(const tal_t *ctx, const u8 *encoded)
{
	struct short_channel_id *scids;
	size_t max = tal_count(encoded);
	enum arr_encode_types type;

	/* BOLT #7:
	 *
	 * The receiver:
	 *   - if the first byte of `encoded_short_ids` is not a known encoding
	 *     type:
	 *     - MAY fail the connection
	 *   - if `encoded_short_ids` does not decode into a whole number of
	 *     `short_channel_id`:
	 *     - MAY fail the connection
	 */
	type = fromwire_u8(&encoded, &max);
	switch (type) {
	case ARR_ZLIB:
		encoded = unzlib(tmpctx, encoded, max);
		if (!encoded)
			return NULL;
		max = tal_count(encoded);
		/* fall thru */
	case ARR_UNCOMPRESSED:
		scids = tal_arr(ctx, struct short_channel_id, 0);
		while (max) {
			struct short_channel_id scid;
			fromwire_short_channel_id(&encoded, &max, &scid);
			tal_arr_expand(&scids, scid);
		}

		/* encoded is set to NULL if we ran over */
		if (!encoded)
			return tal_free(scids);
		return scids;
	}
	return NULL;
}

bigsize_t *decode_scid_query_flags(const tal_t *ctx,
				   const struct tlv_query_short_channel_ids_tlvs_query_flags *qf)
{
	u8 *encoded = qf->encoded_query_flags;
	size_t max = tal_count(encoded);
	bigsize_t *flags;

	/* BOLT #7:
	 *
	 * The receiver:
	 *...
	 *  - if the incoming message includes `query_short_channel_ids_tlvs`:
	 *    - if `encoding_type` is not a known encoding type:
	 *      - MAY fail the connection
	 *    - if `encoded_query_flags` does not decode to exactly one flag per
	 *      `short_channel_id`:
	 *      - MAY fail the connection.
	 */
	switch (qf->encoding_type) {
	case ARR_ZLIB:
		encoded = unzlib(tmpctx, encoded, max);
		if (!encoded)
			return NULL;
		max = tal_count(encoded);
		/* fall thru */
	case ARR_UNCOMPRESSED:
		flags = tal_arr(ctx, bigsize_t, 0);
		while (max)
			tal_arr_expand(&flags,
				       fromwire_bigsize(cast_const2(const u8 **,
								    &encoded),
							&max));

		/* encoded is set to NULL if we ran over */
		if (!encoded)
			return tal_free(flags);
		return flags;
	}
	return NULL;
}

struct channel_update_timestamps *
decode_channel_update_timestamps(const tal_t *ctx,
				 const struct tlv_reply_channel_range_tlvs_timestamps_tlv *timestamps_tlv)
{
	/* Note that our parser will set this to NULL if there are no elements */
	u8 *encoded = timestamps_tlv->encoded_timestamps;
	size_t max = tal_count(encoded);
	struct channel_update_timestamps *ts;

	/* FIXME: BOLT #7 should have a requirements like it does for
	 * query_short_channel_ids_tlvs! */
	switch (timestamps_tlv->encoding_type) {
	case ARR_ZLIB:
		encoded = unzlib(tmpctx, encoded, max);
		if (!encoded)
			return NULL;
		max = tal_count(encoded);
		/* fall thru */
	case ARR_UNCOMPRESSED:
		ts = tal_arr(ctx, struct channel_update_timestamps, 0);
		while (max) {
			struct channel_update_timestamps t;
			fromwire_channel_update_timestamps
				(cast_const2(const u8 **, &encoded),
				 &max, &t);
			/* Sets this to NULL if it fails */
			if (!encoded)
				return tal_free(ts);
			tal_arr_expand(&ts, t);
		}
		return ts;
	}
	return NULL;
}
