#include <common/decode_short_channel_ids.h>
#include <common/utils.h>
#include <wire/wire.h>
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
	size_t max = tal_count(encoded), n;
	enum scid_encode_types type;

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
	case SHORTIDS_ZLIB:
		encoded = unzlib(tmpctx, encoded, max);
		if (!encoded)
			return NULL;
		max = tal_count(encoded);
		/* fall thru */
	case SHORTIDS_UNCOMPRESSED:
		n = 0;
		scids = tal_arr(ctx, struct short_channel_id, n);
		while (max) {
			tal_resize(&scids, n+1);
			fromwire_short_channel_id(&encoded, &max, &scids[n++]);
		}

		/* encoded is set to NULL if we ran over */
		if (!encoded)
			return tal_free(scids);
		return scids;
	}
	return NULL;
}
