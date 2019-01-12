#include <bitcoin/short_channel_id.h>
#include <ccan/tal/str/str.h>
#include <stdio.h>
#include <string.h>

/* BOLT#07:
 *
 * The `short_channel_id` is the unique description of the funding
 * transaction. It is constructed as follows:

 * 1. the most significant 3 bytes: indicating the block height
 * 2. the next 3 bytes: indicating the transaction index within the block
 * 3. the least significant 2 bytes: indicating the output index that pays to the channel.
 *
 * The standard human readable format for `short_channel_id` is created
 * by printing the above components, in the order: block height,
 * transaction index, and output index. Each component is printed as a
 * decimal number, and separated from each other by the small letter
 * `x`. For example, a `short_channel_id` might be written as
 * `539268x845x1`, indicating a channel on the output 1 of the
 * transaction at index 845 of the block at height 539268.
*/


void mk_short_channel_id(struct short_channel_id *scid,
			 u32 blocknum, u32 txnum, u16 outnum)
{
	scid->u64 = (((u64)blocknum & 0xFFFFFF) << 40 |
		     ((u64)txnum & 0xFFFFFF) << 16 |
		     (outnum & 0xFFFF));
}

bool short_channel_id_from_str(const char *str, size_t strlen,
			       struct short_channel_id *dst)
{
	u32 blocknum, txnum;
	u16 outnum;
	int matches;

	char buf[strlen + 1];
	memcpy(buf, str, strlen);
	buf[strlen] = 0;

#ifdef COMPAT_V062
	/* Pre-adelaide format vs. post-adelaide format */
	if (strchr(buf, ':'))
		matches = sscanf(buf, "%u:%u:%hu", &blocknum, &txnum, &outnum);
	else
		matches = sscanf(buf, "%ux%ux%hu", &blocknum, &txnum, &outnum);
#else
	matches = sscanf(buf, "%ux%ux%hu", &blocknum, &txnum, &outnum);
#endif
	mk_short_channel_id(dst, blocknum, txnum, outnum);
	return matches == 3;
}

char *short_channel_id_to_str(const tal_t *ctx, const struct short_channel_id *scid)
{
	return tal_fmt(ctx, "%dx%dx%d",
		       short_channel_id_blocknum(scid),
		       short_channel_id_txnum(scid),
		       short_channel_id_outnum(scid));
}
