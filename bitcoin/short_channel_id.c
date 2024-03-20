#include "config.h"
#include <bitcoin/short_channel_id.h>
#include <ccan/tal/str/str.h>
#include <common/type_to_string.h>
#include <stdio.h>
#include <wire/wire.h>

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


bool mk_short_channel_id(struct short_channel_id *scid,
			 u64 blocknum, u64 txnum, u64 outnum)
{
	if ((blocknum & 0xFFFFFF) != blocknum
	    || (txnum & 0xFFFFFF) != txnum
	    || (outnum & 0xFFFF) != outnum)
		return false;
	scid->u64 = (((u64)blocknum & 0xFFFFFF) << 40 |
		     ((u64)txnum & 0xFFFFFF) << 16 |
		     (outnum & 0xFFFF));
	return true;
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

	matches = sscanf(buf, "%ux%ux%hu", &blocknum, &txnum, &outnum);
	return matches == 3
		&& mk_short_channel_id(dst, blocknum, txnum, outnum);
}

char *fmt_short_channel_id(const tal_t *ctx, struct short_channel_id scid)
{
	return tal_fmt(ctx, "%dx%dx%d",
		       short_channel_id_blocknum(&scid),
		       short_channel_id_txnum(&scid),
		       short_channel_id_outnum(&scid));
}

bool short_channel_id_dir_from_str(const char *str, size_t strlen,
				   struct short_channel_id_dir *scidd)
{
	const char *slash = memchr(str, '/', strlen);
	if (!slash || slash + 2 != str + strlen)
		return false;
	if (!short_channel_id_from_str(str, slash - str, &scidd->scid))
		return false;
	if (slash[1] == '0')
		scidd->dir = 0;
	else if (slash[1] == '1')
		scidd->dir = 1;
	else
		return false;
	return true;
}

char *fmt_short_channel_id_dir(const tal_t *ctx,
			       const struct short_channel_id_dir *scidd)
{
	char *str, *scidstr = fmt_short_channel_id(NULL, scidd->scid);
	str = tal_fmt(ctx, "%s/%u", scidstr, scidd->dir);
	tal_free(scidstr);
	return str;
}

static char *fmt_short_channel_id_ptr(const tal_t *ctx,
				      const struct short_channel_id *scid)
{
	return fmt_short_channel_id(ctx, *scid);
}

REGISTER_TYPE_TO_STRING(short_channel_id, fmt_short_channel_id_ptr);
REGISTER_TYPE_TO_STRING(short_channel_id_dir, fmt_short_channel_id_dir);

void towire_short_channel_id(u8 **pptr,
			     const struct short_channel_id *short_channel_id)
{
	towire_u64(pptr, short_channel_id->u64);
}

void fromwire_short_channel_id(const u8 **cursor, size_t *max,
			       struct short_channel_id *short_channel_id)
{
	short_channel_id->u64 = fromwire_u64(cursor, max);
}
