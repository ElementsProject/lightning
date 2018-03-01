#include <bitcoin/short_channel_id.h>
#include <ccan/tal/str/str.h>
#include <stdio.h>
#include <string.h>

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

	matches = sscanf(buf, "%u:%u:%hu", &blocknum, &txnum, &outnum);
	mk_short_channel_id(dst, blocknum, txnum, outnum);
	return matches == 3;
}

char *short_channel_id_to_str(const tal_t *ctx, const struct short_channel_id *scid)
{
	return tal_fmt(ctx, "%d:%d:%d",
		       short_channel_id_blocknum(scid),
		       short_channel_id_txnum(scid),
		       short_channel_id_outnum(scid));
}
