#include <bitcoin/short_channel_id.h>
#include <ccan/tal/str/str.h>
#include <stdio.h>
#include <string.h>

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
	dst->blocknum = blocknum;
	dst->txnum = txnum;
	dst->outnum = outnum;
	return matches == 3;
}

char *short_channel_id_to_str(const tal_t *ctx, const struct short_channel_id *scid)
{
	return tal_fmt(ctx, "%d:%d:%d", scid->blocknum, scid->txnum, scid->outnum);
}

bool short_channel_id_eq(const struct short_channel_id *a,
			 const struct short_channel_id *b)
{
	return a->blocknum == b->blocknum && a->txnum == b->txnum &&
	       a->outnum == b->outnum;
}
