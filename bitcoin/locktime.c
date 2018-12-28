#include <assert.h>
#include <bitcoin/locktime.h>
#include <ccan/tal/str/str.h>
#include <common/type_to_string.h>

#define SECONDS_POINT 500000000

#define BIP68_SECONDS_FLAG (1<<22)
#define BIP68_LOCKTIME_MASK (0x0000FFFF)
#define BIP68_SECONDS_SHIFT 9

static bool abs_blocks_to_locktime(u32 blocks, u32 *locktime)
{
	*locktime = blocks;
	if (*locktime >= SECONDS_POINT)
		return false;
	return true;
}

static bool abs_is_seconds(u32 locktime)
{
	return locktime >= SECONDS_POINT;
}

bool rel_locktime_is_seconds(const struct rel_locktime *rel)
{
	return rel->locktime & BIP68_SECONDS_FLAG;
}

u32 rel_locktime_to_seconds(const struct rel_locktime *rel)
{
	assert(rel_locktime_is_seconds(rel));
	return (rel->locktime & BIP68_LOCKTIME_MASK) << BIP68_SECONDS_SHIFT;
}

u32 rel_locktime_to_blocks(const struct rel_locktime *rel)
{
	assert(!rel_locktime_is_seconds(rel));
	return rel->locktime & BIP68_LOCKTIME_MASK;
}

bool blocks_to_abs_locktime(u32 blocks, struct abs_locktime *abs)
{
	return abs_blocks_to_locktime(blocks, &abs->locktime);
}

bool abs_locktime_is_seconds(const struct abs_locktime *abs)
{
	return abs_is_seconds(abs->locktime);
}

u32 abs_locktime_to_seconds(const struct abs_locktime *abs)
{
	assert(abs_locktime_is_seconds(abs));
	return abs->locktime;
}

u32 abs_locktime_to_blocks(const struct abs_locktime *abs)
{
	assert(!abs_locktime_is_seconds(abs));
	return abs->locktime;
}

static char *fmt_rel_locktime(const tal_t *ctx, const struct rel_locktime *rl)
{
	if (rel_locktime_is_seconds(rl))
		return tal_fmt(ctx, "+%usec", rel_locktime_to_seconds(rl));
	else
		return tal_fmt(ctx, "+%ublocks", rel_locktime_to_blocks(rl));
}

static char *fmt_abs_locktime(const tal_t *ctx, const struct abs_locktime *al)
{
	if (abs_locktime_is_seconds(al))
		return tal_fmt(ctx, "%usec", abs_locktime_to_seconds(al));
	else
		return tal_fmt(ctx, "%ublocks", abs_locktime_to_blocks(al));
}

REGISTER_TYPE_TO_STRING(rel_locktime, fmt_rel_locktime);
REGISTER_TYPE_TO_STRING(abs_locktime, fmt_abs_locktime);
