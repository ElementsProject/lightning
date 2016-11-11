#include "bitcoin/locktime.h"
#include <assert.h>

#define SECONDS_POINT 500000000

#define BIP68_SECONDS_FLAG (1<<22)
#define BIP68_LOCKTIME_MASK (0x0000FFFF)
#define BIP68_SECONDS_SHIFT 9

static bool abs_seconds_to_locktime(u32 seconds, u32 *locktime)
{
	*locktime = seconds;
	if (*locktime < SECONDS_POINT)
		return false;
	return true;
}

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

bool seconds_to_rel_locktime(u32 seconds, struct rel_locktime *rel)
{
	if ((seconds >> BIP68_SECONDS_SHIFT) > BIP68_LOCKTIME_MASK)
		return false;
	rel->locktime = BIP68_SECONDS_FLAG | (seconds >> BIP68_SECONDS_SHIFT);
	return true;
}

bool blocks_to_rel_locktime(u32 blocks, struct rel_locktime *rel)
{
	if (blocks > BIP68_LOCKTIME_MASK)
		return false;
	rel->locktime = blocks;
	return true;
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

u32 bitcoin_nsequence(const struct rel_locktime *rel)
{
	/* Can't set disable bit, or other bits except low 16 and bit 22 */
	assert(!(rel->locktime & ~(BIP68_SECONDS_FLAG|BIP68_LOCKTIME_MASK)));
	return rel->locktime;
}

bool seconds_to_abs_locktime(u32 seconds, struct abs_locktime *abs)
{
	return abs_seconds_to_locktime(seconds, &abs->locktime);
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
