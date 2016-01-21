#include "bitcoin/locktime.h"
#include <assert.h>

/* Alpha uses simple locktimes a-la the tx locktime field; BIP68 uses
 * a bitmask */
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
#ifdef HAS_BIP68
	if ((seconds >> BIP68_SECONDS_SHIFT) > BIP68_LOCKTIME_MASK)
		return false;
	rel->locktime = BIP68_SECONDS_FLAG | (seconds >> BIP68_SECONDS_SHIFT);
	return true;
#else
	/* Make abs-style time by adding SECONDS_POINT. */
	return abs_seconds_to_locktime(seconds + SECONDS_POINT, &rel->locktime);
#endif
}

bool blocks_to_rel_locktime(u32 blocks, struct rel_locktime *rel)
{
#ifdef HAS_BIP68
	if (blocks > BIP68_LOCKTIME_MASK)
		return false;
#endif
	rel->locktime = blocks;
	return true;
}

bool rel_locktime_is_seconds(const struct rel_locktime *rel)
{
#ifdef HAS_BIP68
	return rel->locktime & BIP68_SECONDS_FLAG;
#else
	return abs_is_seconds(rel->locktime);
#endif
}

u32 rel_locktime_to_seconds(const struct rel_locktime *rel)
{
	assert(rel_locktime_is_seconds(rel));
#ifdef HAS_BIP68
	return rel->locktime & BIP68_LOCKTIME_MASK;
#else
	return rel->locktime - SECONDS_POINT;
#endif
}

u32 rel_locktime_to_blocks(const struct rel_locktime *rel)
{
	assert(!rel_locktime_is_seconds(rel));
#ifdef HAS_BIP68
	return rel->locktime & BIP68_LOCKTIME_MASK;
#else
	return rel->locktime;
#endif
}

u32 bitcoin_nsequence(const struct rel_locktime *rel)
{
#ifdef HAS_BIP68
	/* Can't set disable bit, or other bits except low 16 and bit 22 */
	assert(!(rel->locktime & ~(BIP68_SECONDS_FLAG|BIP68_LOCKTIME_MASK)));
	return rel->locktime;
#else
	/* Alpha uses the original proposal: simply invert the bits. */
	return ~rel->locktime;
#endif
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
