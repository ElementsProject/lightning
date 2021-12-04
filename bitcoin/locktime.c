#include "config.h"
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

bool blocks_to_abs_locktime(u32 blocks, struct abs_locktime *abs)
{
	return abs_blocks_to_locktime(blocks, &abs->locktime);
}

u32 abs_locktime_to_blocks(const struct abs_locktime *abs)
{
	assert(!abs_is_seconds(abs->locktime));
	return abs->locktime;
}
