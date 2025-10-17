#include "config.h"
#include <assert.h>
#include <common/clock_time.h>

static bool used = false;
static struct timeabs dev_override;

bool clock_time_overridden(void)
{
	return dev_override.ts.tv_sec != 0;
}

struct timeabs clock_time(void)
{
	used = true;
	if (!clock_time_overridden())
		return time_now(); /* discouraged: use clock_time so we can override */

	return dev_override;
}

struct timeabs clock_time_progresses_(u64 *progress)
{
	if (!clock_time_overridden())
		return clock_time();

	return timeabs_add(dev_override, time_from_sec((*progress)++));
}

void dev_override_clock_time(struct timeabs now)
{
	assert(!used);

	dev_override = now;
	assert(clock_time_overridden());
}
