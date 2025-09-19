#ifndef LIGHTNING_COMMON_CLOCK_TIME_H
#define LIGHTNING_COMMON_CLOCK_TIME_H
#include "config.h"
#include <ccan/short_types/short_types.h>
#include <ccan/time/time.h>

/* We use this instead of time_now, for overriding when we want reproducibility */
struct timeabs clock_time(void);

/* If you need a clock that progresses even when reproducible, use this. */
#define clock_time_progresses() ({static u64 progress; clock_time_progresses_(&progress);})
struct timeabs clock_time_progresses_(u64 *progress);

/* dev setting to override time */
void dev_override_clock_time(struct timeabs now);

/* Did someone override time? */
bool clock_time_overridden(void);
#endif /* LIGHTNING_COMMON_CLOCK_TIME_H */
