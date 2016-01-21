#ifndef LIGHTNING_DAEMON_CONTROLLED_TIME_H
#define LIGHTNING_DAEMON_CONTROLLED_TIME_H
#include "config.h"
#include <ccan/short_types/short_types.h>
#include <ccan/time/time.h>

struct timeabs controlled_time(void);

#endif /* LIGHTNING_DAEMON_CONTROLLED_TIME_H */
