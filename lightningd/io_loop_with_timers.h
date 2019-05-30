#ifndef LIGHTNING_LIGHTNINGD_IO_LOOP_WITH_TIMERS_H
#define LIGHTNING_LIGHTNINGD_IO_LOOP_WITH_TIMERS_H

#include "config.h"

struct lightningd;

void *io_loop_with_timers(struct lightningd *ld);

#endif /* LIGHTNING_LIGHTNINGD_IO_LOOP_WITH_TIMERS_H */
