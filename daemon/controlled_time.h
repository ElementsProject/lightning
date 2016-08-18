#ifndef LIGHTNING_DAEMON_CONTROLLED_TIME_H
#define LIGHTNING_DAEMON_CONTROLLED_TIME_H
#include "config.h"
#include <ccan/short_types/short_types.h>
#include <ccan/tal/tal.h>
#include <ccan/time/time.h>

struct timeabs controlled_time(void);
void controlled_time_register_opts(void);
char *controlled_time_arg(const tal_t *ctx);

#endif /* LIGHTNING_DAEMON_CONTROLLED_TIME_H */
