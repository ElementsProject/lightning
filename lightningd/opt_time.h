#ifndef LIGHTNING_DAEMON_OPT_TIME_H
#define LIGHTNING_DAEMON_OPT_TIME_H
#include "config.h"
#include <ccan/opt/opt.h>
#include <ccan/time/time.h>

char *opt_set_time(const char *arg, struct timerel *t);
void opt_show_time(char buf[OPT_SHOW_LEN], const struct timerel *t);

char *opt_set_timeabs(const char *arg, struct timeabs *t);
void opt_show_timeabs(char buf[OPT_SHOW_LEN], const struct timeabs *t);

#endif /* LIGHTNING_DAEMON_OPT_TIME_H */
