#ifndef LIGHTNING_PLUGINS_RENEPAY_RENEPAYCONFIG_H
#define LIGHTNING_PLUGINS_RENEPAY_RENEPAYCONFIG_H
#include "config.h"

#define MAX_NUM_ATTEMPTS 10

/* Knowledge is proportionally decreased with time up to TIMER_FORGET_SEC when
 * we forget everything. */
#define TIMER_FORGET_SEC 3600

/* Time lapse used to wait for failed sendpays. */
#define COLLECTOR_TIME_WINDOW_MSEC 50

#endif /* LIGHTNING_PLUGINS_RENEPAY_RENEPAYCONFIG_H */
