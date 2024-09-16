#ifndef LIGHTNING_PLUGINS_RENEPAY_RENEPAYCONFIG_H
#define LIGHTNING_PLUGINS_RENEPAY_RENEPAYCONFIG_H
#include "config.h"

#define RENEPAY_LAYER "renepay"

#define MAX_NUM_ATTEMPTS 10

/* Knowledge is proportionally decreased with time up to TIMER_FORGET_SEC when
 * we forget everything. */
#define TIMER_FORGET_SEC 600000

/* Time lapse used to wait for failed sendpays. */
#define COLLECTOR_TIME_WINDOW_MSEC 50

/* FIXME a hard coded constant to indicate a limit on any channel
 capacity. Channels for which the capacity is unknown (because they are not
 announced) use this value. It makes sense, because if we don't even know the
 channel capacity the liquidity could be anything but it will never be greater
 than the global number of msats.
 It remains to be checked if this value does not lead to overflow somewhere in
 the code. */
#define MAX_CAPACITY (AMOUNT_MSAT(1000000 * MSAT_PER_BTC))

#endif /* LIGHTNING_PLUGINS_RENEPAY_RENEPAYCONFIG_H */
