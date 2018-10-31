#ifndef LIGHTNING_COMMON_TIMEOUT_H
#define LIGHTNING_COMMON_TIMEOUT_H
#include "config.h"

#include <ccan/tal/tal.h>
#include <ccan/time/time.h>
#include <ccan/timer/timer.h>
#include <ccan/typesafe_cb/typesafe_cb.h>

/* tal_free this to disable timer. */
struct oneshot *reltimer_new_(struct timers *timers,
			      const tal_t *ctx,
			      struct timerel expire,
			      void (*cb)(void *), void *arg);

#define reltimer_new(timers, ctx, relexpire, func, arg)		\
	reltimer_new_((timers), (ctx), (relexpire),			\
		      typesafe_cb(void, void *, (func), (arg)), (arg))

void timer_expired(tal_t *ctx, struct timer *timer);

#endif /* LIGHTNING_COMMON_TIMEOUT_H */
