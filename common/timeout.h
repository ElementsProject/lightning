#ifndef LIGHTNING_COMMON_TIMEOUT_H
#define LIGHTNING_COMMON_TIMEOUT_H
#include "config.h"

#include <ccan/tal/tal.h>
#include <ccan/time/time.h>
#include <ccan/timer/timer.h>
#include <ccan/typesafe_cb/typesafe_cb.h>

/* tal_free this to disable timer. */
struct oneshot *new_reltimer_(struct timers *timers,
			      const tal_t *ctx,
			      struct timerel expire,
			      void (*cb)(void *), void *arg);

#define new_reltimer(timers, ctx, relexpire, func, arg)		\
	new_reltimer_((timers), (ctx), (relexpire),			\
		      typesafe_cb(void, void *, (func), (arg)), (arg))

void timer_expired(tal_t *ctx, struct timer *timer);

#endif /* LIGHTNING_COMMON_TIMEOUT_H */
