#ifndef LIGHTNING_DAEMON_TIMEOUT_H
#define LIGHTNING_DAEMON_TIMEOUT_H
#include "config.h"

#include <ccan/tal/tal.h>
#include <ccan/time/time.h>
#include <ccan/timer/timer.h>
#include <ccan/typesafe_cb/typesafe_cb.h>

/* tal_free this to disable timer. */
struct oneshot *new_reltimer_(struct lightningd_state *dstate,
			      const tal_t *ctx,
			      struct timerel expire,
			      void (*cb)(void *), void *arg);

#define new_reltimer(dstate, ctx, relexpire, func, arg)		\
	new_reltimer_((dstate), (ctx), (relexpire),			\
		      typesafe_cb(void, void *, (func), (arg)), (arg))

void timer_expired(struct lightningd_state *dstate, struct timer *timer);

#endif /* LIGHTNING_DAEMON_TIMEOUT_H */
