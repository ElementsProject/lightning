#ifndef LIGHTNING_DAEMON_TIMEOUT_H
#define LIGHTNING_DAEMON_TIMEOUT_H
#include "config.h"

#include <ccan/tal/tal.h>
#include <ccan/time/time.h>
#include <ccan/timer/timer.h>
#include <ccan/typesafe_cb/typesafe_cb.h>

struct timeout {
	struct timer timer;
	struct timerel interval;
	void (*cb)(void *);
	void *arg;
};

struct lightningd_state;

void init_timeout_(struct timeout *t, unsigned int interval,
		   void (*cb)(void *), void *arg);
 
void refresh_timeout(struct lightningd_state *dstate, struct timeout *t);

#define init_timeout(t, interval, func, arg)				\
	init_timeout_((t), (interval),					\
		     typesafe_cb(void, void *, (func), (arg)), (arg))

/* tal_free this to disable timer. */
struct oneshot *oneshot_timeout_(struct lightningd_state *dstate,
				 const tal_t *ctx, unsigned int seconds,
				 void (*cb)(void *), void *arg);

#define oneshot_timeout(dstate, ctx, interval, func, arg)		\
	oneshot_timeout_((dstate), (ctx), (interval),			\
			 typesafe_cb(void, void *, (func), (arg)), (arg))

#endif /* LIGHTNING_DAEMON_TIMEOUT_H */
