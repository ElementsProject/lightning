#include "controlled_time.h"
#include "lightningd.h"
#include "timeout.h"

void init_timeout_(struct timeout *t, unsigned int interval,
		   void (*cb)(void *), void *arg)
{
	timer_init(&t->timer);
	t->interval = time_from_sec(interval);
	t->cb = cb;
	t->arg = arg;
}
 
void refresh_timeout(struct lightningd_state *dstate, struct timeout *t)
{
	timer_del(&dstate->timers, &t->timer);
	timer_add(&dstate->timers, &t->timer,
		  timeabs_add(controlled_time(), t->interval));
}

/* FIXME: Make all timers one-shot! */
struct oneshot {
	struct timeout timeout;
	struct lightningd_state *dstate;
	void (*cb)(void *);
	void *arg;
};

static void remove_timer(struct oneshot *o)
{
	timer_del(&o->dstate->timers, &o->timeout.timer);
}

static void oneshot_done(struct oneshot *o)
{
	o->cb(o->arg);
	tal_free(o);
}

struct oneshot *oneshot_timeout_(struct lightningd_state *dstate,
				 const tal_t *ctx, unsigned int seconds,
				 void (*cb)(void *), void *arg)
{
	struct oneshot *o = tal(ctx, struct oneshot);

	o->dstate = dstate;
	o->cb = cb;
	o->arg = arg;

	init_timeout(&o->timeout, seconds, oneshot_done, o);
	refresh_timeout(dstate, &o->timeout);
	tal_add_destructor(o, remove_timer);

	return o;
}
