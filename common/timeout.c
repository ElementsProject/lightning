#include "timeout.h"
#include <common/utils.h>

struct oneshot {
	struct timers *timers;
	struct timer timer;
	void (*cb)(void *);
	void *arg;
};

static void destroy_timer(struct oneshot *t)
{
	timer_del(t->timers, &t->timer);
}

struct oneshot *new_reltimer_(struct timers *timers,
			      const tal_t *ctx,
			      struct timerel relexpiry,
			      void (*cb)(void *), void *arg)
{
	struct oneshot *t = tal(ctx, struct oneshot);

	t->cb = cb;
	t->arg = arg;
	t->timers = timers;
	timer_init(&t->timer);
	timer_addrel(timers, &t->timer, relexpiry);
	tal_add_destructor(t, destroy_timer);

	return t;
}

void timer_expired(tal_t *ctx, struct timer *timer)
{
	struct oneshot *t = container_of(timer, struct oneshot, timer);

	/* If it doesn't free itself, freeing tmpctx will do it */
	tal_steal(tmpctx, t);
	t->cb(t->arg);
}
