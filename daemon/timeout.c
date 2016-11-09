#include "lightningd.h"
#include "timeout.h"
#include "utils.h"

struct oneshot {
	struct lightningd_state *dstate;
	struct timer timer;
	void (*cb)(void *);
	void *arg;
};

static void remove_timer(struct oneshot *t)
{
	timer_del(&t->dstate->timers, &t->timer);
}

struct oneshot *new_reltimer_(struct lightningd_state *dstate,
			      const tal_t *ctx,
			      struct timerel relexpiry,
			      void (*cb)(void *), void *arg)
{
	struct oneshot *t = tal(ctx, struct oneshot);

	t->cb = cb;
	t->arg = arg;
	t->dstate = dstate;
	timer_init(&t->timer);
	timer_addrel(&dstate->timers, &t->timer, relexpiry);
	tal_add_destructor(t, remove_timer);

	return t;
}

void timer_expired(struct lightningd_state *dstate, struct timer *timer)
{
	struct oneshot *t = container_of(timer, struct oneshot, timer);
	const tal_t *tmpctx = tal_tmpctx(dstate);

	/* If it doesn't free itself, freeing tmpctx will do it */
	tal_steal(tmpctx, t);
	t->cb(t->arg);
	tal_free(tmpctx);
}
