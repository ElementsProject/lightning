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
 
void refresh_timeout(struct lightningd_state *state, struct timeout *t)
{
	timer_del(&state->timers, &t->timer);
	timer_add(&state->timers, &t->timer,
		  timeabs_add(time_now(), t->interval));
}
