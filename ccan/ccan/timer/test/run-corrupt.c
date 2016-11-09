#define CCAN_TIMER_DEBUG 1
#include <ccan/timer/timer.h>
/* Include the C files directly. */
#include <ccan/timer/timer.c>
#include <ccan/tap/tap.h>

static void new_timer(struct timers *timers, unsigned long nsec)
{
	struct timer *timer;
	struct timemono when;

	timer = malloc(sizeof(*timer));
	timer_init(timer);
	when.ts.tv_sec = 0; when.ts.tv_nsec = nsec;
	timer_addmono(timers, timer, when);
}

static void update_and_expire(struct timers *timers)
{
	struct timemono when;

	timer_earliest(timers, &when);
	free(timers_expire(timers, when));
}

int main(void)
{
	struct timemono when;
	struct timers timers;

	plan_tests(7);
	
	when.ts.tv_sec = 0; when.ts.tv_nsec = 0;
	timers_init(&timers, when);

	/* Add these */
	new_timer(&timers, 35000000);
	new_timer(&timers, 38000000);
	new_timer(&timers, 59000000);
	new_timer(&timers, 65000000);
	new_timer(&timers, 88000000);
	new_timer(&timers, 125000000);
	new_timer(&timers, 130000000);
	new_timer(&timers, 152000000);
	new_timer(&timers, 168000000);
	/* Expire all but the last one. */
	update_and_expire(&timers);
	update_and_expire(&timers);
	update_and_expire(&timers);
	update_and_expire(&timers);
	update_and_expire(&timers);
	update_and_expire(&timers);
	update_and_expire(&timers);
	update_and_expire(&timers);
	/* Add a new one. */
	new_timer(&timers, 169000000);
	ok1(timers_check(&timers, NULL));

	/* Used to get the wrong one... */
	timers_dump(&timers, stdout);
	ok1(timer_earliest(&timers, &when));
	ok1(when.ts.tv_nsec == 168000000);
	free(timers_expire(&timers, when));

	ok1(timer_earliest(&timers, &when));
	ok1(when.ts.tv_nsec == 169000000);
	free(timers_expire(&timers, when));

	ok1(timers_check(&timers, NULL));
	ok1(!timer_earliest(&timers, &when));
	timers_cleanup(&timers);

	return exit_status();
}
