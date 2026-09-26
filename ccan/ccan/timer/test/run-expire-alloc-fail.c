/* Regression test for audit finding F2 (2026-08-05, temporary):
 * allocator failure in add_level() during timers_expire() leaves
 * timers->level[0] == NULL; timers_expire() then dereferences it at
 * timer.c:368 (list_pop(&timers->level[0]->list[off], ...)) -> SEGV.
 *
 * Expected post-fix behavior encoded here: with allocation failing,
 * timers_expire() must not crash and must not lose the timer (it stays
 * pending on the far list); once allocation succeeds again the timer
 * expires normally.
 *
 * Currently crashes (NULL dereference) before test 2. */
#include <unistd.h>
#include <ccan/timer/timer.h>
/* Include the C files directly. */
#include <ccan/timer/timer.c>
#include <ccan/tap/tap.h>

static bool alloc_fails;

static void *test_alloc(struct timers *timers, size_t len)
{
	(void)timers;
	if (alloc_fails)
		return NULL;
	return malloc(len);
}

static void test_free(struct timers *timers, void *p)
{
	(void)timers;
	free(p);
}

int main(void)
{
	struct timers timers;
	struct timer t;
	const struct timemono epoch = { { 0, 0 } };

	alarm(10);
	plan_tests(5);

	timers_set_allocator(test_alloc, test_free);
	timers_init(&timers, epoch);
	timer_init(&t);

	alloc_fails = true;
	timer_addmono(&timers, &t, grains_to_time(5));
	ok1(timers_check(&timers, NULL));

	/* Level 0 cannot be allocated: must return gracefully. */
	ok1(timers_expire(&timers, grains_to_time(5)) == NULL);
	ok1(timers_check(&timers, NULL));

	/* Once allocation succeeds, the timer must still expire. */
	alloc_fails = false;
	ok1(timers_expire(&timers, grains_to_time(5)) == &t);
	ok1(timers_check(&timers, NULL));

	timers_cleanup(&timers);

	/* This exits depending on whether all tests passed */
	return exit_status();
}
