#define CCAN_TIMER_DEBUG
/* Include the C files directly. */
#include <ccan/timer/timer.c>
#include <ccan/tap/tap.h>

struct timers_with_counters {
	struct timers timers;
	size_t num_alloc, num_free;
};


static void *test_alloc(struct timers *timers, size_t len)
{
	((struct timers_with_counters *)timers)->num_alloc++;
	return malloc(len);
}

static void test_free(struct timers *timers, void *p)
{
	if (p) {
		((struct timers_with_counters *)timers)->num_free++;
		free(p);
	}
}

static struct timemono timemono_from_nsec(unsigned long long nsec)
{
	struct timemono epoch = { { 0, 0 } };
	return timemono_add(epoch, time_from_nsec(nsec));
}

int main(void)
{
	struct timers_with_counters tc;
	struct timer t[64];
	const struct timemono epoch = { { 0, 0 } };

	tc.num_alloc = tc.num_free = 0;
	plan_tests(12);

	timers_set_allocator(test_alloc, test_free);
	timers_init(&tc.timers, epoch);
	timer_init(&t[0]);

	timer_addmono(&tc.timers, &t[0],
		      timemono_from_nsec(TIMER_GRANULARITY << TIMER_LEVEL_BITS));
	timers_expire(&tc.timers, timemono_from_nsec(1));
	ok1(tc.num_alloc == 1);
	ok1(tc.num_free == 0);
	timer_del(&tc.timers, &t[0]);
	ok1(tc.num_alloc == 1);
	ok1(tc.num_free == 0);
	timers_cleanup(&tc.timers);
	ok1(tc.num_alloc == 1);
	ok1(tc.num_free == 1);

	/* Should restore defaults */
	timers_set_allocator(NULL, NULL);
	ok1(timer_alloc == timer_default_alloc);
	ok1(timer_free == timer_default_free);

	timers_init(&tc.timers, epoch);
	timer_addmono(&tc.timers, &t[0],
		      timemono_from_nsec(TIMER_GRANULARITY << TIMER_LEVEL_BITS));
	ok1(tc.num_alloc == 1);
	ok1(tc.num_free == 1);
	timers_cleanup(&tc.timers);
	ok1(tc.num_alloc == 1);
	ok1(tc.num_free == 1);

	/* This exits depending on whether all tests passed */
	return exit_status();
}
