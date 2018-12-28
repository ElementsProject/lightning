#include <ccan/timer/timer.h>
/* Include the C files directly. */
#include <ccan/timer/timer.c>
#include <ccan/tap/tap.h>

/* More than 32 bits */
#define MAX_ORD 34

/* 0...17, 63, 64, 65, 127, 128, 129, 255, 256, 257, ... */
static uint64_t next(uint64_t base)
{
	if (base > 16 && ((base - 1) & ((base - 1) >> 1)) == 0)
		return base * 2 - 3;
	return base+1;
}

int main(void)
{
	struct timers timers;
	struct timer t;
	uint64_t diff;
	unsigned int i;
	struct timemono epoch = { { 0, 0 } };

	/* This is how many tests you plan to run */
	plan_tests(2 + (18 + (MAX_ORD - 4) * 3) * (18 + (MAX_ORD - 4) * 3));

	timers_init(&timers, epoch);
	ok1(timers_check(&timers, NULL));

	for (i = 0; i < 4; i++)
		add_level(&timers, i);

	i = 0;
	timer_init(&t);
	for (diff = 0; diff < (1ULL << MAX_ORD)+2; diff = next(diff)) {
		i++;
		for (timers.base = 0;
		     timers.base < (1ULL << MAX_ORD)+2;
		     timers.base = next(timers.base)) {
			timer_addmono(&timers, &t, grains_to_time(timers.base + diff));
			ok1(timers_check(&timers, NULL));
			timer_del(&timers, &t);
		}
	}

	ok1(timers_check(&timers, NULL));

	timers_cleanup(&timers);

	/* This exits depending on whether all tests passed */
	return exit_status();
}
