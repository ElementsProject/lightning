#include <ccan/timer/timer.h>
/* Include the C files directly. */
#include <ccan/timer/timer.c>
#include <ccan/tap/tap.h>

static struct timeabs timeabs_from_usec(unsigned long long usec)
{
	struct timeabs epoch = { { 0, 0 } };
	return timeabs_add(epoch, time_from_usec(usec));
}

int main(void)
{
	struct timers timers;
	struct timer t, *expired;

	/* This is how many tests you plan to run */
	plan_tests(3);

	timers_init(&timers, timeabs_from_usec(1364726722653919ULL));
	timer_init(&t);
	timer_add(&timers, &t, timeabs_from_usec(1364726722703919ULL));
	ok1(!timers_expire(&timers, timeabs_from_usec(1364726722653920ULL)));
	expired = timers_expire(&timers, timeabs_from_usec(1364726725454187ULL));
	ok1(expired == &t);
	ok1(!timers_expire(&timers, timeabs_from_usec(1364726725454187ULL)));
	timers_cleanup(&timers);

	/* This exits depending on whether all tests passed */
	return exit_status();
}
