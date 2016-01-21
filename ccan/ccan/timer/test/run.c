#define CCAN_TIMER_DEBUG
#include <ccan/timer/timer.h>
/* Include the C files directly. */
#include <ccan/timer/timer.c>
#include <ccan/tap/tap.h>

static struct timeabs timeabs_from_nsec(unsigned long long nsec)
{
	struct timeabs epoch = { { 0, 0 } };
	return timeabs_add(epoch, time_from_nsec(nsec));
}

int main(void)
{
	struct timers timers;
	struct timer t[64];
	struct timeabs earliest;
	uint64_t i;
	struct timeabs epoch = { { 0, 0 } };

	/* This is how many tests you plan to run */
	plan_tests(488);

	timers_init(&timers, epoch);
	ok1(timers_check(&timers, NULL));
	ok1(!timer_earliest(&timers, &earliest));

	timer_init(&t[0]);
	/* timer_del can be called immediately after init. */
	timer_del(&timers, &t[0]);

	timer_add(&timers, &t[0], timeabs_from_nsec(1));
	ok1(timers_check(&timers, NULL));
	ok1(timer_earliest(&timers, &earliest));
	ok1(timeabs_eq(earliest, grains_to_time(t[0].time)));
	timer_del(&timers, &t[0]);
	ok1(timers_check(&timers, NULL));
	ok1(!timer_earliest(&timers, &earliest));

	/* timer_del can be called twice, no problems. */
	timer_del(&timers, &t[0]);

	/* Check timer ordering. */
	for (i = 0; i < 32; i++) {
		timer_init(&t[i*2]);
		timer_add(&timers, &t[i*2], timeabs_from_nsec(1ULL << i));
		ok1(timers_check(&timers, NULL));
		timer_init(&t[i*2+1]);
		timer_add(&timers, &t[i*2+1], timeabs_from_nsec((1ULL << i) + 1));
		ok1(timers_check(&timers, NULL));
	}

	for (i = 0; i < 32; i++) {
		const struct timer *t1, *t2;

		t1 = get_first(&timers);
		ok1(t1 == &t[i*2] || t1 == &t[i*2+1]);
		timer_del(&timers, (struct timer *)t1);
		ok1(timers_check(&timers, NULL));

		t2 = get_first(&timers);
		ok1(t2 != t1 && (t2 == &t[i*2] || t2 == &t[i*2+1]));
		timer_del(&timers, (struct timer *)t2);
		ok1(timers_check(&timers, NULL));
	}

	/* Check expiry. */
	for (i = 0; i < 32; i++) {
		uint64_t exp = (uint64_t)TIMER_GRANULARITY << i;

		timer_add(&timers, &t[i*2], timeabs_from_nsec(exp));
		ok1(timers_check(&timers, NULL));
		timer_add(&timers, &t[i*2+1], timeabs_from_nsec(exp + 1));
		ok1(timers_check(&timers, NULL));
	}

	for (i = 0; i < 32; i++) {
		struct timer *t1, *t2;

		ok1(timer_earliest(&timers, &earliest));
		t1 = timers_expire(&timers, earliest);
		ok1(t1);
		t2 = timers_expire(&timers, earliest);
		ok1(t2);
		ok1(!timers_expire(&timers, earliest));

		ok1(t1 == &t[i*2] || t1 == &t[i*2+1]);
		ok1(t2 != t1 && (t2 == &t[i*2] || t2 == &t[i*2+1]));
		ok1(timers_check(&timers, NULL));
	}

	ok1(!timer_earliest(&timers, &earliest));

	timers_cleanup(&timers);

	/* This exits depending on whether all tests passed */
	return exit_status();
}
