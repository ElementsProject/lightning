/* Regression test for audit finding F1 (2026-08-05, temporary):
 * a timer >= 2^60 grains in the future lands on level 12 (the top
 * level); fast-forwarding across the 2^60 boundary computes
 * 1ULL << ((12+1)*TIMER_LEVEL_BITS) == 1ULL << 65 (undefined behavior)
 * in timer_fast_forward() (timer.c:317) and add_level() (timer.c:173).
 * In practice (x86 shift-count masking) the far timer is never
 * promoted, and timers_expire() spins forever when base was 0.
 *
 * 2^60 grains == ~36.6 years at TIMER_GRANULARITY=1 (ns), ~36,600
 * years at the default 1000 (us); the values are legal per the
 * documented API (no upper bound on timemono arguments).
 *
 * Currently fails: UBSan reports the oversized shift, then the test
 * hangs in timers_expire() until alarm() fires.  Note: any
 * intermediate expire() call would advance base and mask the hang
 * (the level-11 far-pull bound then reaches the timer), so the jump
 * here is done in one step. */
#include <unistd.h>
#include <ccan/timer/timer.h>
/* Include the C files directly. */
#include <ccan/timer/timer.c>
#include <ccan/tap/tap.h>

int main(void)
{
	struct timers timers;
	struct timer t;
	struct timemono earliest;
	const struct timemono epoch = { { 0, 0 } };
	/* level_of(): ilog64((2^60)/2) / TIMER_LEVEL_BITS == 60/5 == 12 */
	const uint64_t when = 1ULL << 60;

	alarm(10);
	plan_tests(6);

	timers_init(&timers, epoch);
	timer_init(&t);
	timer_addmono(&timers, &t, grains_to_time(when));
	ok1(timers_check(&timers, NULL));
	ok1(timer_earliest(&timers, &earliest));
	ok1(timemono_eq(earliest, grains_to_time(when)));

	/* Not due at the epoch (expire == base does not advance base). */
	ok1(!timers_expire(&timers, epoch));

	/* Must expire when its time comes (UB shift + hang before fix). */
	ok1(timers_expire(&timers, grains_to_time(when)) == &t);
	ok1(timers_check(&timers, NULL));

	timers_cleanup(&timers);

	/* This exits depending on whether all tests passed */
	return exit_status();
}
