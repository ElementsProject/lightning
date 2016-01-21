#include <ccan/time/time.h>
#include <ccan/time/time.c>
#include <ccan/tap/tap.h>

int main(void)
{
	struct timemono t1, t2;
	struct timerel t3;

	plan_tests(2);

	/* Test time_mono */
	t1 = time_mono();
	t2 = time_mono();

	ok1(!time_less_(t2.ts, t1.ts));

	t3.ts.tv_sec = 1;
	t3.ts.tv_nsec = 0;

	ok1(time_less(timemono_between(t1, t2), t3));

	return exit_status();
}
