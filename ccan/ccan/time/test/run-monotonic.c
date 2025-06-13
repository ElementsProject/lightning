#include <ccan/time/time.h>
#include <ccan/time/time.c>
#include <ccan/tap/tap.h>

int main(void)
{
	struct timemono t1, t2;
	struct timerel t3;

	plan_tests(10);

	/* Test time_mono */
	t1 = time_mono();
	t2 = time_mono();

	ok1(!timemono_before(t2, t1));

	t3.ts.tv_sec = 1;
	t3.ts.tv_nsec = 0;

	ok1(time_less(timemono_between(t2, t1), t3));
	ok1(time_less(timemono_since(t1), t3));

	ok1(timemono_add(t1, t3).ts.tv_sec == t1.ts.tv_sec + 1);
	ok1(timemono_add(t2, t3).ts.tv_nsec == t2.ts.tv_nsec);

	ok1(timemono_sub(timemono_add(t1, t3), t3).ts.tv_sec == t1.ts.tv_sec);
	ok1(timemono_sub(timemono_add(t1, t3), t3).ts.tv_nsec == t1.ts.tv_nsec);

	ok1(timemono_after(timemono_add(t1, t3), t1));
	ok1(!timemono_after(t1, timemono_add(t1, t3)));
	ok1(!timemono_after(t1, t1));
	return exit_status();
}
