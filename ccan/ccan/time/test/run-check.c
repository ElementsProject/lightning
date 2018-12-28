#define DEBUG
#include <ccan/time/time.h>
#include <ccan/time/time.c>
#include <ccan/tap/tap.h>
#include <unistd.h>
#include <stdlib.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/wait.h>

/* If we really abort, we don't get coverage info! */
void abort(void)
{
	exit(7);
}

int main(void)
{
	struct timeabs t1, t2, epoch = { { 0, 0 } };
	struct timemono t1m, t2m;
	struct timerel t3, t4, zero = { { 0, 0 } };
	int fds[2];

	plan_tests(69);

	/* Test time_now */
	t1 = time_now();
	t2 = time_now();

	/* Test time_between. */
	t3 = time_between(t2, t1);
	ok1(t3.ts.tv_sec > 0 || t3.ts.tv_nsec >= 0);
	t3 = time_between(t2, t2);
	ok1(t3.ts.tv_sec == 0 && t3.ts.tv_nsec == 0);
	t3 = time_between(t1, t1);
	ok1(t3.ts.tv_sec == 0 && t3.ts.tv_nsec == 0);

	/* Test timeabs_eq / timerel_eq */
	ok1(timeabs_eq(t1, t1));
	ok1(timeabs_eq(t2, t2));
	ok1(!timeabs_eq(t1, epoch));
	ok1(!timeabs_eq(t2, epoch));
	t3.ts.tv_sec = 1;
	ok1(timerel_eq(t3, t3));
	ok1(!timerel_eq(t3, zero));

	/* Test time_mono */
	t1m = time_mono();
	t2m = time_mono();

	ok1(!time_less_(t2m.ts, t1m.ts));

	t3.ts.tv_sec = 1;
	t3.ts.tv_nsec = 0;

	ok1(time_less(timemono_between(t2m, t1m), t3));
	ok1(time_less(timemono_since(t1m), t3));

	ok1(timemono_add(t1m, t3).ts.tv_sec == t1m.ts.tv_sec + 1);
	ok1(timemono_add(t2m, t3).ts.tv_nsec == t2m.ts.tv_nsec);

	/* Make sure t2 > t1. */
	t3.ts.tv_sec = 0;
	t3.ts.tv_nsec = 1;
	t2 = timeabs_add(t2, t3);

	/* Test time_before and time_after. */
	ok1(!timeabs_eq(t1, t2));
	ok1(!time_after(t1, t2));
	ok1(time_before(t1, t2));
	ok1(time_after(t2, t1));
	ok1(!time_before(t2, t1));
	t3.ts.tv_sec = 0;
	t3.ts.tv_nsec = 999999999;
	t2 = timeabs_add(t2, t3);
	ok1(!timeabs_eq(t1, t2));
	ok1(!time_after(t1, t2));
	ok1(time_before(t1, t2));
	ok1(time_after(t2, t1));
	ok1(!time_before(t2, t1));

	t3 = time_between(t2, epoch);
	ok1(t2.ts.tv_sec == t3.ts.tv_sec && t2.ts.tv_nsec == t3.ts.tv_nsec);
	t3 = time_between(t2, t2);
	ok1(timerel_eq(t3, zero));

	/* time_from_msec / time_to_msec */
	t3 = time_from_msec(500);
	ok1(t3.ts.tv_sec == 0);
	ok1(t3.ts.tv_nsec == 500000000);
	ok1(time_to_msec(t3) == 500);

	t3 = time_from_msec(1000);
	ok1(t3.ts.tv_sec == 1);
	ok1(t3.ts.tv_nsec == 0);
	ok1(time_to_msec(t3) == 1000);

	t3 = time_from_msec(1500);
	ok1(t3.ts.tv_sec == 1);
	ok1(t3.ts.tv_nsec == 500000000);
	ok1(time_to_msec(t3) == 1500);

	/* time_from_usec */
	t3 = time_from_usec(500000);
	ok1(t3.ts.tv_sec == 0);
	ok1(t3.ts.tv_nsec == 500000000);
	ok1(time_to_usec(t3) == 500000);

	t3 = time_from_usec(1000000);
	ok1(t3.ts.tv_sec == 1);
	ok1(t3.ts.tv_nsec == 0);
	ok1(time_to_usec(t3) == 1000000);

	t3 = time_from_usec(1500000);
	ok1(t3.ts.tv_sec == 1);
	ok1(t3.ts.tv_nsec == 500000000);
	ok1(time_to_usec(t3) == 1500000);

	/* time_from_nsec */
	t3 = time_from_nsec(500000000);
	ok1(t3.ts.tv_sec == 0);
	ok1(t3.ts.tv_nsec == 500000000);
	ok1(time_to_nsec(t3) == 500000000);

	t3 = time_from_nsec(1000000000);
	ok1(t3.ts.tv_sec == 1);
	ok1(t3.ts.tv_nsec == 0);
	ok1(time_to_nsec(t3) == 1000000000);

	t3 = time_from_nsec(1500000000);
	ok1(t3.ts.tv_sec == 1);
	ok1(t3.ts.tv_nsec == 500000000);
	ok1(time_to_nsec(t3) == 1500000000);

	/* Test wrapunder */
	t1 = timeabs_sub(timeabs_sub(t2, time_from_msec(500)),
			 time_from_msec(500));
	ok1(t1.ts.tv_sec == t2.ts.tv_sec - 1);
	ok1(t1.ts.tv_nsec == t2.ts.tv_nsec);

	/* time_divide and time_multiply */
	t4.ts.tv_nsec = 100;
	t4.ts.tv_sec = 100;

	t3 = time_divide(t4, 2);
	ok1(t3.ts.tv_sec == 50);
	ok1(t3.ts.tv_nsec == 50);

	t3 = time_divide(t4, 100);
	ok1(t3.ts.tv_sec == 1);
	ok1(t3.ts.tv_nsec == 1);

	t3 = time_multiply(t3, 100);
	ok1(timerel_eq(t3, t4));

	t3 = time_divide(t4, 200);
	ok1(t3.ts.tv_sec == 0);
	ok1(t3.ts.tv_nsec == 500000000);

	/* Divide by huge number. */
	t4.ts.tv_sec = (1U << 31) - 1;
	t4.ts.tv_nsec = 999999999;
	t3 = time_divide(t4, 1 << 30);
	/* Allow us to round either way. */
	ok1((t3.ts.tv_sec == 2 && t3.ts.tv_nsec == 0)
	    || (t3.ts.tv_sec == 1 && t3.ts.tv_nsec == 999999999));

	/* Multiply by huge number. */
	t4.ts.tv_sec = 0;
	t4.ts.tv_nsec = 1;
	t3 = time_multiply(t4, 1UL << 31);
	ok1(t3.ts.tv_sec == 2);
	ok1(t3.ts.tv_nsec == 147483648);

	if (pipe(fds) != 0)
		exit(1);

	fflush(stdout);
	switch (fork()) {
	case 0:
		close(fds[0]);
		dup2(fds[1], 1);
		dup2(fds[1], 2);
		t1.ts.tv_sec = 7;
		t1.ts.tv_nsec = 1000000001;
		t2 = timeabs_check(t1, NULL);
		if (t2.ts.tv_sec != 8 || t2.ts.tv_nsec != 1)
			exit(1);
		t1.ts.tv_sec = -1;
		t1.ts.tv_nsec = 5;
		t2 = timeabs_check(t1, NULL);
		if (t2.ts.tv_sec != 0 || t2.ts.tv_nsec != 5)
			exit(1);
		t1.ts.tv_sec = 8;
		t1.ts.tv_nsec = 1000000002;
		/* We expect this to abort! */
		t2 = timeabs_check(t1, "abortstr");
		exit(1);
		
	default: {
		char readbuf[1024];
		int r, len = 0;

		close(fds[1]);
		while ((r = read(fds[0], readbuf + len, 1023 - len)) > 0)
			len += r;
		readbuf[len] = '\0';
		ok1(strcmp(readbuf,
			   "WARNING: malformed time"
			   " 7 seconds 1000000001 ns converted to 8.000000001.\n"
			   "WARNING: malformed time"
			   " -1 seconds 5 ns converted to 0.000000005.\n"
			   "abortstr: malformed time 8.1000000002\n") == 0);
		ok1(wait(&r) != -1);
		ok1(WIFEXITED(r));
		ok1(WEXITSTATUS(r) == 7);
	}
	}

	return exit_status();
}
