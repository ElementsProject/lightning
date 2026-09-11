/* Auditor-added regression test (temporary) for the time_divide()
 * double-path roundup defect: for divisors > 2^30 with
 * tv_sec % div == div-1 and tv_nsec == 999999999, the true quotient's
 * sub-second part is 1e9 - 1/div, which the double computation rounds
 * UP to exactly 1000000000, returning a malformed timerel
 * (tv_nsec == 1000000000) from well-formed inputs.  In DEBUG builds
 * time_divide() aborts on its own result (TIMEREL_CHECK at time.c:65).
 *
 * Currently FAILS (test 1 and 2): r.ts.tv_nsec == 1000000000.
 * After repair it must pass: result well-formed and equal to either
 * {0, 999999999} (truncation) or {1, 0} (correct round-up).
 */
#include <unistd.h>
#include <ccan/time/time.h>
#include <ccan/time/time.c>
#include <ccan/tap/tap.h>
#include <signal.h>

int main(void)
{
	struct timerel t, r, trunc = { { 0, 999999999 } }, one = { { 1, 0 } };

	alarm(10);
	plan_tests(3);

	t.ts.tv_sec = 1073741824; /* == div - 1 */
	t.ts.tv_nsec = 999999999;
	r = time_divide(t, 1073741825); /* > 2^30: takes the double path */

	/* Result must be well-formed. */
	ok1(r.ts.tv_sec >= 0
	    && r.ts.tv_nsec >= 0 && r.ts.tv_nsec < 1000000000);
	/* True value is 0.99999999907s: trunc or rounded-up {1,0} only. */
	ok1(timerel_eq(r, trunc) || timerel_eq(r, one));

	/* A second point in the same family. */
	t.ts.tv_sec = 2147483648; /* == div - 1 */
	t.ts.tv_nsec = 999999999;
	r = time_divide(t, 2147483649);
	ok1(r.ts.tv_sec >= 0
	    && r.ts.tv_nsec >= 0 && r.ts.tv_nsec < 1000000000);

	return exit_status();
}
