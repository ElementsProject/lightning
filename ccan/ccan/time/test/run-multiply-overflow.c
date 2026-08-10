/* Auditor-added regression test (temporary) for the time_multiply()
 * double-path UB: when t.ts.tv_nsec * mult exceeds ~9.2e27, the
 * intermediate `nsec / 1000000000.0` exceeds INT64_MAX and the
 * double->time_t conversion at time.c:77 is undefined behavior
 * (clang UBSan: "outside the range of representable values of type
 * 'long'").  The product genuinely does not fit in a timerel, so this
 * is an inferred-precondition gray zone (LIKLEY, not CONFIRMED): the
 * test passes in plain builds and only aborts under UBSan.  After a
 * repair (document the overflow precondition and/or clamp), it must
 * run UBSan-clean.
 */
#include <ccan/time/time.h>
#include <ccan/time/time.c>
#include <ccan/tap/tap.h>
#include <stdint.h>
#include <signal.h>

int main(void)
{
	struct timerel t, r;

	alarm(10);
	plan_tests(1);

	t.ts.tv_sec = 0;
	t.ts.tv_nsec = 999999999;
	/* nsec ~= 1.8e28; nsec/1e9 ~= 1.8e19 > INT64_MAX: UB conversion. */
	r = time_multiply(t, UINT64_MAX);

	/* Any result at all is acceptable in a plain build; the point of
	 * the test is reaching here without a sanitizer abort. */
	ok1(r.ts.tv_sec != 0 || r.ts.tv_nsec != 0 || true);

	return exit_status();
}
