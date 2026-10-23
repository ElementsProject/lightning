/* Regression test (2026-08-05 audit, see audit-findings/str.md):
 * strcount(haystack, "") must not hang.  strstr(haystack, "") returns
 * haystack, so without the empty-needle guard in strcount() the loop
 * never advances.  The alarm() bound turns a regression into a visible
 * test failure (killed by SIGALRM) instead of a stuck test run. */
#include <ccan/str/str.h>
#include <ccan/str/str.c>
#include <ccan/tap/tap.h>
#include <signal.h>
#include <unistd.h>

int main(void)
{
	plan_tests(1);
	alarm(10);
	/* Fixed semantics: an empty needle occurs nowhere (0).  The point
	 * is that strcount() returns at all. */
	ok1(strcount("abc", "") == 0);
	return exit_status();
}
