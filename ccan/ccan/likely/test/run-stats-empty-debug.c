#define CCAN_LIKELY_DEBUG 1
#include <ccan/likely/likely.c>
#include <ccan/likely/likely.h>
#include <ccan/tap/tap.h>
#include <stdlib.h>
#include <signal.h>

/* Regression test for likely.c likely_stats(): with no entry meeting
 * the criteria, the worst_ratio guard is skipped when percent >= 200
 * (worst_ratio stays 2.0; 2.0 * 100 > percent is false), and worst
 * (NULL) is dereferenced at strlen(worst->condstr).  The header
 * documents: "It returns NULL when nothing meets those criteria." */
static bool one_seems_likely(unsigned int val)
{
	if (likely(val == 1))
		return true;
	return false;
}

int main(void)
{
	char *bad;

	alarm(10);
	plan_tests(3);

	/* Empty table: nothing meets the criteria, must return NULL. */
	bad = likely_stats(0, 200);
	ok1(bad == NULL);

	/* Entry below min_hits: likewise nothing meets the criteria. */
	one_seems_likely(0);
	one_seems_likely(2);
	bad = likely_stats(4, 200);
	ok1(bad == NULL);

	/* A qualifying entry must still be reported with percent=200. */
	bad = likely_stats(2, 200);
	ok(bad != NULL && strends(bad, "correct 0% (0/2)"),
	   "likely_stats returned %s", bad ? bad : "(null)");
	free(bad);

	exit(exit_status());
}
