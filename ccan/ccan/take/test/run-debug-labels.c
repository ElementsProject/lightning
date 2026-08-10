#include <stdlib.h>
#include <stdbool.h>
#include <stdio.h>
#include <unistd.h>

#define CCAN_TAKE_DEBUG 1
#include <ccan/take/take.h>
#include <ccan/take/take.c>
#include <ccan/tap/tap.h>

/* Regression test: taken() must keep labelarr in sync with takenarr.
 * After a non-last entry is consumed, taken_any() must still report the
 * label of a *still-taken* pointer, not that of a consumed one. */
int main(void)
{
	int alpha, beta;
	const char *l;
	int line_alpha, line_beta;
	char expect[80];

	alarm(10);
	plan_tests(8);

	/* Control: removing the last entry keeps labels in sync. */
	line_alpha = __LINE__ + 1;
	take(&alpha);
	take(&beta);
	ok1(taken(&beta));
	l = taken_any();
	ok1(l != NULL);
	snprintf(expect, sizeof(expect), ":%d:&alpha", line_alpha);
	ok1(strstr(l, expect) != NULL);
	ok1(taken(&alpha));
	ok1(!taken_any());

	take_cleanup();

	/* Removing the first entry must not misalign the labels. */
	take(&alpha);
	line_beta = __LINE__ + 1;
	take(&beta);
	ok1(taken(&alpha));
	l = taken_any();
	ok1(l != NULL);
	snprintf(expect, sizeof(expect), ":%d:&beta", line_beta);
	/* Fails today: taken_any() reports take(&alpha)'s label instead. */
	ok1(strstr(l, expect) != NULL);

	take_cleanup();

	return exit_status();
}
