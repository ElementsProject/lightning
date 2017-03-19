#include <stdlib.h>
#include <stdbool.h>

#define CCAN_TAKE_DEBUG 1
#include <ccan/take/take.h>
#include <ccan/take/take.c>
#include <ccan/tap/tap.h>

int main(void)
{
	const char *p = "hi";

	plan_tests(14);

	/* We can take NULL. */
	ok1(take(NULL) == NULL);
	ok1(is_taken(NULL));
	ok1(strstr(taken_any(), "run-debug.c:16:"));
	ok1(taken(NULL)); /* Undoes take() */
	ok1(!is_taken(NULL));
	ok1(!taken(NULL));
	ok1(!taken_any());

	/* We can take a real pointer. */
	ok1(take(p) == p);
	ok1(is_taken(p));
	ok1(strends(taken_any(), "run-debug.c:25:p"));
	ok1(taken(p)); /* Undoes take() */
	ok1(!is_taken(p));
	ok1(!taken(p));
	ok1(!taken_any());

	return exit_status();
}
