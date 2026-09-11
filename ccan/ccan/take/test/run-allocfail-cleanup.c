#include <stdlib.h>
#include <stdbool.h>
#include <unistd.h>

static bool fail_realloc;
static void *my_realloc(void *p, size_t len)
{
	if (fail_realloc)
		return NULL;
	return realloc(p, len);
}
#define realloc my_realloc

#include <ccan/take/take.h>
#include <ccan/take/take.c>
#include <ccan/tap/tap.h>

static void noop_allocfail(const void *p UNNEEDED)
{
}

/* Regression test: take_cleanup() is documented to "remove all taken
 * pointers from list", but it leaves the allocfail counter behind, so a
 * phantom taken NULL survives the cleanup. */
int main(void)
{
	static int x;

	alarm(10);
	plan_tests(4);

	take_allocfail(noop_allocfail);
	ok1(take(&x) == &x);

	/* Force the next take's realloc to fail: phantom taken NULL. */
	fail_realloc = true;
	ok1(take(&x) == NULL);

	/* take_cleanup() should remove *all* taken state. */
	take_cleanup();
	/* Both fail today: the phantom NULL is still "taken". */
	ok1(!is_taken(NULL));
	ok1(!taken(NULL));

	return exit_status();
}
