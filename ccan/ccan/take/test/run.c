#include <stdlib.h>
#include <stdbool.h>

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

static int my_allocfail_called;
static void my_allocfail(const void *p UNNEEDED)
{
	my_allocfail_called++;
}	

static void recurse(const char *takeme, int count)
{
	if (count < 1000)
		recurse(take(strdup(takeme)), count+1);
	if (taken(takeme))
		free((char *)takeme);
}

int main(void)
{
	const char *p = "hi";

	plan_tests(43);

	/* We can take NULL. */
	ok1(take(NULL) == NULL);
	ok1(is_taken(NULL));
	ok1(taken_any());
	ok1(taken(NULL)); /* Undoes take() */
	ok1(!is_taken(NULL));
	ok1(!taken(NULL));

	/* We can take NULL twice! */
	ok1(take(NULL) == NULL);
	ok1(take(NULL) == NULL);
	ok1(is_taken(NULL));
	ok1(taken_any());
	ok1(taken(NULL)); /* Undoes take() */
	ok1(is_taken(NULL));
	ok1(taken_any());
	ok1(taken(NULL)); /* Undoes take() */
	ok1(!is_taken(NULL));
	ok1(!taken(NULL));
	ok1(!taken_any());

	/* We can take a real pointer. */
	ok1(take(p) == p);
	ok1(is_taken(p));
	ok1(taken_any());
	ok1(taken(p)); /* Undoes take() */
	ok1(!is_taken(p));
	ok1(!taken(p));
	ok1(!taken_any());

	/* Force a failure. */
	ok1(!my_allocfail_called);
	ok1(take(p) == p);
	ok1(take(p+1) == p+1);

	fail_realloc = true;
	/* Without a handler, must pass through and leak. */
	ok1(take(p+2) == p+2);
	ok1(!taken(p+2));

	/* Now, with a handler. */
	take_allocfail(my_allocfail);
	ok1(take(p+2) == NULL);

	ok1(my_allocfail_called == 1);
	ok1(taken_any());
	ok1(taken(p));
	ok1(taken(p+1));
	ok1(is_taken(NULL));
	ok1(taken(NULL));
	ok1(!taken(NULL));
	ok1(!taken_any());

	/* Test some deep nesting. */
	fail_realloc = false;
	recurse("hello", 0);
	ok1(max_taken == 1000);
	ok1(!taken_any());

	take_cleanup();
	ok1(num_taken == 0);
	ok1(max_taken == 0);
	ok1(takenarr == NULL);

	return exit_status();
}
