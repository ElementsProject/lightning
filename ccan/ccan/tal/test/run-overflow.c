#include <ccan/tal/tal.h>
#include <ccan/tal/tal.c>
#include <ccan/tap/tap.h>

static int error_count;

static void my_error(const char *msg UNNEEDED)
{
	error_count++;
}

int main(void)
{
	void *p;
	int *pi, *origpi;
	char *cp;

	plan_tests(30);

	tal_set_backend(NULL, NULL, NULL, my_error);

	p = tal_arr(NULL, int, (size_t)-1);
	ok1(!p);
	ok1(error_count == 1);

	p = tal_arr(NULL, char, (size_t)-2);
	ok1(!p);
	ok1(error_count == 2);

	/* Now try overflow cases for tal_dup. */
	error_count = 0;
	origpi = tal_arr(NULL, int, 100);
	ok1(origpi);
	ok1(error_count == 0);
	pi = tal_dup_arr(NULL, int, origpi, (size_t)-1, 0);
	ok1(!pi);
	ok1(error_count == 1);
	pi = tal_dup_arr(NULL, int, origpi, 0, (size_t)-1);
	ok1(!pi);
	ok1(error_count == 2);

	pi = tal_dup_arr(NULL, int, origpi, (size_t)-1UL / sizeof(int),
		     (size_t)-1UL / sizeof(int));
	ok1(!pi);
	ok1(error_count == 3);
	/* This will still overflow when tal_hdr is added. */
	pi = tal_dup_arr(NULL, int, origpi, (size_t)-1UL / sizeof(int) / 2,
		     (size_t)-1UL / sizeof(int) / 2);
	ok1(!pi);
	ok1(error_count == 4);
	ok1(tal_first(NULL) == origpi && !tal_next(origpi) && !tal_first(origpi));
	tal_free(origpi);

	/* Now, check that with taltk() we free old one on failure. */
	origpi = tal_arr(NULL, int, 100);
	error_count = 0;
	pi = tal_dup_arr(NULL, int, take(origpi), (size_t)-1, 0);
	ok1(!pi);
	ok1(error_count == 1);

	origpi = tal_arr(NULL, int, 100);
	error_count = 0;
	pi = tal_dup_arr(NULL, int, take(origpi), 0, (size_t)-1);
	ok1(!pi);
	ok1(error_count == 1);
	ok1(!tal_first(NULL));

	origpi = tal_arr(NULL, int, 100);
	error_count = 0;
	pi = tal_dup_arr(NULL, int, take(origpi), (size_t)-1UL / sizeof(int),
		     (size_t)-1UL / sizeof(int));
	ok1(!pi);
	ok1(error_count == 1);
	ok1(!tal_first(NULL));

	origpi = tal_arr(NULL, int, 100);
	error_count = 0;
	/* This will still overflow when tal_hdr is added. */
	pi = tal_dup_arr(NULL, int, take(origpi), (size_t)-1UL / sizeof(int) / 2,
		     (size_t)-1UL / sizeof(int) / 2);
	ok1(!pi);
	ok1(error_count == 1);
	ok1(!tal_first(NULL));

	/* Overflow on expand addition. */
	cp = tal_arr(p, char, 100);
	ok1(!tal_expand(&cp, NULL, (size_t)-99UL));
	ok1(error_count == 2);
	tal_free(cp);

	/* Overflow when multiplied by size */
	origpi = tal_arr(NULL, int, 100);
	ok1(!tal_expand(&origpi, NULL, (size_t)-1UL / sizeof(int)));
	ok1(error_count == 3);
	tal_free(origpi);

	tal_cleanup();
	return exit_status();
}
