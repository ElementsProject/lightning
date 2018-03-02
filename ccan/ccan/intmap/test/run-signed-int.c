#include <ccan/intmap/intmap.h>
#include <ccan/intmap/intmap.c>
#include <ccan/tap/tap.h>

int main(void)
{
	SINTMAP(const char *) map;
	const char *first = "first", *second = "second";
	int64_t s;

	/* This is how many tests you plan to run */
	plan_tests(38);

	sintmap_init(&map);
	/* Test boundaries. */
	ok1(!sintmap_get(&map, 0x7FFFFFFFFFFFFFFFLL));
	ok1(!sintmap_get(&map, -0x8000000000000000LL));
	ok1(sintmap_first(&map, &s) == NULL);
	ok1(sintmap_last(&map, &s) == NULL);
	ok1(errno == ENOENT);
	s = 0x7FFFFFFFFFFFFFFFLL;
	ok1(sintmap_after(&map, &s) == NULL);
	ok1(errno == ENOENT);
	s = -0x8000000000000000LL;
	ok1(sintmap_after(&map, &s) == NULL);
	ok1(errno == ENOENT);
	s = 0x7FFFFFFFFFFFFFFELL;
	ok1(sintmap_after(&map, &s) == NULL);
	ok1(errno == ENOENT);
	ok1(sintmap_add(&map, 0x7FFFFFFFFFFFFFFFLL, first));
	ok1(sintmap_get(&map, 0x7FFFFFFFFFFFFFFFLL) == first);
	ok1(sintmap_first(&map, &s) == first && s == 0x7FFFFFFFFFFFFFFFLL);
	ok1(sintmap_last(&map, &s) == first && s == 0x7FFFFFFFFFFFFFFFLL);
	ok1(errno == 0);
	ok1(sintmap_add(&map, -0x8000000000000000LL, second));
	ok1(sintmap_get(&map, 0x7FFFFFFFFFFFFFFFLL) == first);
	ok1(sintmap_get(&map, -0x8000000000000000LL) == second);
	ok1(sintmap_first(&map, &s) == second && s == -0x8000000000000000LL);
	ok1(sintmap_after(&map, &s) == first && s == 0x7FFFFFFFFFFFFFFFLL);
	ok1(sintmap_last(&map, &s) == first && s == 0x7FFFFFFFFFFFFFFFLL);
	ok1(errno == 0);
	s = 0x7FFFFFFFFFFFFFFELL;
	ok1(sintmap_after(&map, &s) == first && s == 0x7FFFFFFFFFFFFFFFLL);
	ok1(errno == 0);
	s = -0x7FFFFFFFFFFFFFFFLL;
	ok1(sintmap_after(&map, &s) == first && s == 0x7FFFFFFFFFFFFFFFLL);
	ok1(errno == 0);
	ok1(sintmap_after(&map, &s) == NULL);
	ok1(errno == ENOENT);
	ok1(sintmap_del(&map, 0x7FFFFFFFFFFFFFFFLL) == first);
	s = -0x8000000000000000LL;
	ok1(sintmap_after(&map, &s) == NULL);
	ok1(errno == ENOENT);
	ok1(sintmap_add(&map, 0x7FFFFFFFFFFFFFFFLL, first));
	ok1(sintmap_del(&map, 0x8000000000000000LL) == second);
	s = -0x8000000000000000LL;
	ok1(sintmap_after(&map, &s) == first && s == 0x7FFFFFFFFFFFFFFFLL);
	ok1(errno == 0);
	ok1(sintmap_del(&map, 0x7FFFFFFFFFFFFFFFLL) == first);
	ok1(sintmap_empty(&map));
	
	/* This exits depending on whether all tests passed */
	return exit_status();
}
