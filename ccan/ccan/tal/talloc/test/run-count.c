#include <ccan/tal/talloc/talloc.h>
#include <ccan/tal/talloc/talloc.c>
#include <ccan/tap/tap.h>

int main(void)
{
	char *p1, *p2;

	plan_tests(12);

	p1 = tal(NULL, char);
	ok1(p1);
	ok1(tal_count(p1) == 1);

	p2 = tal_arr(p1, char, 1);
	ok1(p2);
	ok1(tal_count(p2) == 1);
	ok1(tal_resize(&p2, 2));
	ok1(tal_count(p2) == 2);
	ok1(tal_check(NULL, NULL));
	tal_free(p2);

	p2 = tal_arrz(p1, char, 7);
	ok1(p2);
	ok1(tal_count(p2) == 7);
	ok1(tal_resize(&p2, 0));
	ok1(tal_count(p2) == 0);
	ok1(tal_check(NULL, NULL));
	tal_free(p2);
	tal_free(p1);

	return exit_status();
}
