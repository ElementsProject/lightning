#include <ccan/tal/tal.h>
#include <ccan/tal/tal.c>
#include <ccan/tap/tap.h>

int main(void)
{
	int *a;
	const int arr[] = { 1, 2 };

	plan_tests(13);

	a = tal_arrz(NULL, int, 1);
	ok1(a);

	ok1(tal_expand(&a, arr, 2));
	ok1(tal_count(a) == 3);
	ok1(a[0] == 0);
	ok1(a[1] == 1);
	ok1(a[2] == 2);

	ok1(tal_expand(&a, take(tal_arrz(NULL, int, 1)), 1));
	ok1(tal_count(a) == 4);
	ok1(a[0] == 0);
	ok1(a[1] == 1);
	ok1(a[2] == 2);
	ok1(a[3] == 0);
	ok1(tal_first(NULL) == a && !tal_next(a) && !tal_first(a));

	tal_free(a);

	tal_cleanup();
	return exit_status();
}
