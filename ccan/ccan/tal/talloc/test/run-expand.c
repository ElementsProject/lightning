#include <ccan/tal/talloc/talloc.h>
#include <ccan/tal/talloc/talloc.c>
#include <ccan/tap/tap.h>

int main(void)
{
	int *a;
	const int arr[] = { 1, 2 };

	plan_tests(14);
	talloc_enable_null_tracking_no_autofree();

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
	ok1(talloc_total_blocks(NULL) == 2);
	ok1(talloc_total_blocks(a) == 1);

	tal_free(a);

	talloc_disable_null_tracking();
	return exit_status();
}
