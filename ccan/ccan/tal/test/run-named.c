#include <ccan/tal/tal.h>
#include <ccan/tal/tal.c>
#include <ccan/tap/tap.h>

int main(void)
{
	int *p;
	char name[] = "test name";

	plan_tests(6);

	p = tal(NULL, int);
	ok1(strcmp(tal_name(p), "int") == 0);

	tal_set_name(p, "some literal");
	ok1(strcmp(tal_name(p), "some literal") == 0);

	tal_set_name(p, name);
	ok1(strcmp(tal_name(p), name) == 0);
	/* You can't reuse my pointer though! */
	ok1(tal_name(p) != name);

	tal_set_name(p, "some other literal");
	ok1(strcmp(tal_name(p), "some other literal") == 0);

	tal_free(p);

	p = tal_arr(NULL, int, 2);
	ok1(strcmp(tal_name(p), "int[]") == 0);
	tal_free(p);

	tal_cleanup();
	return exit_status();
}
