#include <ccan/tal/tal.h>
#include <ccan/tal/tal.c>
#include <ccan/tap/tap.h>

int main(void)
{
	char *p[5];
	unsigned int i;

	plan_tests(9);

	p[0] = tal(NULL, char);
	for (i = 1; i < 5; i++)
		p[i] = tal(p[i-1], char);

	tal_check(NULL, "check");
	/* Steal node with no children. */
	ok1(tal_steal(p[0], p[4]) == p[4]);
	tal_check(NULL, "check");
	/* Noop steal. */
	ok1(tal_steal(p[0], p[4]) == p[4]);
	tal_check(NULL, "check");
	/* Steal with children. */
	ok1(tal_steal(p[0], p[1]) == p[1]);
	tal_check(NULL, "check");
	/* Noop steal. */
	ok1(tal_steal(p[0], p[1]) == p[1]);
	tal_check(NULL, "check");
	/* Steal from direct child. */
	ok1(tal_steal(p[0], p[2]) == p[2]);
	tal_check(NULL, "check");

	ok1(tal_parent(p[1]) == p[0]);
	ok1(tal_parent(p[2]) == p[0]);
	ok1(tal_parent(p[3]) == p[2]);
	ok1(tal_parent(p[4]) == p[0]);
	tal_free(p[0]);

	tal_cleanup();
	return exit_status();
}
