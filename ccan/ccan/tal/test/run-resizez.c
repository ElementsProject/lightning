#include <ccan/tal/tal.h>
#include <ccan/tal/tal.c>
#include <ccan/tap/tap.h>

int main(void)
{
	char *parent, *c;
	int i;

	plan_tests(1 + 3 * 100 + 98);

	parent = tal(NULL, char);
	ok1(parent);

	for (i = 0; i < 100; i++) {
		c = tal_arr(parent, char, 1);
		ok1(tal_resizez(&c, i));
		ok1(tal_count(c) == i);
		ok1(tal_parent(c) == parent);
		if (i > 1)
			ok1(c[i-1] == '\0');
	}
	tal_free(parent);

	tal_cleanup();
	return exit_status();
}
