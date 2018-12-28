#include <ccan/tal/tal.h>
#include <ccan/tal/tal.c>
#include <ccan/tap/tap.h>

int main(void)
{
	char *parent, *c[4], *p;
	int i, j;

	plan_tests(14);

	/* tal_free(NULL) works. */
	ok1(tal_free(NULL) == NULL);

	parent = tal(NULL, char);
	ok1(parent);
	ok1(tal_parent(parent) == NULL);
	ok1(tal_parent(NULL) == NULL);

	for (i = 0; i < 4; i++)
		c[i] = tal(parent, char);

	for (i = 0; i < 4; i++)
		ok1(tal_parent(c[i]) == parent);

	/* Iteration test. */
	i = 0;
	for (p = tal_first(parent); p; p = tal_next(p)) {
		*p = '1';
		i++;
	}
	ok1(i == 4);
	ok1(*c[0] == '1');
	ok1(*c[1] == '1');
	ok1(*c[2] == '1');
	ok1(*c[3] == '1');

	/* Free parent. */
	ok1(tal_free(parent) == NULL);

	parent = tal(NULL, char);

	/* Test freeing in every order */
	for (i = 0; i < 4; i++) {
		for (j = 0; j < 4; j++)
			c[j] = tal(parent, char);

		tal_free(c[i]);
		debug_tal(to_tal_hdr(parent));
		tal_free(c[(i+1) % 4]);
		debug_tal(to_tal_hdr(parent));
		tal_free(c[(i+2) % 4]);
		debug_tal(to_tal_hdr(parent));
		tal_free(c[(i+3) % 4]);
		debug_tal(to_tal_hdr(parent));
	}
	tal_free(parent);

	tal_cleanup();
	return exit_status();
}
