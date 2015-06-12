#include <ccan/tal/talloc/talloc.h>
#include <ccan/tal/talloc/talloc.c>
#include <ccan/tap/tap.h>

int main(void)
{
	char *parent, *c[4];
	int i, j;

	plan_tests(9);

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

	/* Free parent. */
	ok1(tal_free(parent) == NULL);

	parent = tal(NULL, char);

	/* Test freeing in every order */
	for (i = 0; i < 4; i++) {
		for (j = 0; j < 4; j++)
			c[j] = tal(parent, char);

		tal_free(c[i]);
		tal_free(c[(i+1) % 4]);
		tal_free(c[(i+2) % 4]);
		tal_free(c[(i+3) % 4]);
	}
	tal_free(parent);

	return exit_status();
}
