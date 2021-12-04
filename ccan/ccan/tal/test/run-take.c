#include <ccan/tal/tal.h>
#include <ccan/tal/tal.c>
#include <ccan/tap/tap.h>

int main(void)
{
	char *parent, *c;

	plan_tests(22);

	/* We can take NULL. */
	ok1(take(NULL) == NULL);
	ok1(is_taken(NULL));
	ok1(taken(NULL)); /* Undoes take() */
	ok1(!is_taken(NULL));
	ok1(!taken(NULL));

	parent = tal(NULL, char);
	ok1(parent);

	ok1(take(parent) == parent);
	ok1(is_taken(parent));
	ok1(taken(parent)); /* Undoes take() */
	ok1(!is_taken(parent));
	ok1(!taken(parent));

	c = tal(parent, char);
	*c = 'h';
	c = tal_dup(parent, char, take(c));
	ok1(c[0] == 'h');
	ok1(tal_parent(c) == parent);

	c = tal_dup_arr(parent, char, take(c), 1, 2);
	ok1(c[0] == 'h');
	strcpy(c, "hi");
	ok1(tal_parent(c) == parent);

	/* dup must reparent child. */
	c = tal_dup(NULL, char, take(c));
	ok1(c[0] == 'h');
	ok1(tal_parent(c) == NULL);

	/* No leftover allocations. */
	tal_free(c);
	ok1(tal_first(parent) == NULL);

	/* tal_resize should return a taken pointer. */
	c = take(tal_arr(parent, char, 5));
	tal_resize(&c, 100);
	ok1(taken(c));
	tal_free(c);

	tal_free(parent);
	ok1(!taken_any());

	/* NULL pass-through. */
	c = NULL;
	ok1(tal_dup_arr(NULL, char, take(c), 5, 5) == NULL);
	ok1(!taken_any());

	tal_cleanup();
	return exit_status();
}
