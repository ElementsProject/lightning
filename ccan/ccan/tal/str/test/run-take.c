#include <ccan/tal/str/str.h>
#include <ccan/tal/str/str.c>
#include <ccan/tap/tap.h>
#include "helper.h"

int main(void)
{
	char *parent, *c;

	plan_tests(14);

	parent = tal(NULL, char);
	ok1(parent);

	c = tal_strdup(parent, "hello");

	c = tal_strdup(parent, take(c));
	ok1(strcmp(c, "hello") == 0);
	ok1(tal_parent(c) == parent);

	c = tal_strndup(parent, take(c), 5);
	ok1(strcmp(c, "hello") == 0);
	ok1(tal_parent(c) == parent);

	c = tal_strndup(parent, take(c), 3);
	ok1(strcmp(c, "hel") == 0);
	ok1(tal_parent(c) == parent);
	tal_free(c);

	c = tal_strdup(parent, "hello %s");
	c = tal_fmt(parent, take(c), "there");
	ok1(strcmp(c, "hello there") == 0);
	ok1(tal_parent(c) == parent);
	/* No leftover allocations. */
	tal_free(c);
	ok1(no_children(parent));

	tal_free(parent);
	ok1(!taken_any());

	/* NULL pass-through. */
	c = NULL;
	ok1(tal_strdup(NULL, take(c)) == NULL);
	ok1(tal_strndup(NULL, take(c), 5) == NULL);
	ok1(tal_fmt(NULL, take(c), 0) == NULL);

	return exit_status();
}
