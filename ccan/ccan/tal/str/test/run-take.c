#include <ccan/tal/str/str.h>
#include <ccan/tal/str/str.c>
#include <ccan/tap/tap.h>
#include "helper.h"

int main(void)
{
	char *parent, *c;

	plan_tests(11);

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

	return exit_status();
}
