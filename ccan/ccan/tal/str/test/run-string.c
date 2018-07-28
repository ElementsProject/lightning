#include <ccan/tal/str/str.h>
#include <ccan/tal/str/str.c>
#include <ccan/tap/tap.h>
#include "helper.h"

int main(void)
{
	char *parent, *c;

	plan_tests(43);

	parent = tal(NULL, char);
	ok1(parent);

	c = tal_strdup(parent, "hello");
	ok1(strcmp(c, "hello") == 0);
	ok1(tal_parent(c) == parent);
	ok1(tal_count(c) == strlen(c) + 1);
	tal_free(c);

	c = tal_strndup(parent, "hello", 3);
	ok1(strcmp(c, "hel") == 0);
	ok1(tal_parent(c) == parent);
	ok1(tal_count(c) == strlen(c) + 1);
	tal_free(c);

#ifdef TAL_USE_TALLOC
	c = tal_talloc_typechk_(parent, char *);
#else
	c = tal_typechk_(parent, char *);
#endif
	c = tal_dup_arr(parent, char, "hello", 6, 0);
	ok1(strcmp(c, "hello") == 0);
	ok1(strcmp(tal_name(c), "char[]") == 0);
	ok1(tal_count(c) == 6);
	ok1(tal_parent(c) == parent);
	tal_free(c);

	/* Now with an extra byte. */
	c = tal_dup_arr(parent, char, "hello", 6, 1);
	ok1(strcmp(c, "hello") == 0);
	ok1(strcmp(tal_name(c), "char[]") == 0);
	ok1(tal_count(c) == 7);
	ok1(tal_parent(c) == parent);
	strcat(c, "x");
	tal_free(c);

	c = tal_fmt(parent, "hello %s", "there");
	ok1(strcmp(c, "hello there") == 0);
	ok1(tal_count(c) == strlen(c) + 1);
	ok1(tal_parent(c) == parent);
	tal_free(c);

	c = tal_strcat(parent, "hello ", "there");
	ok1(strcmp(c, "hello there") == 0);
	ok1(tal_count(c) == strlen(c) + 1);
	ok1(tal_parent(c) == parent);

	/* Make sure take works correctly. */
	c = tal_strcat(parent, take(c), " again");
	ok1(strcmp(c, "hello there again") == 0);
	ok1(tal_count(c) == strlen(c) + 1);
	ok1(tal_parent(c) == parent);
	ok1(single_child(parent, c));

	c = tal_strcat(parent, "And ", take(c));
	ok1(tal_count(c) == strlen(c) + 1);
	ok1(strcmp(c, "And hello there again") == 0);
	ok1(tal_parent(c) == parent);
	ok1(single_child(parent, c));

	/* NULL pass through works... */
	c = tal_strcat(parent, take(NULL), take(c));
	ok1(!c);
	ok1(no_children(parent));

	c = tal_strcat(parent, take(tal_strdup(parent, "hi")),
		       take(NULL));
	ok1(!c);
	ok1(no_children(parent));

	c = tal_strcat(parent, take(NULL), take(NULL));
	ok1(!c);
	ok1(no_children(parent));

	/* Appending formatted strings. */
	c = tal_strdup(parent, "hi");
	ok1(tal_count(c) == strlen(c) + 1);
	ok1(tal_append_fmt(&c, "%s %s", "there", "world"));
	ok1(strcmp(c, "hithere world") == 0);
	ok1(tal_count(c) == strlen(c) + 1);
	ok1(tal_parent(c) == parent);

	ok1(!tal_append_fmt(&c, take(NULL), "there", "world"));
	ok1(strcmp(c, "hithere world") == 0);
	ok1(tal_count(c) == strlen(c) + 1);

	tal_free(parent);

	return exit_status();
}
