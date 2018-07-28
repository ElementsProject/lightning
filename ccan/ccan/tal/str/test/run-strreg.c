#include <ccan/tal/str/str.h>
#include <ccan/tal/str/str.c>
#include <ccan/tap/tap.h>
#include "helper.h"

static bool find_parent(tal_t *child, tal_t *parent)
{
	tal_t *i;

	for (i = child; i; i = tal_parent(i))
		if (i == parent)
			return true;

	return false;
}

int main(void)
{
	void *ctx = tal_strdup(NULL, "toplevel");
	char *a, *b;
	/* If it accesses this, it will crash. */
	char **invalid = (char **)1L;

	plan_tests(54);
	/* Simple matching. */
	ok1(tal_strreg(ctx, "hello world!", "hello") == true);
	ok1(tal_strreg(ctx, "hello world!", "hi") == false);

	/* No parentheses means we don't use any extra args. */
	ok1(tal_strreg(ctx, "hello world!", "hello", invalid) == true);
	ok1(tal_strreg(ctx, "hello world!", "hi", invalid) == false);

	ok1(tal_strreg(ctx, "hello world!", "[a-z]+", invalid) == true);
	ok1(tal_strreg(ctx, "hello world!", "([a-z]+)", &a, invalid) == true);
	/* Found string */
	ok1(streq(a, "hello"));
	/* Allocated off ctx */
	ok1(find_parent(a, ctx));
	ok1(tal_count(a) == strlen(a) + 1);
	tal_free(a);

	ok1(tal_strreg(ctx, "hello world!", "([a-z]*) ([a-z]+)",
		       &a, &b, invalid) == true);
	ok1(streq(a, "hello"));
	ok1(streq(b, "world"));
	ok1(tal_count(a) == strlen(a) + 1);
	ok1(tal_count(b) == strlen(b) + 1);
	ok1(find_parent(a, ctx));
	ok1(find_parent(b, ctx));
	tal_free(a);
	tal_free(b);

	/* * after parentheses returns last match. */
	ok1(tal_strreg(ctx, "hello world!", "([a-z])* ([a-z]+)",
		       &a, &b, invalid) == true);
	ok1(streq(a, "o"));
	ok1(streq(b, "world"));
	ok1(tal_count(a) == strlen(a) + 1);
	ok1(tal_count(b) == strlen(b) + 1);
	tal_free(a);
	tal_free(b);

	/* Nested parentheses are ordered by open brace. */
	ok1(tal_strreg(ctx, "hello world!", "(([a-z]*) world)",
		       &a, &b, invalid) == true);
	ok1(streq(a, "hello world"));
	ok1(streq(b, "hello"));
	ok1(tal_count(a) == strlen(a) + 1);
	ok1(tal_count(b) == strlen(b) + 1);
	tal_free(a);
	tal_free(b);

	/* Nested parentheses are ordered by open brace. */
	ok1(tal_strreg(ctx, "hello world!", "(([a-z]*) world)",
		       &a, &b, invalid) == true);
	ok1(streq(a, "hello world"));
	ok1(streq(b, "hello"));
	ok1(tal_count(a) == strlen(a) + 1);
	ok1(tal_count(b) == strlen(b) + 1);
	tal_free(a);
	tal_free(b);

	/* NULL means we're not interested. */
	ok1(tal_strreg(ctx, "hello world!", "((hello|goodbye) world)",
		       &a, NULL, invalid) == true);
	ok1(streq(a, "hello world"));
	ok1(tal_count(a) == strlen(a) + 1);
	tal_free(a);

	/* No leaks! */
	ok1(no_children(ctx));

	/* NULL arg with take means always fail. */
	ok1(tal_strreg(ctx, take(NULL), "((hello|goodbye) world)",
		       &b, NULL, invalid) == false);

	/* Take string. */
	a = tal_strdup(ctx, "hello world!");
	ok1(tal_strreg(ctx, take(a), "([a-z]+)", &b, invalid) == true);
	ok1(streq(b, "hello"));
	ok1(tal_count(b) == strlen(b) + 1);
	ok1(tal_parent(b) == ctx);
	tal_free(b);
	ok1(no_children(ctx));

	/* Take regex. */
	a = tal_strdup(ctx, "([a-z]+)");
	ok1(tal_strreg(ctx, "hello world!", take(a), &b, invalid) == true);
	ok1(streq(b, "hello"));
	ok1(tal_count(b) == strlen(b) + 1);
	ok1(tal_parent(b) == ctx);
	tal_free(b);
	ok1(no_children(ctx));

	/* Take both. */
	a = tal_strdup(ctx, "([a-z]+)");
	ok1(tal_strreg(ctx, take(tal_strdup(ctx, "hello world!")),
		       take(a), &b, invalid) == true);
	ok1(streq(b, "hello"));
	ok1(tal_count(b) == strlen(b) + 1);
	ok1(tal_parent(b) == ctx);
	tal_free(b);
	ok1(no_children(ctx));

	/* ... even if we fail to match. */
	a = tal_strdup(ctx, "([a-z]+)");
	ok1(tal_strreg(ctx, take(tal_strdup(ctx, "HELLO WORLD!")),
		       take(a), &b, invalid) == false);
	ok1(no_children(ctx));
	tal_free(ctx);

	/* Don't get fooled by \(! */
	ok1(tal_strreg(ctx, "(hello) (world)!", "\\([a-z]*\\) \\([a-z]+\\)",
		       invalid) == true);

	return exit_status();
}
