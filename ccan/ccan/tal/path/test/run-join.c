#include <ccan/tal/path/path.h>
#include <ccan/tal/path/path.c>
#include <ccan/tap/tap.h>

int main(void)
{
	char *path, *ctx = tal_strdup(NULL, "ctx");

	plan_tests(36);

	path = path_join(ctx, "foo", "bar");
	ok1(streq(path, "foo/bar"));
	ok1(tal_parent(path) == ctx);
	tal_free(path);

	path = path_join(ctx, "foo/", "bar");
	ok1(streq(path, "foo/bar"));
	ok1(tal_parent(path) == ctx);
	tal_free(path);

	path = path_join(ctx, "foo/", "/bar");
	ok1(streq(path, "/bar"));
	ok1(tal_parent(path) == ctx);
	tal_free(path);

	path = path_join(ctx, "foo", "/bar");
	ok1(streq(path, "/bar"));
	ok1(tal_parent(path) == ctx);
	tal_free(path);

	/* Test take */
	path = path_join(ctx, "foo", take(tal_strdup(ctx, "bar")));
	ok1(streq(path, "foo/bar"));
	ok1(tal_parent(path) == ctx);
	ok1(tal_first(ctx) == path && tal_next(path) == NULL && tal_first(path) == NULL);
	tal_free(path);

	path = path_join(ctx, "foo", take(tal_strdup(ctx, "/bar")));
	ok1(streq(path, "/bar"));
	ok1(tal_parent(path) == ctx);
	ok1(tal_first(ctx) == path && tal_next(path) == NULL && tal_first(path) == NULL);
	tal_free(path);

	path = path_join(ctx, take(tal_strdup(ctx, "foo")), "bar");
	ok1(streq(path, "foo/bar"));
	ok1(tal_parent(path) == ctx);
	ok1(tal_first(ctx) == path && tal_next(path) == NULL && tal_first(path) == NULL);
	tal_free(path);

	path = path_join(ctx, take(tal_strdup(ctx, "foo")), "/bar");
	ok1(streq(path, "/bar"));
	ok1(tal_parent(path) == ctx);
	ok1(tal_first(ctx) == path && tal_next(path) == NULL && tal_first(path) == NULL);
	tal_free(path);

	path = path_join(ctx, take(tal_strdup(ctx, "foo")),
			 take(tal_strdup(ctx, "bar")));
	ok1(streq(path, "foo/bar"));
	ok1(tal_parent(path) == ctx);
	ok1(tal_first(ctx) == path && tal_next(path) == NULL && tal_first(path) == NULL);
	tal_free(path);

	path = path_join(ctx, take(tal_strdup(ctx, "foo")),
			 take(tal_strdup(ctx, "/bar")));
	ok1(streq(path, "/bar"));
	ok1(tal_parent(path) == ctx);
	ok1(tal_first(ctx) == path && tal_next(path) == NULL && tal_first(path) == NULL);
	tal_free(path);

	path = path_join(ctx, take(NULL), "bar");
	ok1(!path);
	ok1(!tal_first(ctx));

	/* This is allowed to succeed, as first arg unneeded. */
	path = path_join(ctx, take(NULL), "/bar");
	ok1(!path || streq(path, "/bar"));
	tal_free(path);
	ok1(!tal_first(ctx));

	path = path_join(ctx, "foo", take(NULL));
	ok1(!path);
	ok1(!tal_first(ctx));

	path = path_join(ctx, take(NULL), take(NULL));
	ok1(!path);
	ok1(!tal_first(ctx));

	path = path_join(ctx, "", "bar");
	ok1(streq(path, "bar"));
	ok1(tal_parent(path) == ctx);
	tal_free(path);

	tal_free(ctx);

	return exit_status();
}
