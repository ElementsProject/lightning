#include <ccan/tal/path/path.h>
#include <ccan/tal/path/path.c>
#include <ccan/tap/tap.h>

int main(void)
{
	char *path, *ctx = tal_strdup(NULL, "ctx");

	plan_tests(26);

	path = path_dirname(ctx, "/usr/lib");
	ok1(streq(path, "/usr"));
	ok1(tal_parent(path) == ctx);
	path = path_dirname(ctx, "/usr/");
	ok1(streq(path, "/"));
	ok1(tal_parent(path) == ctx);
	path = path_dirname(ctx, "/usr//");
	ok1(streq(path, "/"));
	ok1(tal_parent(path) == ctx);
	path = path_dirname(ctx, "usr");
	ok1(streq(path, "."));
	ok1(tal_parent(path) == ctx);
	path = path_dirname(ctx, "/");
	ok1(streq(path, "/"));
	ok1(tal_parent(path) == ctx);
	path = path_dirname(ctx, "//");
	ok1(streq(path, "/"));
	ok1(tal_parent(path) == ctx);
	path = path_dirname(ctx, ".");
	ok1(streq(path, "."));
	ok1(tal_parent(path) == ctx);
	path = path_dirname(ctx, "./");
	ok1(streq(path, "."));
	ok1(tal_parent(path) == ctx);
	path = path_dirname(ctx, "..");
	ok1(streq(path, "."));
	ok1(tal_parent(path) == ctx);
	path = path_dirname(ctx, "../");
	ok1(streq(path, "."));
	ok1(tal_parent(path) == ctx);
	tal_free(ctx);

	ctx = tal_strdup(NULL, "ctx");
	ok1(!tal_first(ctx));

	/* Test take */
	path = path_dirname(ctx, take(tal_strdup(ctx, "..")));
	ok1(streq(path, "."));
	ok1(tal_parent(path) == ctx);
	ok1(tal_first(ctx) == path && !tal_next(path));
	tal_free(path);
	ok1(path_dirname(ctx, take(NULL)) == NULL);
	ok1(!tal_first(ctx));

	tal_free(ctx);

	return exit_status();
}
