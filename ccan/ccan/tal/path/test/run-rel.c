#include <ccan/tal/path/path.h>
#include <ccan/tal/path/path.c>
#include <ccan/tap/tap.h>

int main(void)
{
	char cwd[1024], *path, *ctx = tal_strdup(NULL, "ctx");

	plan_tests(19);

	if (!getcwd(cwd, sizeof(cwd)))
		abort();

	unlink("run-rel-link");
	rmdir("run-rel-foo");
	if (mkdir("run-rel-foo", 0700) != 0)
		abort();
	if (symlink("run-rel-foo", "run-rel-link") != 0)
		abort();

	path = path_rel(ctx, ".", "run-rel-foo");
	ok1(streq(path, "run-rel-foo"));
	ok1(tal_parent(path) == ctx);
	tal_free(path);

	path = path_rel(ctx, "run-rel-foo", ".");
	ok1(streq(path, ".."));
	ok1(tal_parent(path) == ctx);
	tal_free(path);

	path = path_rel(ctx, ".", "run-rel-link");
	/* This doesn't specify whether it preserves links. */
	ok1(streq(path, "run-rel-link") || streq(path, "run-rel-foo"));
	ok1(tal_parent(path) == ctx);
	tal_free(path);

	path = path_rel(ctx, "/", ".");
	ok1(streq(path, cwd + 1));
	ok1(tal_parent(path) == ctx);
	tal_free(path);

	path = path_rel(ctx, "run-rel-foo", "run-rel-foo");
	ok1(streq(path, "."));
	ok1(tal_parent(path) == ctx);
	tal_free(path);

	path = path_rel(ctx, take(tal_strdup(ctx, ".")), "run-rel-foo");
	ok1(streq(path, "run-rel-foo"));
	ok1(tal_parent(path) == ctx);
	tal_free(path);
	ok1(tal_first(ctx) == NULL);

	path = path_rel(ctx, ".", take(tal_strdup(ctx, "run-rel-foo")));
	ok1(streq(path, "run-rel-foo"));
	ok1(tal_parent(path) == ctx);
	tal_free(path);
	ok1(tal_first(ctx) == NULL);

	path = path_rel(ctx, take(tal_strdup(ctx, ".")),
			take(tal_strdup(ctx, "run-rel-foo")));
	ok1(streq(path, "run-rel-foo"));
	ok1(tal_parent(path) == ctx);
	tal_free(path);
	ok1(tal_first(ctx) == NULL);

	tal_free(ctx);

	return exit_status();
}
