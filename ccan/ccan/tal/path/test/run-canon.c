#include <ccan/tal/path/path.h>
#include <ccan/tal/path/path.c>
#include <ccan/tap/tap.h>

int main(void)
{
	char cwd[1024], *path, *path2, *ctx = tal_strdup(NULL, "ctx");

	plan_tests(15);

	if (!getcwd(cwd, sizeof(cwd)))
		abort();

	unlink("run-canon-link");
	rmdir("run-canon-foo");
	if (mkdir("run-canon-foo", 0700) != 0)
		abort();
	if (symlink("run-canon-foo", "run-canon-link") != 0)
		abort();

	path = path_canon(ctx, "run-canon-foo");
	ok1(tal_parent(path) == ctx);
	ok1(strends(path, "run-canon-foo"));
	ok1(strstarts(path, cwd));
	ok1(path[strlen(cwd)] == PATH_SEP);
	ok1(strlen(path) == strlen(cwd) + 1 + strlen("run-canon-foo"));
	tal_free(path);

	ok1(!path_canon(ctx, take(NULL)));
	ok1(tal_first(ctx) == NULL);

	/* Test take doesn't leak. */
	ok1(tal_first(ctx) == NULL);
	path = path_canon(ctx, take(tal_strdup(ctx, "run-canon-foo")));
	ok1(strends(path, "run-canon-foo"));
	ok1(strstarts(path, cwd));
	ok1(path[strlen(cwd)] == PATH_SEP);
	ok1(strlen(path) == strlen(cwd) + 1 + strlen("run-canon-foo"));
	ok1(tal_first(ctx) == path && tal_next(path) == NULL);
	path2 = path_canon(ctx, "run-canon-link");
	ok1(streq(path2, path));

	unlink("run-canon-link");
	if (symlink(".", "run-canon-link") != 0)
		abort();

	path = path_canon(ctx, "run-canon-link");
	ok1(streq(path, cwd));

	tal_free(ctx);

	return exit_status();
}
