#include <ccan/tal/path/path.h>
#include <ccan/tal/path/path.c>
#include <ccan/tap/tap.h>

int main(void)
{
	char cwd[1024], *path, *ctx = tal_strdup(NULL, "ctx");

	plan_tests(87);

	if (!getcwd(cwd, sizeof(cwd)))
		abort();

	rmdir("run-simplify-foo");
	unlink("run-simplify-link");
	if (mkdir("run-simplify-foo", 0700) != 0)
		abort();
	if (symlink("run-simplify-foo", "run-simplify-link") != 0)
		abort();

	/* Handling of . and .. */
	path = path_simplify(ctx, ".");
	ok1(streq(path, "."));
	ok1(tal_parent(path) == ctx);
	tal_free(path);

	path = path_simplify(ctx, "./");
	ok1(streq(path, "."));
	ok1(tal_parent(path) == ctx);
	tal_free(path);

	path = path_simplify(ctx, "..");
	ok1(streq(path, ".."));
	ok1(tal_parent(path) == ctx);
	tal_free(path);

	path = path_simplify(ctx, "../");
	ok1(streq(path, ".."));
	ok1(tal_parent(path) == ctx);
	tal_free(path);

	path = path_simplify(ctx, "./..");
	ok1(streq(path, ".."));
	ok1(tal_parent(path) == ctx);
	tal_free(path);

	path = path_simplify(ctx, "./../");
	ok1(streq(path, ".."));
	ok1(tal_parent(path) == ctx);
	tal_free(path);

	path = path_simplify(ctx, "./../.");
	ok1(streq(path, ".."));
	ok1(tal_parent(path) == ctx);
	tal_free(path);

	path = path_simplify(ctx, "./.././");
	ok1(streq(path, ".."));
	ok1(tal_parent(path) == ctx);
	tal_free(path);

	path = path_simplify(ctx, "./../..");
	ok1(streq(path, "../.."));
	ok1(tal_parent(path) == ctx);
	tal_free(path);

	path = path_simplify(ctx, "./../../");
	ok1(streq(path, "../.."));
	ok1(tal_parent(path) == ctx);
	tal_free(path);

	/* Handling of /. and /.. */
	path = path_simplify(ctx, "/");
	ok1(streq(path, "/"));
	ok1(tal_parent(path) == ctx);
	tal_free(path);

	path = path_simplify(ctx, "//");
	ok1(streq(path, "/"));
	ok1(tal_parent(path) == ctx);
	tal_free(path);

	path = path_simplify(ctx, "/.");
	ok1(streq(path, "/"));
	ok1(tal_parent(path) == ctx);
	tal_free(path);

	path = path_simplify(ctx, "/./");
	ok1(streq(path, "/"));
	ok1(tal_parent(path) == ctx);
	tal_free(path);

	path = path_simplify(ctx, "/..");
	ok1(streq(path, "/"));
	ok1(tal_parent(path) == ctx);
	tal_free(path);

	path = path_simplify(ctx, "/../");
	ok1(streq(path, "/"));
	ok1(tal_parent(path) == ctx);
	tal_free(path);

	path = path_simplify(ctx, "/./..");
	ok1(streq(path, "/"));
	ok1(tal_parent(path) == ctx);
	tal_free(path);

	path = path_simplify(ctx, "/./../");
	ok1(streq(path, "/"));
	ok1(tal_parent(path) == ctx);
	tal_free(path);

	path = path_simplify(ctx, "/./../.");
	ok1(streq(path, "/"));
	ok1(tal_parent(path) == ctx);
	tal_free(path);

	path = path_simplify(ctx, "/./.././");
	ok1(streq(path, "/"));
	ok1(tal_parent(path) == ctx);
	tal_free(path);

	path = path_simplify(ctx, "/./../..");
	ok1(streq(path, "/"));
	ok1(tal_parent(path) == ctx);
	tal_free(path);

	path = path_simplify(ctx, "/./../../");
	ok1(streq(path, "/"));
	ok1(tal_parent(path) == ctx);
	tal_free(path);

	/* Don't trace back over a symlink link */
	path = path_simplify(ctx, "run-simplify-foo");
	ok1(streq(path, "run-simplify-foo"));
	ok1(tal_parent(path) == ctx);
	tal_free(path);

	path = path_simplify(ctx, "./run-simplify-foo");
	ok1(streq(path, "run-simplify-foo"));
	ok1(tal_parent(path) == ctx);
	tal_free(path);

	path = path_simplify(ctx, "./run-simplify-foo/.");
	ok1(streq(path, "run-simplify-foo"));
	ok1(tal_parent(path) == ctx);
	tal_free(path);

	path = path_simplify(ctx, "run-simplify-link");
	ok1(streq(path, "run-simplify-link"));
	ok1(tal_parent(path) == ctx);
	tal_free(path);

	path = path_simplify(ctx, "./run-simplify-link");
	ok1(streq(path, "run-simplify-link"));
	ok1(tal_parent(path) == ctx);
	tal_free(path);

	path = path_simplify(ctx, "./run-simplify-link/.");
	ok1(streq(path, "run-simplify-link"));
	ok1(tal_parent(path) == ctx);
	tal_free(path);

	path = path_simplify(ctx, "run-simplify-foo/..");
	ok1(streq(path, "."));
	ok1(tal_parent(path) == ctx);
	tal_free(path);

	path = path_simplify(ctx, "run-simplify-foo//..");
	ok1(streq(path, "."));
	ok1(tal_parent(path) == ctx);
	tal_free(path);

	path = path_simplify(ctx, "run-simplify-foo//../");
	ok1(streq(path, "."));
	ok1(tal_parent(path) == ctx);
	tal_free(path);

	/* This is expected to be a real directory. */
	path = path_simplify(ctx, "/tmp");
	ok1(streq(path, "/tmp"));
	ok1(tal_parent(path) == ctx);
	tal_free(path);

	path = path_simplify(ctx, "/tmp/");
	ok1(streq(path, "/tmp"));
	ok1(tal_parent(path) == ctx);
	tal_free(path);

	path = path_simplify(ctx, "/tmp/.");
	ok1(streq(path, "/tmp"));
	ok1(tal_parent(path) == ctx);
	tal_free(path);

	path = path_simplify(ctx, "/./tmp/.");
	ok1(streq(path, "/tmp"));
	ok1(tal_parent(path) == ctx);
	tal_free(path);

	path = path_simplify(ctx, "/../tmp/.");
	ok1(streq(path, "/tmp"));
	ok1(tal_parent(path) == ctx);
	tal_free(path);

	path = path_simplify(ctx, "/tmp/..");
	ok1(streq(path, "/"));
	ok1(tal_parent(path) == ctx);
	tal_free(path);

	path = path_simplify(ctx, "/tmp/../");
	ok1(streq(path, "/"));
	ok1(tal_parent(path) == ctx);
	tal_free(path);

	path = path_simplify(ctx, "/tmp/../tmp");
	ok1(streq(path, "/tmp"));
	ok1(tal_parent(path) == ctx);
	tal_free(path);

	path = path_simplify(ctx, "/tmp/../tmp/");
	ok1(streq(path, "/tmp"));
	ok1(tal_parent(path) == ctx);
	tal_free(path);

	path = path_simplify(ctx, "/tmp/../tmp/.");
	ok1(streq(path, "/tmp"));
	ok1(tal_parent(path) == ctx);
	tal_free(path);

	/* take tests */
	path = path_simplify(ctx, take(tal_strdup(ctx, "/tmp/../tmp/.")));
	ok1(streq(path, "/tmp"));
	ok1(tal_parent(path) == ctx);
	tal_free(path);
	ok1(tal_first(ctx) == NULL);

	path = path_simplify(ctx, take(NULL));
	ok1(!path);
	ok1(tal_first(ctx) == NULL);

	tal_free(ctx);

	return exit_status();
}
