#include <ccan/tal/path/path.h>
#include <ccan/tal/path/path.c>
#include <ccan/tap/tap.h>

int main(void)
{
	char cwd[1024], *path, *parent, *tmpbase, *ctx = tal_strdup(NULL, "ctx");
	const char *realtmp;

	plan_tests(95);

	if (!getcwd(cwd, sizeof(cwd)))
		abort();

	rmdir("run-simplify-foo");
	unlink("run-simplify-link");
	if (mkdir("run-simplify-foo", 0700) != 0)
		abort();
	if (symlink("run-simplify-foo", "run-simplify-link") != 0)
		abort();

	/* /tmp can itself be a symlink (e.g. to /private/tmp on macOS),
	 * which would make path_simplify() keep ".." literally instead of
	 * collapsing it.  Resolve it, so the tests below always exercise a
	 * real directory. */
	realtmp = path_canon(ctx, "/tmp");
	parent = path_dirname(ctx, realtmp);
	tmpbase = path_basename(ctx, realtmp);

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
	path = path_simplify(ctx, realtmp);
	ok1(streq(path, realtmp));
	ok1(tal_parent(path) == ctx);
	tal_free(path);

	path = path_simplify(ctx, take(tal_fmt(ctx, "%s/", realtmp)));
	ok1(streq(path, realtmp));
	ok1(tal_parent(path) == ctx);
	tal_free(path);

	path = path_simplify(ctx, take(tal_fmt(ctx, "%s/.", realtmp)));
	ok1(streq(path, realtmp));
	ok1(tal_parent(path) == ctx);
	tal_free(path);

	path = path_simplify(ctx, take(tal_fmt(ctx, "/.%s/.", realtmp)));
	ok1(streq(path, realtmp));
	ok1(tal_parent(path) == ctx);
	tal_free(path);

	path = path_simplify(ctx, take(tal_fmt(ctx, "/..%s/.", realtmp)));
	ok1(streq(path, realtmp));
	ok1(tal_parent(path) == ctx);
	tal_free(path);

	path = path_simplify(ctx, take(tal_fmt(ctx, "%s/..", realtmp)));
	ok1(streq(path, parent));
	ok1(tal_parent(path) == ctx);
	tal_free(path);

	path = path_simplify(ctx, take(tal_fmt(ctx, "%s/../", realtmp)));
	ok1(streq(path, parent));
	ok1(tal_parent(path) == ctx);
	tal_free(path);

	path = path_simplify(ctx, take(tal_fmt(ctx, "%s/../%s", realtmp, tmpbase)));
	ok1(streq(path, realtmp));
	ok1(tal_parent(path) == ctx);
	tal_free(path);

	path = path_simplify(ctx, take(tal_fmt(ctx, "%s/../%s/", realtmp, tmpbase)));
	ok1(streq(path, realtmp));
	ok1(tal_parent(path) == ctx);
	tal_free(path);

	path = path_simplify(ctx, take(tal_fmt(ctx, "%s/../%s/.", realtmp, tmpbase)));
	ok1(streq(path, realtmp));
	ok1(tal_parent(path) == ctx);
	tal_free(path);

	/* Don't trace back over a symlink: keep ".." literally. */
	path = path_simplify(ctx, "run-simplify-link/..");
	ok1(streq(path, "run-simplify-link/.."));
	ok1(tal_parent(path) == ctx);
	tal_free(path);

	path = path_simplify(ctx, "run-simplify-link/../");
	ok1(streq(path, "run-simplify-link/.."));
	ok1(tal_parent(path) == ctx);
	tal_free(path);

	path = path_simplify(ctx, "run-simplify-link/../x");
	ok1(streq(path, "run-simplify-link/../x"));
	ok1(tal_parent(path) == ctx);
	tal_free(path);

	path = path_simplify(ctx, "run-simplify-link/../../foo");
	ok1(streq(path, "run-simplify-link/../../foo"));
	ok1(tal_parent(path) == ctx);
	tal_free(path);

	/* Nonexistent path: can't prove it's a real dir, keep "..". */
	path = path_simplify(ctx, "run-simplify-nosuch/..");
	ok1(streq(path, "run-simplify-nosuch/.."));
	ok1(tal_parent(path) == ctx);
	tal_free(path);

	/* take tests */
	path = path_simplify(ctx, take(tal_fmt(ctx, "%s/../%s/.", realtmp, tmpbase)));
	ok1(streq(path, realtmp));
	ok1(tal_parent(path) == ctx);
	tal_free(path);
	tal_free(parent);
	tal_free(tmpbase);
	tal_free(realtmp);
	ok1(tal_first(ctx) == NULL);

	tal_free(ctx);

	return exit_status();
}
