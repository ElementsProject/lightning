#include <ccan/tal/path/path.h>
#include <ccan/tal/path/path.c>
#include <ccan/tap/tap.h>

int main(void)
{
	struct path_pushd *pd;
	char path1[1024], path2[1024], *ctx = tal_strdup(NULL, "ctx");

	/* This is how many tests you plan to run */
	plan_tests(19);

	/* Test pushd/popd */
	if (!getcwd(path1, sizeof(path1)))
		abort();

	pd = path_pushd(NULL, "non-existent-dir");
	ok1(errno == ENOENT);
	ok1(!pd);

	errno = -100;
	pd = path_pushd(ctx, take(tal_strdup(ctx, "non-existent-dir")));
	ok1(errno == ENOENT);
	ok1(!pd);
	ok1(!tal_first(ctx));

	errno = -100;
	pd = path_pushd(ctx, take(NULL));
	ok1(!pd);
	ok1(!tal_first(ctx));
	ok1(errno == -100);

	pd = path_pushd(ctx, "/tmp");
	ok1(pd);
	ok1(tal_parent(pd) == ctx);

	if (!getcwd(path2, sizeof(path2)))
		abort();

	ok1(streq(path2, "/tmp"));
	path_popd(pd);

	if (!getcwd(path2, sizeof(path2)))
		abort();
	ok1(streq(path2, path1));

	pd = path_pushd(ctx, take(tal_strdup(ctx, "/tmp")));
	ok1(pd);
	ok1(tal_parent(pd) == ctx);
	path_popd(pd);
	if (!getcwd(path2, sizeof(path2)))
		abort();
	ok1(streq(path2, path1));
	ok1(!tal_first(ctx));

	/* Without fchdir, we can't push a path which no longer exists. */
	if (mkdir("run-pushd-dir", 0700) != 0)
		abort();
	if (chdir("run-pushd-dir") != 0)
		abort();
	if (rmdir("../run-pushd-dir") != 0)
		abort();

	pd = path_pushd(ctx, path1);
#if HAVE_FCHDIR
	ok1(pd);
	ok1(path_popd(pd));
#else
	ok1(errno == ENOENT);
	ok1(!pd);
#endif
	ok1(!tal_first(ctx));
	tal_free(ctx);
	return exit_status();
}
