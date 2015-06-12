#include <ccan/tal/path/path.h>
#include <ccan/tal/path/path.c>
#include <ccan/tap/tap.h>

int main(void)
{
	char path1[1024], *cwd, *ctx = tal_strdup(NULL, "ctx");

	/* This is how many tests you plan to run */
	plan_tests(5);

	if (!getcwd(path1, sizeof(path1)))
		abort();

	cwd = path_cwd(ctx);
	ok1(cwd);
	ok1(tal_parent(cwd) == ctx);
	tal_free(cwd);

	rmdir("run-cwd-long-long-long-name/bar-long-long-long-long-name");
	rmdir("run-cwd-long-long-long-name");
	if (mkdir("run-cwd-long-long-long-name", 0700) != 0)
		abort();
	if (mkdir("run-cwd-long-long-long-name/bar-long-long-long-long-name", 0700) != 0)
		abort();
	if (chdir("run-cwd-long-long-long-name/bar-long-long-long-long-name") != 0)
		abort();

	cwd = path_cwd(ctx);
	ok1(cwd);
	ok1(tal_parent(cwd) == ctx);
	ok1(strends(cwd,
		    "run-cwd-long-long-long-name/bar-long-long-long-long-name"));
	tal_free(ctx);

	return exit_status();
}
