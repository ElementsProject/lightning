#include <ccan/tal/path/path.h>
#include <ccan/tal/path/path.c>
#include <ccan/tap/tap.h>

int main(void)
{
	char *link, *ctx = tal_strdup(NULL, "ctx");

	plan_tests(12);

	unlink("run-readlink-link");

	link = path_readlink(ctx, "run-readlink-link");
	ok1(errno == ENOENT);
	ok1(!link);

	link = path_readlink(ctx, take(tal_strdup(ctx, "run-readlink-link")));
	ok1(errno == ENOENT);
	ok1(!link);
	ok1(tal_first(ctx) == NULL);

	if (symlink("/tmp", "run-readlink-link") != 0)
		abort();

	link = path_readlink(ctx, "run-readlink-link");
	ok1(tal_parent(link) == ctx);
	ok1(streq(link, "/tmp"));
	tal_free(link);

	link = path_readlink(ctx, take(tal_strdup(ctx, "run-readlink-link")));
	ok1(tal_parent(link) == ctx);
	ok1(streq(link, "/tmp"));
	ok1(tal_first(ctx) == link && tal_next(link) == NULL && tal_first(link) == NULL);

	unlink("run-readlink-link");

	if (symlink("some-really-really-really-really-really-really-really-really-really-really-really-really-really-really-really-really-really-really-really-really-really-really-really-really-really-really-really-really-really-really-long-name", "run-readlink-link") != 0)
		abort();

	link = path_readlink(ctx, "run-readlink-link");
	ok1(tal_parent(link) == ctx);
	ok1(streq(link, "some-really-really-really-really-really-really-really-really-really-really-really-really-really-really-really-really-really-really-really-really-really-really-really-really-really-really-really-really-really-really-long-name"));
	tal_free(ctx);

	return exit_status();
}
