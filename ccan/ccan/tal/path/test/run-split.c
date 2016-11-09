#include <ccan/tal/path/path.h>
#include <ccan/tal/path/path.c>
#include <ccan/tap/tap.h>

int main(void)
{
	char *ctx = tal_strdup(NULL, "ctx"), **split;

	plan_tests(46);

	split = path_split(ctx, "foo" PATH_SEP_STR "bar");
	ok1(tal_parent(split) == ctx);
	ok1(streq(split[0], "foo"));
	ok1(streq(split[1], "bar"));
	ok1(split[2] == NULL);
	tal_free(split);

	split = path_split(ctx, "foo" PATH_SEP_STR "bar" PATH_SEP_STR);
	ok1(tal_parent(split) == ctx);
	ok1(streq(split[0], "foo"));
	ok1(streq(split[1], "bar"));
	ok1(split[2] == NULL);
	tal_free(split);

	split = path_split(ctx, PATH_SEP_STR "foo"
			   PATH_SEP_STR "bar" PATH_SEP_STR);
	ok1(tal_parent(split) == ctx);
	ok1(streq(split[0], "foo"));
	ok1(streq(split[1], "bar"));
	ok1(split[2] == NULL);
	tal_free(split);

	split = path_split(ctx, PATH_SEP_STR PATH_SEP_STR "foo"
			   PATH_SEP_STR PATH_SEP_STR "bar"
			   PATH_SEP_STR PATH_SEP_STR);
	ok1(tal_parent(split) == ctx);
	ok1(streq(split[0], "foo"));
	ok1(streq(split[1], "bar"));
	ok1(split[2] == NULL);
	tal_free(split);

	split = path_split(ctx, "foo");
	ok1(tal_parent(split) == ctx);
	ok1(streq(split[0], "foo"));
	ok1(split[1] == NULL);
	tal_free(split);

	split = path_split(ctx, PATH_SEP_STR "foo");
	ok1(tal_parent(split) == ctx);
	ok1(streq(split[0], "foo"));
	ok1(split[1] == NULL);
	tal_free(split);

	split = path_split(ctx, PATH_SEP_STR PATH_SEP_STR "foo");
	ok1(tal_parent(split) == ctx);
	ok1(streq(split[0], "foo"));
	ok1(split[1] == NULL);
	tal_free(split);

	split = path_split(ctx, "foo" PATH_SEP_STR);
	ok1(tal_parent(split) == ctx);
	ok1(streq(split[0], "foo"));
	ok1(split[1] == NULL);
	tal_free(split);

	split = path_split(ctx, "foo" PATH_SEP_STR PATH_SEP_STR);
	ok1(tal_parent(split) == ctx);
	ok1(streq(split[0], "foo"));
	ok1(split[1] == NULL);
	tal_free(split);

	split = path_split(ctx, PATH_SEP_STR "foo" PATH_SEP_STR);
	ok1(tal_parent(split) == ctx);
	ok1(streq(split[0], "foo"));
	ok1(split[1] == NULL);
	tal_free(split);

	split = path_split(ctx, "");
	ok1(tal_parent(split) == ctx);
	ok1(split[0] == NULL);
	tal_free(split);

	split = path_split(ctx, PATH_SEP_STR);
	ok1(tal_parent(split) == ctx);
	ok1(streq(split[0], PATH_SEP_STR));
	ok1(split[1] == NULL);
	tal_free(split);

	/* Test take */
	split = path_split(ctx, take(tal_strdup(ctx, PATH_SEP_STR)));
	ok1(tal_parent(split) == ctx);
	ok1(streq(split[0], PATH_SEP_STR));
	ok1(split[1] == NULL);
	tal_free(split);
	ok1(tal_first(ctx) == NULL);

	split = path_split(ctx, take(NULL));
	ok1(!split);
	ok1(tal_first(ctx) == NULL);

	ok1(tal_first(NULL) == ctx && tal_next(ctx) == NULL && tal_first(ctx) == NULL);
	tal_free(ctx);

	return exit_status();
}
