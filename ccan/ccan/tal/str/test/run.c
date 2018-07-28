#include <ccan/tal/str/str.h>
#include <stdlib.h>
#include <stdio.h>
#include <ccan/tal/str/str.c>
#include <ccan/tap/tap.h>
#include "helper.h"

#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof(arr[0]))

static const char *substrings[]
= { "far", "bar", "baz", "b", "ba", "z", "ar", NULL };

int main(void)
{
	char **split, *str;
	void *ctx;

	plan_tests(78);
	split = tal_strsplit(NULL, "hello  world", " ", STR_EMPTY_OK);
	ok1(!strcmp(split[0], "hello"));
	ok1(!strcmp(split[1], ""));
	ok1(!strcmp(split[2], "world"));
	ok1(split[3] == NULL);
	ok1(tal_count(split) == 4);
	tal_free(split);

	split = tal_strsplit(NULL, "hello  world", " ", STR_NO_EMPTY);
	ok1(!strcmp(split[0], "hello"));
	ok1(!strcmp(split[1], "world"));
	ok1(split[2] == NULL);
	ok1(tal_count(split) == 3);
	tal_free(split);

	split = tal_strsplit(NULL, "  hello  world", " ", STR_NO_EMPTY);
	ok1(!strcmp(split[0], "hello"));
	ok1(!strcmp(split[1], "world"));
	ok1(split[2] == NULL);
	ok1(tal_count(split) == 3);
	tal_free(split);

	split = tal_strsplit(NULL, "hello  world", "o ", STR_EMPTY_OK);
	ok1(!strcmp(split[0], "hell"));
	ok1(!strcmp(split[1], ""));
	ok1(!strcmp(split[2], ""));
	ok1(!strcmp(split[3], "w"));
	ok1(!strcmp(split[4], "rld"));
	ok1(split[5] == NULL);
	ok1(tal_count(split) == 6);

	ctx = split;
	split = tal_strsplit(ctx, "hello  world", "o ", STR_EMPTY_OK);
	ok1(tal_parent(split) == ctx);
	tal_free(ctx);

	str = tal_strjoin(NULL, (char **)substrings, ", ", STR_TRAIL);
	ok1(!strcmp(str, "far, bar, baz, b, ba, z, ar, "));
	ok1(tal_count(str) == strlen(str) + 1);
	ctx = str;
	str = tal_strjoin(ctx, (char **)substrings, "", STR_TRAIL);
	ok1(!strcmp(str, "farbarbazbbazar"));
	ok1(tal_count(str) == strlen(str) + 1);
	ok1(tal_parent(str) == ctx);
	str = tal_strjoin(ctx, (char **)substrings, ", ", STR_NO_TRAIL);
	ok1(tal_parent(str) == ctx);
	ok1(!strcmp(str, "far, bar, baz, b, ba, z, ar"));
	ok1(tal_count(str) == strlen(str) + 1);
	str = tal_strjoin(ctx, (char **)substrings, "", STR_NO_TRAIL);
	ok1(!strcmp(str, "farbarbazbbazar"));
	ok1(tal_parent(str) == ctx);
	ok1(tal_count(str) == strlen(str) + 1);
	tal_free(ctx);

	ctx = tal_strdup(NULL, "context");
	/* Pass through NULLs from take. */
	ok1(tal_strsplit(NULL, take(NULL), " ", STR_EMPTY_OK) == NULL);
	ok1(tal_strsplit(NULL, "foo", take(NULL), STR_EMPTY_OK) == NULL);

	/* tal_strsplit take string.  It reallocs it to same size, but
	 * that sometimes causes a move, so we can't directly check
	 * that split[0] == str. */
	str = tal_strdup(ctx, "hello world");
	ok1(tal_check(ctx, NULL));
	ok1(tal_check(str, NULL));
	ok1(tal_count(str) == strlen(str) + 1);
	split = tal_strsplit(ctx, take(str), " ", STR_EMPTY_OK);
	ok1(tal_parent(split) == ctx);
	ok1(!strcmp(split[0], "hello"));
	ok1(!strcmp(split[1], "world"));
	ok1(split[2] == NULL);
	ok1(tal_check(split, NULL));
	ok1(tal_check(ctx, NULL));
	tal_free(split);
	/* Previous free should get rid of str */
	ok1(no_children(ctx));

	/* tal_strsplit take delims */
	str = tal_strdup(ctx, " ");
	ok1(tal_count(str) == strlen(str) + 1);
	split = tal_strsplit(ctx, "hello world", take(str), STR_EMPTY_OK);
	ok1(tal_parent(split) == ctx);
	ok1(!strcmp(split[0], "hello"));
	ok1(!strcmp(split[1], "world"));
	ok1(split[2] == NULL);
	ok1(tal_check(split, NULL));
	ok1(tal_check(ctx, NULL));
	tal_free(split);
	/* str is gone... */
	ok1(no_children(ctx));

	/* tal_strsplit takes both. */
	split = tal_strsplit(ctx, take(tal_strdup(NULL, "hello world")),
			     take(tal_strdup(NULL, " ")), STR_EMPTY_OK);
	ok1(tal_parent(split) == ctx);
	ok1(!strcmp(split[0], "hello"));
	ok1(!strcmp(split[1], "world"));
	ok1(split[2] == NULL);
	ok1(tal_check(split, NULL));
	ok1(tal_check(ctx, NULL));
	tal_free(split);
	/* temp allocs are gone... */
	ok1(no_children(ctx));

	/* tal_strjoin passthrough taken NULLs OK. */
	ok1(tal_strjoin(ctx, take(NULL), "", STR_TRAIL) == NULL);
	ok1(tal_strjoin(ctx, take(NULL), "", STR_NO_TRAIL) == NULL);
	ok1(tal_strjoin(ctx, split, take(NULL), STR_TRAIL) == NULL);
	ok1(tal_strjoin(ctx, split, take(NULL), STR_NO_TRAIL) == NULL);

	/* tal_strjoin take strings[] */
	split = tal_strsplit(ctx, "hello world", " ", STR_EMPTY_OK);
	str = tal_strjoin(ctx, take(split), " there ", STR_NO_TRAIL);
	ok1(!strcmp(str, "hello there world"));
	ok1(tal_count(str) == strlen(str) + 1);
	ok1(tal_parent(str) == ctx);
	/* split is gone... */
	ok1(single_child(ctx, str));
	tal_free(str);
	ok1(no_children(ctx));

	/* tal_strjoin take delim */
	split = tal_strsplit(ctx, "hello world", " ", STR_EMPTY_OK);
	str = tal_strjoin(ctx, split, take(tal_strdup(ctx, " there ")),
			  STR_NO_TRAIL);
	ok1(!strcmp(str, "hello there world"));
	ok1(tal_parent(str) == ctx);
	ok1(tal_count(str) == strlen(str) + 1);
	tal_free(split);
	/* tmp alloc is gone, str is only remainder. */
	ok1(single_child(ctx, str));
	tal_free(str);
	ok1(no_children(ctx));

	/* tal_strjoin take both. */
	str = tal_strjoin(ctx, take(tal_strsplit(ctx, "hello world", " ",
						 STR_EMPTY_OK)),
			  take(tal_strdup(ctx, " there ")), STR_NO_TRAIL);
	ok1(!strcmp(str, "hello there world"));
	ok1(tal_count(str) == strlen(str) + 1);
	ok1(tal_parent(str) == ctx);
	/* tmp allocs are gone, str is only remainder. */
	ok1(single_child(ctx, str));
	tal_free(str);
	ok1(no_children(ctx));
	tal_free(ctx);

	return exit_status();
}
