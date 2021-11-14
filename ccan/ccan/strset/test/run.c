#include <ccan/strset/strset.h>
#include <ccan/strset/strset.c>
#include <ccan/tap/tap.h>

int main(void)
{
	struct strset set;
	const char str[] = "hello";
	const char none[] = "";
	char *dup = strdup(str);

	/* This is how many tests you plan to run */
	plan_tests(36);

	strset_init(&set);

	ok1(!strset_get(&set, str));
	ok1(errno == ENOENT);
	ok1(!strset_get(&set, none));
	ok1(errno == ENOENT);
	ok1(!strset_del(&set, str));
	ok1(errno == ENOENT);
	ok1(!strset_del(&set, none));
	ok1(errno == ENOENT);

	ok1(strset_add(&set, str));
	ok1(strset_get(&set, str));
	/* We compare the string, not the pointer. */
	ok1(strset_get(&set, dup));
	ok1(!strset_get(&set, none));
	ok1(errno == ENOENT);

	/* Add of duplicate should fail. */
	ok1(!strset_add(&set, dup));
	ok1(errno == EEXIST);

	/* Delete should return original string. */
	ok1(strset_del(&set, dup) == str);
	ok1(!strset_get(&set, str));
	ok1(errno == ENOENT);
	ok1(!strset_get(&set, none));
	ok1(errno == ENOENT);

	/* Try insert and delete of empty string. */
	ok1(strset_add(&set, none));
	ok1(strset_get(&set, none));
	ok1(!strset_get(&set, str));
	ok1(errno == ENOENT);

	/* Delete should return original string. */
	ok1(strset_del(&set, "") == none);
	ok1(!strset_get(&set, str));
	ok1(errno == ENOENT);
	ok1(!strset_get(&set, none));
	ok1(errno == ENOENT);

	/* Both at once... */
	ok1(strset_add(&set, none));
	ok1(strset_add(&set, str));
	ok1(strset_get(&set, str));
	ok1(strset_get(&set, none));
	ok1(strset_del(&set, "") == none);
	ok1(strset_del(&set, dup) == str);

	ok1(set.u.n == NULL);
	free(dup);

	/* This exits depending on whether all tests passed */
	return exit_status();
}
