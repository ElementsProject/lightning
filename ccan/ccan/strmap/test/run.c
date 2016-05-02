#include <ccan/strmap/strmap.h>
#include <ccan/strmap/strmap.c>
#include <ccan/tap/tap.h>

int main(void)
{
	STRMAP(char *) map;
	const char str[] = "hello";
	const char val[] = "there";
	const char none[] = "";
	char *dup = strdup(str);
	char *v;

	/* This is how many tests you plan to run */
	plan_tests(42);

	strmap_init(&map);

	ok1(!strmap_get(&map, str));
	ok1(errno == ENOENT);
	ok1(!strmap_get(&map, none));
	ok1(errno == ENOENT);
	ok1(!strmap_del(&map, str, NULL));
	ok1(errno == ENOENT);
	ok1(!strmap_del(&map, none, NULL));
	ok1(errno == ENOENT);

	ok1(strmap_add(&map, str, val));
	ok1(strmap_get(&map, str) == val);
	/* We compare the string, not the pointer. */
	ok1(strmap_get(&map, dup) == val);
	ok1(!strmap_get(&map, none));
	ok1(errno == ENOENT);

	/* Add a duplicate should fail. */
	ok1(!strmap_add(&map, dup, val));
	ok1(errno == EEXIST);
	ok1(strmap_get(&map, dup) == val);

	/* Delete should return original string. */
	ok1(strmap_del(&map, dup, &v) == str);
	ok1(v == val);
	ok1(!strmap_get(&map, str));
	ok1(errno == ENOENT);
	ok1(!strmap_get(&map, none));
	ok1(errno == ENOENT);

	/* Try insert and delete of empty string. */
	ok1(strmap_add(&map, none, none));
	ok1(strmap_get(&map, none) == none);
	ok1(!strmap_get(&map, str));
	ok1(errno == ENOENT);

	/* Delete should return original string. */
	ok1(strmap_del(&map, "", &v) == none);
	ok1(v == none);
	ok1(!strmap_get(&map, str));
	ok1(errno == ENOENT);
	ok1(!strmap_get(&map, none));
	ok1(errno == ENOENT);

	/* Both at once... */
	ok1(strmap_add(&map, none, none));
	ok1(strmap_add(&map, str, val));
	ok1(strmap_get(&map, str) == val);
	ok1(strmap_get(&map, none) == none);
	ok1(strmap_del(&map, "does not exist", NULL) == NULL);
	ok1(strmap_del(&map, "", NULL) == none);
	ok1(strmap_get(&map, str) == val);
	ok1(strmap_del(&map, dup, &v) == str);
	ok1(v == val);

	ok1(strmap_empty(&map));
	free(dup);

	/* This exits depending on whether all tests passed */
	return exit_status();
}
