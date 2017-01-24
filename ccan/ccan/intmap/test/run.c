#include <ccan/intmap/intmap.h>
#include <ccan/intmap/intmap.c>
#include <ccan/tap/tap.h>

int main(void)
{
	UINTMAP(char *) map;
	const char val[] = "there";
	const char none[] = "";

	/* This is how many tests you plan to run */
	plan_tests(28);

	uintmap_init(&map);

	ok1(!uintmap_get(&map, 1));
	ok1(errno == ENOENT);
	ok1(!uintmap_get(&map, 0));
	ok1(errno == ENOENT);
	ok1(!uintmap_del(&map, 1));
	ok1(errno == ENOENT);
	ok1(!uintmap_del(&map, 0));
	ok1(errno == ENOENT);

	ok1(uintmap_add(&map, 1, val));
	ok1(uintmap_get(&map, 1) == val);
	ok1(!uintmap_get(&map, 0));
	ok1(errno == ENOENT);

	/* Add a duplicate should fail. */
	ok1(!uintmap_add(&map, 1, val));
	ok1(errno == EEXIST);

	/* Delete should succeed. */
	ok1(uintmap_del(&map, 1) == val);
	ok1(!uintmap_get(&map, 1));
	ok1(errno == ENOENT);
	ok1(!uintmap_get(&map, 0));
	ok1(errno == ENOENT);

	/* Both at once... */
	ok1(uintmap_add(&map, 0, none));
	ok1(uintmap_add(&map, 1, val));
	ok1(uintmap_get(&map, 1) == val);
	ok1(uintmap_get(&map, 0) == none);
	ok1(!uintmap_del(&map, 2));
	ok1(uintmap_del(&map, 0) == none);
	ok1(uintmap_get(&map, 1) == val);
	ok1(uintmap_del(&map, 1) == val);

	ok1(uintmap_empty(&map));

	/* This exits depending on whether all tests passed */
	return exit_status();
}
