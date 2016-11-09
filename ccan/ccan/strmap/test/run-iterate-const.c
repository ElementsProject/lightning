#include <ccan/strmap/strmap.h>
#include <ccan/strmap/strmap.c>
#include <ccan/tap/tap.h>

static bool found = false;

/* Make sure const args work. */
static bool find_string(const char *str UNNEEDED, char *member, const char *cmp)
{
	if (strcmp(member, cmp) == 0)
		found = true;
	return false;
}

int main(void)
{
	STRMAP(char *) map;

	plan_tests(3);

	strmap_init(&map);
	ok1(strmap_add(&map, "hello", "hello"));
	ok1(strmap_add(&map, "world", "world"));
	strmap_iterate(&map, find_string, (const char *)"hello");
	ok1(found);
	strmap_clear(&map);

	/* This exits depending on whether all tests passed */
	return exit_status();
}
