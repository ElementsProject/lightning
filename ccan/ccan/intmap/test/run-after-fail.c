#include <ccan/intmap/intmap.h>
#include <ccan/intmap/intmap.c>
#include <ccan/tap/tap.h>

int main(void)
{
	UINTMAP(const char *) map;
	u64 idx;

	/* This is how many tests you plan to run */
	plan_tests(2);

	uintmap_init(&map);
	assert(uintmap_add(&map, 0x103, "103"));
	assert(uintmap_add(&map, 0x10b, "10b"));

	uintmap_first(&map, &idx);
	ok1(idx > 0xF);
	idx = 0xF;
	ok1(strcmp(uintmap_after(&map, &idx), "103") == 0);

	uintmap_clear(&map);

	/* This exits depending on whether all tests passed */
	return exit_status();
}
