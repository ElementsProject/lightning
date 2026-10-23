/* Regression test: sintmap_first()/sintmap_last() on an empty map must
 * not populate *indexp (documented: "Returns NULL if the map is empty,
 * otherwise populates *@indexp").  The current implementation always
 * writes SINTMAP_UNOFF(i) where i is an uninitialized local when the
 * map is empty (valgrind: "Conditional jump or move depends on
 * uninitialised value(s)"), clobbering the caller's index variable
 * with garbage.  uintmap_first/uintmap_last leave *indexp untouched.
 */
#include <ccan/intmap/intmap.h>
#include <ccan/intmap/intmap.c>
#include <ccan/tap/tap.h>
#include <unistd.h>

#define SENTINEL 12345

/* Groom the stack so the uninitialized read picks up a known-bad value
 * rather than something that happens to equal SENTINEL. */
static void groom_stack(void)
{
	volatile uint64_t pad[32];

	for (size_t i = 0; i < sizeof(pad)/sizeof(pad[0]); i++)
		pad[i] = 0xDEADBEEFCAFEBABEULL;
}

int main(void)
{
	SINTMAP(const char *) map;
	sintmap_index_t s;
	const char *r;

	alarm(10);

	plan_tests(6);
	sintmap_init(&map);

	/* First/last on empty map return NULL... */
	groom_stack();
	s = SENTINEL;
	r = sintmap_first(&map, &s);
	ok1(r == NULL);
	ok1(errno == ENOENT);
	/* ...and must not touch *indexp. */
	ok1(s == SENTINEL);

	groom_stack();
	s = SENTINEL;
	r = sintmap_last(&map, &s);
	ok1(r == NULL);
	ok1(errno == ENOENT);
	/* ...and must not touch *indexp. */
	ok1(s == SENTINEL);

	/* This exits depending on whether all tests passed */
	return exit_status();
}
