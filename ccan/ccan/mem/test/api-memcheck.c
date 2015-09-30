#include "config.h"

#include <assert.h>

#include <ccan/mem/mem.h>
#include <ccan/tap/tap.h>

int main(void)
{
	char haystack[] = "abcd\0efgh";
	char *p;
	const char *pc;

	/* This is how many tests you plan to run */
	plan_tests(4);

	p = memcheck(haystack, sizeof(haystack));
	ok1(p == haystack);
	pc = memcheck(haystack, sizeof(haystack));
	ok1(pc == haystack);
	p = memcheck(p, sizeof(haystack));
	ok1(p == haystack);
	pc = memcheck(pc, sizeof(haystack));
	ok1(pc == haystack);

	/* This exits depending on whether all tests passed */
	return exit_status();
}
