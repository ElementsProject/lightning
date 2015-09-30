#include "config.h"

#include <assert.h>
#include <ccan/mem/mem.h>

int main(void)
{
	const char *haystack = "abcd\0efgh";
	char *p;

#ifdef FAIL
#if !HAVE_TYPEOF
#error "Can't fail without typeof"
#else
	/* Should catch const discard errors. */
	p = memcheck(haystack, sizeof(haystack));
#endif
#else
	p = memcheck((char *)haystack, sizeof(haystack));
#endif

	return p == haystack ? 0 : 1;
}
