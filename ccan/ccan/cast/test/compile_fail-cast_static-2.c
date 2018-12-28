#include <ccan/cast/cast.h>
#include <stdlib.h>

int main(void)
{
	char *c;
#ifdef FAIL
	long
#else
	char
#endif
		*p = 0;

	c = cast_static(char *, p);
	(void) c; /* Suppress unused-but-set-variable warning. */
	return 0;
}

#ifdef FAIL
#if !HAVE_COMPOUND_LITERALS
#error "Unfortunately we don't fail if cast_static is a noop"
#endif
#endif
