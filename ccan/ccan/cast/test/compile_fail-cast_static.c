#include <ccan/cast/cast.h>
#include <stdlib.h>

int main(int argc, char *argv[])
{
	long c;
#ifdef FAIL
	char *
#else
	char
#endif
		x = 0;

	c = cast_static(long, x);
	(void) c; /* Suppress unused-but-set-variable warning. */
	return 0;
}

#ifdef FAIL
#if !HAVE_COMPOUND_LITERALS
#error "Unfortunately we don't fail if cast_static without compound literals"
#endif
#endif
