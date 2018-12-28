#define CCAN_STR_DEBUG 1
#include <ccan/str/str.h>

int main(int argc, char *argv[])
{
	(void)argc;
#ifdef FAIL
#if !HAVE_BUILTIN_TYPES_COMPATIBLE_P || !HAVE_TYPEOF
#error We need typeof to check iscntrl.
#endif
	char
#else
	unsigned char
#endif
		c = argv[0][0];

#ifdef FAIL
	/* Fake fail on unsigned char platforms. */
	BUILD_ASSERT((char)255 < 0);
#endif

	return iscntrl(c);
}
