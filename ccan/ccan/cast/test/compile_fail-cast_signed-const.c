#include <ccan/cast/cast.h>
#include <stdlib.h>

int main(void)
{
	unsigned char *uc;
#ifdef FAIL
	const
#endif
	char
		*p = NULL;

	uc = cast_signed(unsigned char *, p);
	(void) uc; /* Suppress unused-but-set-variable warning. */
	return 0;
}

#ifdef FAIL
#if !HAVE_TYPEOF||!HAVE_BUILTIN_CHOOSE_EXPR||!HAVE_BUILTIN_TYPES_COMPATIBLE_P
#error "Unfortunately we don't fail if cast_const can only use size"
#endif
#endif
