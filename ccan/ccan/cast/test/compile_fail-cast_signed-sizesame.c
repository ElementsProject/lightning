#include <ccan/cast/cast.h>
#include <stdlib.h>

/* Note: this *isn't* sizeof(char) on all platforms. */
struct char_struct {
	char c;
};

int main(int argc, char *argv[])
{
	unsigned char *uc;
#ifdef FAIL
	struct char_struct
#else
	char
#endif
		*p = NULL;

	uc = cast_signed(unsigned char *, p);

	(void) uc; /* Suppress unused-but-set-variable warning. */
	return 0;
}

#ifdef FAIL
#if !HAVE_TYPEOF||!HAVE_BUILTIN_CHOOSE_EXPR||!HAVE_BUILTIN_TYPES_COMPATIBLE_P
#error "Unfortunately we don't fail if cast_signed can only use size"
#endif
#endif
