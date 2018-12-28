#include <ccan/str/str.h>

struct s {
	int val;
};

int main(void)
{
	struct s
#ifdef FAIL
#if !HAVE_TYPEOF
	#error We need typeof to check STR_MAX_CHARS.
#endif
#else
	/* A pointer is OK. */
		*
#endif
		val;
	char str[STR_MAX_CHARS(val)];

	str[0] = '\0';
	return str[0] ? 0 : 1;
}
