#define CCAN_STR_DEBUG 1
#include <ccan/str/str.h>

int main(void)
{
#ifdef FAIL
#if !HAVE_TYPEOF
	#error We need typeof to check strstr.
#endif
#else
	const
#endif
		char *ret;
	const char *str = "hello";

	ret = strstr(str, "hell");
	return ret ? 0 : 1;
}
