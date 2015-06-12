#define CCAN_STR_DEBUG 1
#include <ccan/str/str.h>

int main(int argc, char *argv[])
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

	ret = strchr(str, 'l');
	return ret ? 0 : 1;
}
