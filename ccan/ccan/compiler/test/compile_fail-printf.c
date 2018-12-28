#include <ccan/compiler/compiler.h>

static void PRINTF_FMT(2,3) my_printf(int x, const char *fmt, ...)
{
	(void)x;
	(void)fmt;
}

int main(void)
{
	unsigned int i = 0;

	my_printf(1, "Not a pointer "
#ifdef FAIL
		  "%p",
#if !HAVE_ATTRIBUTE_PRINTF
#error "Unfortunately we don't fail if !HAVE_ATTRIBUTE_PRINTF."
#endif
#else
		  "%i",
#endif
		  i);
	return 0;
}
