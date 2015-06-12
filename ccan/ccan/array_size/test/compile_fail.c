#include <ccan/array_size/array_size.h>

int main(int argc, char *argv[8])
{
	char array[100];
#ifdef FAIL
	return ARRAY_SIZE(argv) + ARRAY_SIZE(array);
#if !HAVE_TYPEOF || !HAVE_BUILTIN_TYPES_COMPATIBLE_P
#error "Unfortunately we don't fail if _array_size_chk is a noop."
#endif
#else
	return ARRAY_SIZE(array);
#endif
}
