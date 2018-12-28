#include <ccan/array_size/array_size.h>
#include <stdlib.h>

struct foo {
	unsigned int a, b;
};

int check_parameter(const struct foo *array);
int check_parameter(const struct foo *array)
{
#ifdef FAIL
	return (ARRAY_SIZE(array) == 4);
#if !HAVE_TYPEOF || !HAVE_BUILTIN_TYPES_COMPATIBLE_P
#error "Unfortunately we don't fail if _array_size_chk is a noop."
#endif
#else
	return sizeof(array) == 4 * sizeof(struct foo);
#endif
}

int main(void)
{
	return check_parameter(NULL);
}
