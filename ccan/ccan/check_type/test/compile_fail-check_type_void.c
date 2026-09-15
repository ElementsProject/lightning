#include <ccan/check_type/check_type.h>

/* Regression test for audit finding F1 (2026-08-05): an expression of
 * type void (e.g. a dereferenced void pointer, the shape container_of
 * produces for a void * member pointer) silently bypasses check_type:
 * (void *)0 != (int *)0 is constraint-conforming, so no diagnostic is
 * issued at any warning level.  The header documents "a warning or
 * build failure if type is not correct".  This test is RED until the
 * check is strengthened (e.g. __builtin_types_compatible_p). */
int main(int argc, char *argv[])
{
	void *vp = argv;
	(void)argc;
#ifdef FAIL
	if (check_type(*vp, int))
		return 1;
#else
	(void)vp;
#endif
	return 0;
}
