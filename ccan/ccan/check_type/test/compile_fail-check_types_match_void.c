#include <ccan/check_type/check_type.h>

/* Regression test for audit finding F1 (2026-08-05): see
 * compile_fail-check_type_void.c.  check_types_match with one side of
 * type void is likewise accepted silently.  RED until repaired. */
int main(int argc, char *argv[])
{
	void *vp = argv;
#ifdef FAIL
	if (check_types_match(*vp, argc))
		return 1;
#else
	(void)vp;
	(void)argc;
#endif
	return 0;
}
