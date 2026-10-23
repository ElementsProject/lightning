#include <ccan/build_assert/build_assert.h>

/* Regression test for audit finding F1, expression form: with a
 * non-constant condition BUILD_ASSERT_OR_ZERO must fail compilation
 * (build_assert.h:29-30).  Today it compiles silently and, for a
 * condition false at runtime, yields a garbage value (UB via a
 * negative VLA bound) instead of the documented 0. */
int main(int argc, char *argv[])
{
	(void)argv;
#ifdef FAIL
	return BUILD_ASSERT_OR_ZERO(argc == 0) == 0;
#if !HAVE_STATIC_ASSERT
#error "Unfortunately we don't fail on non-constant conditions without _Static_assert."
#endif
#else
	(void)argc;
	return 0;
#endif
}
