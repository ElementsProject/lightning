#include <ccan/build_assert/build_assert.h>

/* Regression test for audit finding F1: build_assert.h:9-10 documents
 * "Your compile will fail if the condition isn't true, or can't be
 * evaluated by the compiler."  With a non-constant condition the
 * negative-array-size trick becomes a VLA bound, which gcc and clang
 * both accept silently (no diagnostic even with -Wall -Wextra -Werror),
 * so the assertion never fires; a false condition at runtime is a
 * negative VLA bound, i.e. undefined behavior.
 *
 * Today this file compiles even with FAIL defined (the defect); after
 * the repair (a constant-expression-forcing implementation, e.g.
 * _Static_assert), the FAIL build must be rejected. */
int main(int argc, char *argv[])
{
	(void)argv;
#ifdef FAIL
	BUILD_ASSERT(argc == 0);
#if !HAVE_STATIC_ASSERT
#error "Unfortunately we don't fail on non-constant conditions without _Static_assert."
#endif
#else
	(void)argc;
#endif
	return 0;
}
