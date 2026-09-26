/* Regression test for compiler.h guard nesting: predefining CONST_FUNCTION
 * (the purpose of the "#ifndef CONST_FUNCTION" guard) must not suppress the
 * definition of PURE_FUNCTION.  Today the PURE_FUNCTION block is nested
 * inside the CONST_FUNCTION guard, so this file fails to compile until
 * compiler.h is fixed (PURE_FUNCTION "unknown type name"). */
#define CONST_FUNCTION
#include <ccan/compiler/compiler.h>
#include <ccan/tap/tap.h>

static PURE_FUNCTION int double_it(int x)
{
	return x * 2;
}

int main(void)
{
	plan_tests(1);
	ok1(double_it(2) == 4);
	return exit_status();
}
