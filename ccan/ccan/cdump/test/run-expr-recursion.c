/* Regression test: tok_take_expr() recursed once per nested '(' or '['
 * with no depth limit, so a deeply nested array size / CDUMP note /
 * __attribute__ expression overflowed the stack (SIGSEGV). */
#include <ccan/cdump/cdump.h>
/* Include the C files directly. */
#include <ccan/cdump/cdump.c>
#include <ccan/tap/tap.h>
#include <unistd.h>
#include <sys/resource.h>
#include <string.h>
#include <stdio.h>

int main(void)
{
	/* Keep the stack small so unbounded recursion dies quickly
	 * instead of after megabytes of input. */
	struct rlimit rl = { 256*1024, 256*1024 };
	size_t depth = 20000, i;
	char *code, *p, *problems;
	struct cdump_definitions *defs;

	plan_tests(2);
	alarm(60);

	setrlimit(RLIMIT_STACK, &rl);

	code = tal_arr(NULL, char, depth * 2 + 64);
	p = code;
	p += sprintf(p, "struct s { int a[");
	for (i = 0; i < depth; i++)
		*p++ = '(';
	*p++ = '1';
	for (i = 0; i < depth; i++)
		*p++ = ')';
	p += sprintf(p, "]; };");

	/* Must fail gracefully (or succeed), never crash. */
	defs = cdump_extract(NULL, code, &problems);
	ok1(defs == NULL);
	ok1(problems != NULL);

	/* This exits depending on whether all tests passed */
	return exit_status();
}
