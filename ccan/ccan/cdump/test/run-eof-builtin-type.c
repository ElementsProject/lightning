/* Regression test: builtin type word as last token inside a struct/union
 * body used to NULL-deref in string_of_toks() via tok_take_type()
 * (cdump.c:350 passed tok_peek()==NULL as `until`). */
#include <ccan/cdump/cdump.h>
/* Include the C files directly. */
#include <ccan/cdump/cdump.c>
#include <ccan/tap/tap.h>
#include <unistd.h>

int main(void)
{
	struct cdump_definitions *defs;
	char *problems;

	plan_tests(8);
	alarm(10);

	/* Truncated after a builtin type word: must fail gracefully. */
	defs = cdump_extract(NULL, "struct s { int ", &problems);
	ok1(!defs);
	ok1(problems);

	defs = cdump_extract(NULL, "struct s { unsigned ", &problems);
	ok1(!defs);
	ok1(problems);

	/* Same, but with a qualifier before the builtin type. */
	defs = cdump_extract(NULL, "union u { const long ", &problems);
	ok1(!defs);
	ok1(problems);

	/* Sanity: the complete version still parses. */
	defs = cdump_extract(NULL, "struct s { int x; };", &problems);
	ok1(defs != NULL);
	ok1(problems == NULL);

	/* This exits depending on whether all tests passed */
	return exit_status();
}
