/* Regression test: tokenize() never flushed a trailing identifier token,
 * so input ending in an identifier silently dropped it.  "struct" alone
 * was accepted as an empty, successful parse instead of a parse error. */
#include <ccan/cdump/cdump.h>
/* Include the C files directly. */
#include <ccan/cdump/cdump.c>
#include <ccan/tap/tap.h>
#include <unistd.h>

int main(void)
{
	struct cdump_definitions *defs;
	char *problems;

	plan_tests(10);
	alarm(10);

	/* Truncated keywords must be parse errors, not silent success. */
	defs = cdump_extract(NULL, "struct", &problems);
	ok1(!defs);
	ok1(problems);

	defs = cdump_extract(NULL, "enum", &problems);
	ok1(!defs);
	ok1(problems);

	defs = cdump_extract(NULL, "union", &problems);
	ok1(!defs);
	ok1(problems);

	/* Trailing identifier after a complete definition must not be
	 * silently swallowed: "struct s { int x; }; struct t" is truncated
	 * and must complain. */
	defs = cdump_extract(NULL, "struct s { int x; }; struct t", &problems);
	ok1(!defs);
	ok1(problems);

	/* Sanity: trailing whitespace/punctuation forms are unaffected. */
	defs = cdump_extract(NULL, "enum foo { BAR };", &problems);
	ok1(defs != NULL);
	ok1(problems == NULL);

	/* This exits depending on whether all tests passed */
	return exit_status();
}
