/* Regression test: an unterminated C comment made tokenize() compute
 * (end + 2) on a NULL end pointer before the !end check (cdump.c:51) —
 * UB flagged by UBSan ("applying non-zero offset 2 to null pointer").
 * This only fails under UBSan; plain builds got the right result anyway
 * because len is recomputed in the !end branch. */
#include <ccan/cdump/cdump.h>
/* Include the C files directly. */
#include <ccan/cdump/cdump.c>
#include <ccan/tap/tap.h>
#include <unistd.h>

int main(void)
{
	struct cdump_definitions *defs;
	char *problems;

	plan_tests(4);
	alarm(10);

	defs = cdump_extract(NULL, "/*", &problems);
	ok1(defs != NULL);
	ok1(problems == NULL);

	defs = cdump_extract(NULL, "struct s { int x; }; /* unterminated", &problems);
	ok1(defs != NULL);
	ok1(problems == NULL);

	/* This exits depending on whether all tests passed */
	return exit_status();
}
