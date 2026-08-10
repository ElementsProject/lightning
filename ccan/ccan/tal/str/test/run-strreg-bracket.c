#include <ccan/tal/str/str.h>
#include <ccan/tal/str/str.c>
#include <ccan/tap/tap.h>

/* A '(' inside a bracket expression is not a capture group: the caller
 * passes no char** arguments, and tal_strreg_() must not read any. */
int main(void)
{
	char *m1, *m2;

	plan_tests(6);

	ok1(tal_strreg(NULL, "(", "[(]") == true);
	ok1(tal_strreg(NULL, "x", "[(]") == false);

	/* Bracket expression plus real groups. */
	m1 = m2 = NULL;
	ok1(tal_strreg(NULL, "(x", "[(]([a-z])(z)?", &m1, &m2) == true);
	ok1(m1 && streq(m1, "x"));
	ok1(m2 == NULL);
	tal_free(m1);
	tal_free(m2);

	/* Escaped paren is not a group either. */
	ok1(tal_strreg(NULL, "(", "\\(") == true);

	tal_cleanup();
	return exit_status();
}
