/* Regression test for audit finding: lexo_order() (rune.c:286-296) uses
 * strncmp(), which stops comparing at the first NUL.  Every other string
 * condition (EQUAL, NOT_EQUAL, BEGINS, ENDS, CONTAINS) uses NUL-safe
 * counted helpers (memeqstr, memstarts_str, memends_str, memmem), so
 * counted field values containing embedded NULs are in-contract for
 * rune_alt_single_str().  With an embedded NUL, lexo_order reports
 * "equal" when the altern value is a proper prefix of the field value
 * up to the NUL, giving wrong answers for RUNE_COND_LEXO_BEFORE and
 * RUNE_COND_LEXO_AFTER (authorization decisions).
 *
 * This test must pass once lexo_order compares counted bytes. */
#include <ccan/rune/rune.c>
#include <ccan/rune/coding.c>
#include <ccan/tal/str/str.h>
#include <ccan/tap/tap.h>
#include <unistd.h>

int main(void)
{
	/* fieldval = "abc\0X": byte-wise it sorts strictly after "abc"
	 * ("abc" is a proper prefix). */
	static const char fieldval[] = { 'a', 'b', 'c', 0, 'X' };
	struct rune_altern *alt;
	const char *err;

	alarm(10);
	plan_tests(3);

	/* fieldval > "abc": LEXO_AFTER must pass (err == NULL). */
	alt = rune_altern_new(NULL, "f", RUNE_COND_LEXO_AFTER, "abc");
	err = rune_alt_single_str(NULL, alt, fieldval, sizeof(fieldval));
	ok1(err == NULL);
	tal_free(alt);

	/* fieldval > "abc": LEXO_BEFORE must fail (err != NULL). */
	alt = rune_altern_new(NULL, "f", RUNE_COND_LEXO_BEFORE, "abc");
	err = rune_alt_single_str(NULL, alt, fieldval, sizeof(fieldval));
	ok1(err != NULL);
	tal_free(alt);

	/* Sanity: genuine equality passes neither strict condition. */
	alt = rune_altern_new(NULL, "f", RUNE_COND_LEXO_AFTER, "abc");
	err = rune_alt_single_str(NULL, alt, "abc", 3);
	ok1(err != NULL);
	tal_free(alt);

	/* This exits depending on whether all tests passed */
	return exit_status();
}
