/* Regression test for audit finding: rune.h documents that an altern
 * fieldname may contain "alphanumerics, '.', '-' and '_'"
 * (rune.h:111-113), and rune_altern_new() accepts such fieldnames
 * without complaint, but rune_altern_fieldname_len() (coding.c:206-213)
 * stops at ANY punctuation except '_' — so a rune built with a '.'
 * or '-' in the fieldname encodes fine yet cannot be parsed back:
 * rune_to_string()/rune_to_base64() output is rejected by
 * rune_from_string()/rune_from_base64() (roundtrip failure).
 *
 * This test must pass once the encode/decode sides agree with the
 * documented fieldname charset. */
#include <ccan/rune/rune.c>
#include <ccan/rune/coding.c>
#include <ccan/tal/str/str.h>
#include <ccan/tap/tap.h>
#include <unistd.h>

int main(void)
{
	static const u8 secret_zero[16];
	struct rune *rune, *back;
	struct rune_restr *restr;
	char *str, *b64;

	alarm(10);
	plan_tests(7);

	rune = rune_new(NULL, secret_zero, sizeof(secret_zero), NULL);
	restr = rune_restr_new(NULL);
	rune_restr_add_altern(restr, take(rune_altern_new(NULL, "a.b-c",
							  RUNE_COND_EQUAL, "7")));
	ok1(rune_add_restr(rune, take(restr)));

	str = rune_to_string(NULL, rune);
	ok1(str != NULL);

	/* Documented-valid rune must survive the string roundtrip. */
	back = rune_from_string(NULL, str);
	ok1(back != NULL);
	if (back)
		ok1(rune_eq(rune, back));
	else
		fail("rune_from_string returned NULL");
	tal_free(back);

	/* And the base64 roundtrip. */
	b64 = rune_to_base64(NULL, rune);
	back = rune_from_base64(NULL, b64);
	ok1(back != NULL);
	if (back)
		ok1(rune_eq(rune, back));
	else
		fail("rune_from_base64 returned NULL");
	tal_free(back);

	/* Direct restriction parsing of a documented-valid fieldname. */
	restr = rune_restr_from_string(NULL, "a.b-c=7", strlen("a.b-c=7"));
	ok1(restr != NULL);
	tal_free(restr);

	tal_free(str);
	tal_free(b64);
	tal_free(rune);
	/* This exits depending on whether all tests passed */
	return exit_status();
}
