/* Regression test for audit finding: rune_dup() shallow-copies the
 * unique_id and version pointers (rune.c:65-79), so the "copy" shares
 * tal-owned strings with the original.  Freeing the original leaves
 * the copy with dangling unique_id/version pointers (heap-use-after-free
 * under ASan; garbage contents in plain builds once the heap is reused).
 *
 * rune_dup is documented as "Copy a rune." (rune.h:99); a copy whose
 * lifetime depends on the original violates that contract.
 *
 * This test must pass both in plain builds and under ASan once fixed. */
#include <ccan/rune/rune.c>
#include <ccan/rune/coding.c>
#include <ccan/tal/str/str.h>
#include <ccan/tap/tap.h>
#include <unistd.h>

int main(void)
{
	static const u8 secret_zero[16];
	struct rune *master, *rune, *dup;
	char *str;

	alarm(10);
	plan_tests(9);

	master = rune_new(NULL, secret_zero, sizeof(secret_zero), "1");
	rune = rune_derive_start(NULL, master, "uid1");
	dup = rune_dup(NULL, rune);

	ok1(dup != NULL);
	ok1(streq(dup->unique_id, "uid1"));
	ok1(streq(dup->version, "1"));

	/* The copy must own its strings: they must not be tal children of
	 * the original rune (which the caller is entitled to free). */
	ok1(tal_parent(dup->unique_id) != (tal_t *)rune);
	ok1(tal_parent(dup->version) != (tal_t *)rune);

	/* Free the original: the documented copy must remain valid. */
	tal_free(rune);

	/* Try to get the freed strings reused by other allocations, so the
	 * dangling pointers point at garbage in plain builds too. */
	for (size_t i = 0; i < 64; i++)
		tal_free(tal_strdup(NULL, "XXXX"));

	/* Under ASan these uses of dup abort with heap-use-after-free. */
	ok1(streq(dup->unique_id, "uid1"));
	ok1(streq(dup->version, "1"));

	/* rune_eq reads unique_id/version of both sides (runestr_eq). */
	ok1(rune_eq(dup, dup));

	/* A roundtrip through the string form must still work. */
	str = rune_to_string(NULL, dup);
	ok1(rune_from_string(NULL, str) != NULL);

	tal_free(dup);
	tal_free(str);
	tal_free(master);
	/* This exits depending on whether all tests passed */
	return exit_status();
}
