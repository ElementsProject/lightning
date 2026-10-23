/* Regression test for strmap_getn_ reading past the stored key (and
 * falsely matching) when the counted member buffer contains an embedded
 * NUL before memberlen (ccan/strmap/strmap.c:45).
 *
 * Correct behavior: a memberlen-byte buffer can only match a key of
 * exactly memberlen bytes; keys are NUL-terminated C strings, so a
 * buffer with an embedded NUL must never match.  The current code's
 * strncmp() stops at the common NUL, then evaluates n->u.s[memberlen],
 * which (a) reads past the end of a shorter stored key and (b) if that
 * out-of-bounds byte happens to be 0, returns a false match.
 *
 * Subtests 1-3 use a key stored in a zero-padded buffer so the current
 * code deterministically returns a WRONG match in a plain build.
 * Subtests 4-5 use a tightly allocated key; today they read 2 bytes past
 * the 3-byte allocation (ASan: heap-buffer-overflow at strmap.c:45).
 */
#include <ccan/strmap/strmap.h>
#include <ccan/strmap/strmap.c>
#include <ccan/tap/tap.h>
#include <string.h>
#include <errno.h>
#include <signal.h>
#include <unistd.h>

int main(void)
{
	STRMAP(char *) map;
	static char keybuf[16] = "hi"; /* zero-padded: current code reads [5] */
	static const char member[5] = { 'h', 'i', 0, 0, 0 };
	char *tight;
	void *v;

	alarm(10);
	plan_tests(6);

	strmap_init(&map);

	/* Empty map: ENOENT, no read at all. */
	errno = 0;
	ok1(strmap_getn(&map, member, 5) == NULL);
	ok1(errno == ENOENT);

	strmap_add(&map, keybuf, keybuf);

	/* The buffer's first 5 bytes contain an embedded NUL; no 5-byte
	 * key can exist in the map, so this must be an ENOENT miss. */
	errno = 0;
	v = strmap_getn(&map, member, 5);
	ok1(v == NULL);
	ok1(errno == ENOENT);

	/* Same, with a tightly allocated key: today strmap.c:45 reads
	 * n->u.s[5], 2 bytes past the 3-byte allocation. */
	tight = strdup("yo");
	strmap_add(&map, tight, tight);
	{
		static const char member2[5] = { 'y', 'o', 0, 0, 0 };
		errno = 0;
		ok1(strmap_getn(&map, member2, 5) == NULL);
		ok1(errno == ENOENT);
	}

	strmap_clear(&map);
	free(tight);

	return exit_status();
}
