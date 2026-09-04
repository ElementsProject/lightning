/* Regression test (auditor-added, temporary): memcchr must treat c the
 * way memchr does -- converted to unsigned char -- since it is
 * documented as "The complement of memchr()" (mem.h:76).
 *
 * ccan/mem/mem.c:63 compares a *signed* char against int c, so bytes
 * 0x80..0xFF are never considered equal to c values 128..255, and
 * c values > 255 never match the byte they convert to.
 *
 * Currently fails 3/3; must pass after repair.
 */
#include "config.h"

#include <unistd.h>
#include <string.h>

#include <ccan/mem/mem.c>
#include <ccan/tap/tap.h>

int main(void)
{
	char buf80[] = { (char)0x80, (char)0x80, 'x' };
	char bufff[] = { (char)0xFF, 'y' };
	char buf00[] = { 0x00, 'z' };

	alarm(10);
	plan_tests(6);

	/* Sanity: memchr itself converts c to unsigned char. */
	ok1(memchr(buf80, 0x80, sizeof(buf80)) == buf80);
	ok1(memchr(buf00, 0x100, sizeof(buf00)) == buf00);

	/* c = 0x80: the complement must skip the two 0x80 bytes. */
	ok1(memcchr(buf80, 0x80, sizeof(buf80)) == buf80 + 2);

	/* c = 255: the complement must skip the 0xFF byte. */
	ok1(memcchr(bufff, 255, sizeof(bufff)) == bufff + 1);

	/* c = 0x100 converts to 0x00: the complement must skip the NUL. */
	ok1(memcchr(buf00, 0x100, sizeof(buf00)) == buf00 + 1);

	/* An ordinary in-range c must still work. */
	ok1(memcchr(buf80, 'x', sizeof(buf80)) == buf80);

	return exit_status();
}
