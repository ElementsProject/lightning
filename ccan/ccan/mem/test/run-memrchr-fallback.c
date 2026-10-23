/* Regression test (auditor-added, temporary): the memrchr fallback in
 * ccan/mem/mem.c:30-43 (compiled when HAVE_MEMRCHR == 0) must convert
 * c to unsigned char, as memchr does (C17 7.24.5.1/2; memrchr is
 * "like memchr, searching backward").  mem.c:36 compares
 * p[n-1] == c without the conversion, so any c outside 0..255
 * (e.g. a negative char, or an int with high bits set) never matches,
 * where the real memrchr finds the byte.
 *
 * To exercise the fallback regardless of host libc, this test forces
 * HAVE_MEMRCHR to 0 and includes the module source directly.
 *
 * Currently fails 3/5; must pass after repair.
 */
#include "config.h"

/* Force the fallback implementation, whatever the host provides. */
#undef HAVE_MEMRCHR
#define HAVE_MEMRCHR 0

#include <unistd.h>

#include <ccan/mem/mem.c>
#include <ccan/tap/tap.h>

int main(void)
{
	const unsigned char buf[] = { 0x41, 0xFF, 0x42 };

	alarm(10);
	plan_tests(5);

	/* Baseline: ordinary c values work. */
	ok1(memrchr(buf, 0x42, sizeof(buf)) == buf + 2);
	ok1(memrchr(buf, 'q', sizeof(buf)) == NULL);

	/* c = -1 must behave as (unsigned char)-1 == 0xFF. */
	ok1(memrchr(buf, -1, sizeof(buf)) == buf + 1);

	/* c = 0x1FF must behave as 0xFF. */
	ok1(memrchr(buf, 0x1FF, sizeof(buf)) == buf + 1);

	/* c = 0x141 must behave as 0x41 ('A'). */
	ok1(memrchr(buf, 0x141, sizeof(buf)) == buf + 0);

	return exit_status();
}
