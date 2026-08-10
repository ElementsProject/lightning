/* Characterization test (2026-08-05 audit, see audit-findings/cppmagic.md
 * F1): an argument which is textually empty or expands to no tokens
 * silently terminates CPPMAGIC_MAP / CPPMAGIC_JOIN iteration, dropping
 * all following arguments.  Pre-C23 __VA_OPT__ the emptiness test
 * cannot distinguish "expands to nothing" from "absent", so this is
 * now the documented behavior (cppmagic.h CPPMAGIC_MAP doc note).
 * This test pins it. */
#include "config.h"

#include <string.h>
#include <signal.h>

#include <ccan/cppmagic/cppmagic.h>
#include <ccan/tap/tap.h>

static inline void check1(const char *orig, const char *expand,
			  const char *match)
{
	ok(strcmp(expand, match) == 0,
	   "%s => %s : %s", orig, expand, match);
}

#define CHECK1(orig, match) \
	check1(#orig, CPPMAGIC_STRINGIFY(orig), match)

#define TESTMAP(x)	[x]

/* EMPTY is an argument which expands to no tokens. */
#define EMPTY

int main(void)
{
	alarm(10);

	plan_tests(4);

	/* An expands-to-nothing argument reads as "absent": NONEMPTY
	 * reports 0, and iteration stops before it. */
	CHECK1(CPPMAGIC_NONEMPTY(EMPTY), "0");
	CHECK1(CPPMAGIC_MAP(TESTMAP, a, EMPTY, b), "[a]");
	CHECK1(CPPMAGIC_JOIN(;, a, EMPTY, b), "a");

	/* A textually empty argument has the same behavior. */
	CHECK1(CPPMAGIC_MAP(TESTMAP, a, , b), "[a]");

	return exit_status();
}
