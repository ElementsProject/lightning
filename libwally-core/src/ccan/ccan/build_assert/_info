#include "config.h"
#include <stdio.h>
#include <string.h>

/**
 * build_assert - routines for build-time assertions
 *
 * This code provides routines which will cause compilation to fail should some
 * assertion be untrue: such failures are preferable to run-time assertions,
 * but much more limited since they can only depends on compile-time constants.
 *
 * These assertions are most useful when two parts of the code must be kept in
 * sync: it is better to avoid such cases if possible, but seconds best is to
 * detect invalid changes at build time.
 *
 * For example, a tricky piece of code might rely on a certain element being at
 * the start of the structure.  To ensure that future changes don't break it,
 * you would catch such changes in your code like so:
 *
 * Example:
 *	#include <stddef.h>
 *	#include <ccan/build_assert/build_assert.h>
 *
 *	struct foo {
 *		char string[5];
 *		int x;
 *	};
 *
 *	static char *foo_string(struct foo *foo)
 *	{
 *		// This trick requires that the string be first in the structure
 *		BUILD_ASSERT(offsetof(struct foo, string) == 0);
 *		return (char *)foo;
 *	}
 *
 * License: CC0 (Public domain)
 * Author: Rusty Russell <rusty@rustcorp.com.au>
 */
int main(int argc, char *argv[])
{
	if (argc != 2)
		return 1;

	if (strcmp(argv[1], "depends") == 0)
		/* Nothing. */
		return 0;

	return 1;
}
