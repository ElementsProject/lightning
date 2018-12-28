#include "config.h"
#include <stdio.h>
#include <string.h>

/**
 * array_size - routine for safely deriving the size of a visible array.
 *
 * This provides a simple ARRAY_SIZE() macro, which (given a good compiler)
 * will also break compile if you try to use it on a pointer.
 *
 * This can ensure your code is robust to changes, without needing a gratuitous
 * macro or constant.
 *
 * Example:
 *	// Outputs "Initialized 32 values\n"
 *	#include <ccan/array_size/array_size.h>
 *	#include <stdlib.h>
 *	#include <stdio.h>
 *
 *	// We currently use 32 random values.
 *	static unsigned int vals[32];
 *
 *	int main(void)
 *	{
 *		unsigned int i;
 *		for (i = 0; i < ARRAY_SIZE(vals); i++)
 *			vals[i] = random();
 *		printf("Initialized %u values\n", i);
 *		return 0;
 *	}
 *
 * License: CC0 (Public domain)
 * Author: Rusty Russell <rusty@rustcorp.com.au>
 */
int main(int argc, char *argv[])
{
	if (argc != 2)
		return 1;

	if (strcmp(argv[1], "depends") == 0) {
		printf("ccan/build_assert\n");
		return 0;
	}

	return 1;
}
