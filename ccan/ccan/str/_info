#include "config.h"
#include <stdio.h>
#include <string.h>

/**
 * str - string helper routines
 *
 * This is a grab bag of functions for string operations, designed to enhance
 * the standard string.h.
 *
 * Note that if you define CCAN_STR_DEBUG, you will get extra compile
 * checks on common misuses of the following functions (they will now
 * be out-of-line, so there is a runtime penalty!).
 *
 *	strstr, strchr, strrchr:
 *		Return const char * if first argument is const (gcc only).
 *
 *	isalnum, isalpha, isascii, isblank, iscntrl, isdigit, isgraph,
 *	    islower, isprint, ispunct, isspace, isupper, isxdigit:
 *		Static and runtime check that input is EOF or an *unsigned*
 *		char, as per C standard (really!).
 *
 * Example:
 *	#include <stdio.h>
 *	#include <ccan/str/str.h>
 *
 *	int main(int argc, char *argv[])
 *	{
 *		if (argc > 1 && streq(argv[1], "--verbose"))
 *			printf("verbose set\n");
 *		if (argc > 1 && strstarts(argv[1], "--"))
 *			printf("Some option set\n");
 *		if (argc > 1 && strends(argv[1], "cow-powers"))
 *			printf("Magic option set\n");
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
