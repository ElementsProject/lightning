/* Regression test: asort.h must be usable from a translation unit that
 * included libc headers before it.
 *
 * With HAVE_QSORT_R_PRIVATE_LAST == 1 the asort() macro expands to a
 * direct call of qsort_r (asort.h:26), but glibc only declares qsort_r
 * under _GNU_SOURCE, and config.h's "#define _GNU_SOURCE" comes too
 * late once any libc header (via features.h) was already processed.
 * The result is a call to an undeclared function: a hard error on
 * clang >= 15 and gcc >= 14 (C99+ implicit function declarations), a
 * warning plus UB-ish implicit decl on older gcc.  Today this file
 * fails to compile under clang; after routing qsort_r through a real
 * _asort() function defined in asort.c (where config.h is included
 * first) it must compile cleanly and pass.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <unistd.h>
#include <ccan/asort/asort.h>
#include <ccan/asort/asort.c>
#include <ccan/tap/tap.h>

static int cmp_int(const int *a, const int *b, void *ctx)
{
	(void)ctx;
	return (*a > *b) - (*a < *b);
}

int main(void)
{
	int a[7] = { 7, 1, 6, 2, 5, 3, 4 };
	bool ok = true;

	alarm(10);
	plan_tests(1);

	asort(a, 7, cmp_int, NULL);
	for (size_t i = 1; i < 7; i++)
		if (a[i-1] > a[i])
			ok = false;
	ok1(ok);

	return exit_status();
}
