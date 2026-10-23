/* Regression test for the !HAVE_QSORT_R_PRIVATE_LAST fallback in asort.c.
 *
 * The vendored glibc mergesort fallback must compile on any supported
 * platform, including glibc systems where config.h legitimately has
 * HAVE_QSORT_R_PRIVATE_LAST == 0 (e.g. ccanlint's reduce_features
 * check, hand-written or cross-compilation configs).  glibc's string.h
 * declares __mempcpy under _DEFAULT_SOURCE (on by default), so the
 * fallback's "static inline void *__mempcpy(...)" helper collides with
 * the libc declaration: "error: static declaration of '__mempcpy'
 * follows non-static declaration".  This test forces the fallback on
 * and therefore fails to compile on glibc today; after the helper is
 * renamed it must compile and pass everywhere.
 */
#include "config.h"
#undef HAVE_QSORT_R_PRIVATE_LAST
#define HAVE_QSORT_R_PRIVATE_LAST 0
#include <ccan/asort/asort.h>
#include <ccan/asort/asort.c>
#include <ccan/tap/tap.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static int cmp_int(const int *a, const int *b, int *count)
{
	(*count)++;
	return (*a > *b) - (*a < *b);
}

struct big { char pad[9]; int key; char pad2[31]; }; /* 44 bytes: indirect */
static int cmp_big(const struct big *a, const struct big *b, int *count)
{
	(*count)++;
	return (a->key > b->key) - (a->key < b->key);
}

static bool sorted_ints(const int *a, size_t n)
{
	for (size_t i = 1; i < n; i++)
		if (a[i-1] > a[i])
			return false;
	return true;
}

int main(void)
{
	alarm(10);
	plan_tests(3);

	/* Small array: mergesort with the stack buffer. */
	{
		int a[50];
		int count = 0;
		for (size_t i = 0; i < 50; i++)
			a[i] = (int)((i * 37 + 11) % 23);
		asort(a, 50, cmp_int, &count);
		ok1(sorted_ints(a, 50) && count > 0);
	}

	/* 40000 bytes: exceeds QSORT_STACK_SIZE, takes the malloc path. */
	{
		size_t n = 10000;
		int *a = malloc(n * sizeof(*a));
		int count = 0;
		unsigned long long r = 12345;
		for (size_t i = 0; i < n; i++) {
			r ^= r << 13; r ^= r >> 7; r ^= r << 17;
			a[i] = (int)r;
		}
		asort(a, n, cmp_int, &count);
		ok1(sorted_ints(a, n));
		free(a);
	}

	/* Elements larger than 32 bytes: indirect (pointer) mergesort. */
	{
		size_t n = 100;
		struct big *b = malloc(n * sizeof(*b));
		int count = 0;
		bool ok = true;
		for (size_t i = 0; i < n; i++) {
			memset(&b[i], (int)(i & 0xff), sizeof(*b));
			b[i].key = (int)((i * 53) % 31);
		}
		asort(b, n, cmp_big, &count);
		for (size_t i = 1; i < n; i++)
			if (b[i-1].key > b[i].key)
				ok = false;
		ok1(ok);
		free(b);
	}

	return exit_status();
}
