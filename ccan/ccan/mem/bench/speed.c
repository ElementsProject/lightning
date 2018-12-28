/* Test speed of memiszero */
#include <ccan/time/time.h>
#include <ccan/mem/mem.h>
#include <stdlib.h>
#include <stdio.h>
#include <assert.h>

#define MAX_TEST 65536

int main(int argc, char *argv[])
{
	size_t n, i, max = argv[1] ? atol(argv[1]) : 100000000, runs;
	char *arr;
	size_t total = 0;

	arr = calloc(1, max + MAX_TEST + 1);

	runs = max;
	/* First test even sizes case. */
	for (n = 1; n <= MAX_TEST; n *= 2) {
		struct timeabs start = time_now();
		struct timerel each;

		for (i = 0; i < runs; i++)
			total += memeqzero(arr + i, n);
		each = time_divide(time_between(time_now(), start), runs);
		assert(each.ts.tv_sec == 0);
		printf("%zu: %uns\n", n, (unsigned int)each.ts.tv_nsec);

		/* Reduce runs over time, as bigger take longer. */
		runs = runs * 2 / 3;
	}

	runs = max;
	for (n = 1; n <= MAX_TEST; n *= 2) {
		struct timeabs start = time_now();
		struct timerel each;

		for (i = 0; i < runs; i++)
			total += memeqzero(arr + i, n+1);
		each = time_divide(time_between(time_now(), start), runs);
		assert(each.ts.tv_sec == 0);
		printf("%zu: %uns\n", n+1, (unsigned int)each.ts.tv_nsec);
		runs = runs * 2 / 3;
	}

	printf("total = %zu\n", total);
	return 0;
}
