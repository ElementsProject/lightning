#include <ccan/bitmap/bitmap.h>
#include <ccan/tap/tap.h>
#include <ccan/array_size/array_size.h>
#include <ccan/foreach/foreach.h>

#include <ccan/bitmap/bitmap.c>

int bitmap_sizes[] = {
	1, 2, 3, 4, 5, 6, 7, 8,
	16, 24, 32, 64, 256,
	/*
	 * Don't put too big sizes in here, or it will take forever to
	 * run under valgrind (the test is O(n^3)).
	 */
};
#define NSIZES ARRAY_SIZE(bitmap_sizes)
#define NTESTS 2

static void test_size(int nbits)
{
	BITMAP_DECLARE(bitmap, nbits);
	uint32_t marker = 0xdeadbeef;
	int i, j, k;
	bool wrong;

	for (i = 0; i < nbits; i++) {
		for (j = i; j <= nbits; j++) {
			bitmap_zero(bitmap, nbits);
			bitmap_fill_range(bitmap, i, j);

			wrong = false;
			for (k = 0; k < nbits; k++) {
				bool inrange = (k >= i) && (k < j);
				wrong = wrong || (bitmap_test_bit(bitmap, k) != inrange);
			}
			ok1(!wrong);
		}
	}

	for (i = 0; i < nbits; i++) {
		for (j = i; j <= nbits; j++) {
			bitmap_fill(bitmap, nbits);
			bitmap_zero_range(bitmap, i, j);

			wrong = false;
			for (k = 0; k < nbits; k++) {
				bool inrange = (k >= i) && (k < j);
				wrong = wrong || (bitmap_test_bit(bitmap, k) == inrange);
			}
			ok1(!wrong);
		}
	}

	ok1(marker == 0xdeadbeef);
}

int main(void)
{
	int totaltests = 0;
	int i;

	for (i = 0; i < NSIZES; i++) {
		int size = bitmap_sizes[i];

		/* Summing the arithmetic series gives: */
		totaltests += size*(size + 3) + 1;
	}
	plan_tests(totaltests);

	for (i = 0; i < NSIZES; i++) {
		diag("Testing %d-bit bitmap", bitmap_sizes[i]);
		test_size(bitmap_sizes[i]);
	}

	/* This exits depending on whether all tests passed */
	return exit_status();
}
