#include <ccan/bitmap/bitmap.h>
#include <ccan/tap/tap.h>
#include <ccan/array_size/array_size.h>
#include <ccan/foreach/foreach.h>

#include <ccan/bitmap/bitmap.c>

int bitmap_sizes[] = {
	1, 2, 3, 4, 5, 6, 7, 8,
	16, 17, 24, 32, 33,
	64, 65, 127, 128, 129,
	1023, 1024, 1025,
};
#define NSIZES ARRAY_SIZE(bitmap_sizes)

#define ok_eq(a, b) \
	ok((a) == (b), "%s [%u] == %s [%u]", \
	   #a, (unsigned)(a), #b, (unsigned)(b))

static void test_size(int nbits)
{
	BITMAP_DECLARE(bitmap, nbits);
	int i;

	bitmap_zero(bitmap, nbits);
	ok_eq(bitmap_ffs(bitmap, 0, nbits), nbits);

	for (i = 0; i < nbits; i++) {
		bitmap_zero(bitmap, nbits);
		bitmap_set_bit(bitmap, i);

		ok_eq(bitmap_ffs(bitmap, 0, nbits), i);
		ok_eq(bitmap_ffs(bitmap, i, nbits), i);
		ok_eq(bitmap_ffs(bitmap, i + 1, nbits), nbits);

		bitmap_zero(bitmap, nbits);
		bitmap_fill_range(bitmap, i, nbits);

		ok_eq(bitmap_ffs(bitmap, 0, nbits), i);
		ok_eq(bitmap_ffs(bitmap, i, nbits), i);
		ok_eq(bitmap_ffs(bitmap, i + 1, nbits), (i + 1));
		ok_eq(bitmap_ffs(bitmap, nbits - 1, nbits), (nbits - 1));

		if (i > 0) {
			ok_eq(bitmap_ffs(bitmap, 0, i), i);
			ok_eq(bitmap_ffs(bitmap, 0, i - 1), (i - 1));
		}

		if (i > 0) {
			bitmap_zero(bitmap, nbits);
			bitmap_fill_range(bitmap, 0, i);

			ok_eq(bitmap_ffs(bitmap, 0, nbits), 0);
			ok_eq(bitmap_ffs(bitmap, i - 1, nbits), (i - 1));
			ok_eq(bitmap_ffs(bitmap, i, nbits), nbits);
		}
	}
}

int main(void)
{
	int i;

	/* Too complicated to work out the exact number */
	plan_no_plan();

	for (i = 0; i < NSIZES; i++) {
		diag("Testing %d-bit bitmap", bitmap_sizes[i]);
		test_size(bitmap_sizes[i]);
	}

	/* This exits depending on whether all tests passed */
	return exit_status();
}
