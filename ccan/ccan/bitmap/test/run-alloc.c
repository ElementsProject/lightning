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
#define NTESTS_BASE 4
#define NTESTS_REALLOC 10

static void test_basic_alloc(int nbits)
{
	bitmap *bitmap;

	bitmap = bitmap_alloc0(nbits);
	ok1(bitmap != NULL);
	ok1(bitmap_empty(bitmap, nbits));

	free(bitmap);

	bitmap = bitmap_alloc1(nbits);
	ok1(bitmap != NULL);
	ok1(bitmap_full(bitmap, nbits));

	free(bitmap);
}

static void test_realloc(int obits, int nbits)
{
	bitmap *bitmap;
	int i;
	bool wrong;

	bitmap = bitmap_alloc0(obits);
	ok1(bitmap != NULL);
	ok1(bitmap_empty(bitmap, obits));

	bitmap = bitmap_realloc1(bitmap, obits, nbits);
	ok1(bitmap != NULL);
	if (obits < nbits)
		ok1(bitmap_empty(bitmap, obits));
	else
		ok1(bitmap_empty(bitmap, nbits));

	wrong = false;
	for (i = obits; i < nbits; i++)
		wrong = wrong || !bitmap_test_bit(bitmap, i);
	ok1(!wrong);

	free(bitmap);

	bitmap = bitmap_alloc1(obits);
	ok1(bitmap != NULL);
	ok1(bitmap_full(bitmap, obits));

	bitmap = bitmap_realloc0(bitmap, obits, nbits);
	ok1(bitmap != NULL);
	if (obits < nbits)
		ok1(bitmap_full(bitmap, obits));
	else
		ok1(bitmap_full(bitmap, nbits));

	wrong = false;
	for (i = obits; i < nbits; i++)
		wrong = wrong || bitmap_test_bit(bitmap, i);
	ok1(!wrong);

	free(bitmap);
}

int main(void)
{
	int i, j;

	/* This is how many tests you plan to run */
	plan_tests(NSIZES * NTESTS_BASE + NSIZES * NSIZES * NTESTS_REALLOC);

	for (i = 0; i < NSIZES; i++) {
		diag("Testing %d-bit bitmap", bitmap_sizes[i]);
		test_basic_alloc(bitmap_sizes[i]);
	}

	for (i = 0; i < NSIZES; i++) {
		for (j = 0; j < NSIZES; j++) {
			diag("Testing %d-bit => %d-bit bitmap",
			     bitmap_sizes[i], bitmap_sizes[j]);

			test_realloc(bitmap_sizes[i], bitmap_sizes[j]);
		}
	}

	/* This exits depending on whether all tests passed */
	return exit_status();
}
