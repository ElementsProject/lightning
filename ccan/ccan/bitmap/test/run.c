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
#define NTESTS 9

static void test_sizes(int nbits, bool dynalloc)
{
	BITMAP_DECLARE(sbitmap, nbits);
	uint32_t marker;
	bitmap *bitmap;
	int i, j;
	bool wrong;

	if (dynalloc) {
		bitmap = bitmap_alloc(nbits);
		ok1(bitmap != NULL);
	} else {
		bitmap = sbitmap;
		marker = 0xdeadbeef;
	}

	bitmap_zero(bitmap, nbits);
	wrong = false;
	for (i = 0; i < nbits; i++) {
		wrong = wrong || bitmap_test_bit(bitmap, i);
	}
	ok1(!wrong);

	bitmap_fill(bitmap, nbits);
	wrong = false;
	for (i = 0; i < nbits; i++) {
		wrong = wrong || !bitmap_test_bit(bitmap, i);
	}
	ok1(!wrong);

	wrong = false;
	for (i = 0; i < nbits; i++) {
		bitmap_zero(bitmap, nbits);
		bitmap_set_bit(bitmap, i);
		for (j = 0; j < nbits; j++) {
			bool val = (i == j);

			wrong = wrong || (bitmap_test_bit(bitmap, j) != val);
		}
	}
	ok1(!wrong);

	wrong = false;
	for (i = 0; i < nbits; i++) {
		bitmap_fill(bitmap, nbits);
		bitmap_clear_bit(bitmap, i);
		for (j = 0; j < nbits; j++) {
			bool val = !(i == j);

			wrong = wrong || (bitmap_test_bit(bitmap, j) != val);
		}
	}
	ok1(!wrong);

	bitmap_zero(bitmap, nbits);
	ok1(bitmap_empty(bitmap, nbits));

	wrong = false;
	for (i = 0; i < nbits; i++) {
		bitmap_zero(bitmap, nbits);
		bitmap_set_bit(bitmap, i);
		wrong = wrong || bitmap_empty(bitmap, nbits);
	}
	ok1(!wrong);

	bitmap_fill(bitmap, nbits);
	ok1(bitmap_full(bitmap, nbits));

	wrong = false;
	for (i = 0; i < nbits; i++) {
		bitmap_fill(bitmap, nbits);
		bitmap_clear_bit(bitmap, i);
		wrong = wrong || bitmap_full(bitmap, nbits);
	}
	ok1(!wrong);
	
	if (dynalloc) {
		free(bitmap);
	} else {
		ok1(marker == 0xdeadbeef);
	}
}

int main(void)
{
	int i;
	bool dynalloc;

	/* This is how many tests you plan to run */
	plan_tests(NSIZES * NTESTS * 2);

	for (i = 0; i < NSIZES; i++) {
		foreach_int(dynalloc, false, true) {
			diag("Testing %d-bit bitmap (%s allocation)",
			     bitmap_sizes[i], dynalloc ? "dynamic" : "static");
			test_sizes(bitmap_sizes[i], dynalloc);
		}
	}

	/* This exits depending on whether all tests passed */
	return exit_status();
}
