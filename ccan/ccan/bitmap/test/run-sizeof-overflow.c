/* Regression test for the allocation-sizing overflow in BITMAP_NWORDS /
 * bitmap_sizeof (ccan/bitmap/bitmap.h:15-16, 31-34).
 *
 * BITMAP_NWORDS(_n) computes ((_n) + BITMAP_WORD_BITS - 1) /
 * BITMAP_WORD_BITS; the addition wraps for nbits within
 * BITMAP_WORD_BITS-1 of ULONG_MAX, so bitmap_sizeof() returns a tiny
 * size (0 for ULONG_MAX) and bitmap_alloc() then returns a non-NULL
 * pointer to a 0-byte allocation that purports to hold ~2^64 bits; the
 * first bitmap_set_bit() writes out of bounds (observed: ASan
 * heap-buffer-overflow, access of size 8 on a 1-byte region).
 *
 * Correct behavior: the reference computation below (divide first,
 * then round up) never overflows and its product with
 * sizeof(bitmap_word) still fits in size_t on both LP64 and ILP32, so
 * bitmap_sizeof() must equal it for every nbits, including ULONG_MAX
 * (bitmap_alloc() will then correctly fail with NULL for the
 * unmappable ~2^61-byte request).
 */
#include <ccan/bitmap/bitmap.h>
#include <ccan/bitmap/bitmap.c>
#include <ccan/tap/tap.h>
#include <limits.h>
#include <unistd.h>

static unsigned long ref_nwords(unsigned long nbits)
{
	return nbits / BITMAP_WORD_BITS + ((nbits % BITMAP_WORD_BITS) != 0);
}

int main(void)
{
	/* Largest nbits that does NOT wrap the + (BITS-1) addition. */
	unsigned long edge = ULONG_MAX - (BITMAP_WORD_BITS - 1);

	alarm(10);
	plan_tests(4);

	/* These two fail against the current code (both return 0). */
	ok1(BITMAP_NWORDS(ULONG_MAX) == ref_nwords(ULONG_MAX));
	ok1(bitmap_sizeof(ULONG_MAX) ==
	    ref_nwords(ULONG_MAX) * sizeof(bitmap_word));

	/* Boundary sanity: these already pass today and must keep passing. */
	ok1(BITMAP_NWORDS(edge) == ref_nwords(edge));
	ok1(bitmap_sizeof(edge) == ref_nwords(edge) * sizeof(bitmap_word));

	return exit_status();
}
