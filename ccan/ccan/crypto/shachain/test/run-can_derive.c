#define shachain_index_t uint8_t

#include <ccan/crypto/shachain/shachain.h>
/* Include the C files directly. */
#include <ccan/crypto/shachain/shachain.c>
#include <ccan/tap/tap.h>

#include <stdio.h>

static bool bit_set(uint64_t index, int bit)
{
	return index & (1ULL << bit);
}

/* As per design.txt */
static bool naive_can_derive(uint64_t from, shachain_index_t to)
{
	int i;

	for (i = count_trailing_zeroes(from); i < 8; i++) {
		if (bit_set(from, i) != bit_set(to, i))
			return false;
	}
	return true;
}

int main(void)
{
	int i, j;

	/* This is how many tests you plan to run */
	plan_tests(65536);

	for (i = 0; i < 256; i++) {
		for (j = 0; j < 256; j++) {
			ok1(can_derive(i, j) == naive_can_derive(i, j));
		}
	}

	return exit_status();
}
