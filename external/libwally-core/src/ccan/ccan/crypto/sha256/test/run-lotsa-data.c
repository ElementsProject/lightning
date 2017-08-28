#include <ccan/crypto/sha256/sha256.h>
/* Include the C files directly. */
#include <ccan/crypto/sha256/sha256.c>
#include <ccan/tap/tap.h>

int main(void)
{
	struct sha256 h, expected;
	static const char zeroes[1000];
	size_t i;

	plan_tests(63);

	/* Test different alignments. */
	sha256(&expected, zeroes, sizeof(zeroes) - 64);
	for (i = 1; i < 64; i++) {
		sha256(&h, zeroes + i, sizeof(zeroes) - 64);
		ok1(memcmp(&h, &expected, sizeof(h)) == 0);
	}

	/* This exits depending on whether all tests passed */
	return exit_status();
}
