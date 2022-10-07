#include <ccan/crypto/ripemd160/ripemd160.h>
/* Include the C files directly. */
#include <ccan/crypto/ripemd160/ripemd160.c>
#include <ccan/tap/tap.h>

int main(void)
{
	struct ripemd160 h, expected;
	static const char zeroes[1000];
	size_t i;

	plan_tests(63);

	/* Test different alignments. */
	ripemd160(&expected, zeroes, sizeof(zeroes) - 64);
	for (i = 1; i < 64; i++) {
		ripemd160(&h, zeroes + i, sizeof(zeroes) - 64);
		ok1(memcmp(&h, &expected, sizeof(h)) == 0);
	}

	/* This exits depending on whether all tests passed */
	return exit_status();
}
