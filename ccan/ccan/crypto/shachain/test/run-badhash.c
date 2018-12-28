#include <ccan/crypto/shachain/shachain.h>
/* Include the C files directly. */
#include <ccan/crypto/shachain/shachain.c>
#include <ccan/tap/tap.h>

#define NUM_TESTS 1000

int main(void)
{
	struct sha256 seed;
	struct shachain chain;
	uint64_t i;

	plan_tests(NUM_TESTS);

	memset(&seed, 0xFF, sizeof(seed));
	shachain_init(&chain);

	for (i = 0xFFFFFFFFFFFFFFFFULL;
	     i > 0xFFFFFFFFFFFFFFFFULL - NUM_TESTS;
	     i--) {
		struct sha256 expect;

		shachain_from_seed(&seed, i, &expect);
		/* Screw it up. */
		expect.u.u8[0]++;

		/* Either it should fail, or it couldn't derive any others (ie. pos 0). */
		if (shachain_add_hash(&chain, i, &expect)) {
			ok1(chain.known[0].index == i);
			/* Fix it up in-place */
			chain.known[0].hash.u.u8[0]--;
		} else {
			expect.u.u8[0]--;
			ok1(shachain_add_hash(&chain, i, &expect));
		}
	}
	return exit_status();
}
