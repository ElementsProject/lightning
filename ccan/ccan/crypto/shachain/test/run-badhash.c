#include <ccan/crypto/shachain/shachain.h>
/* Include the C files directly. */
#include <ccan/crypto/shachain/shachain.c>
#include <ccan/tap/tap.h>

#define NUM_TESTS 1000

int main(void)
{
	struct sha256 seed;
	struct shachain chain;
	size_t i;

	plan_tests(NUM_TESTS);

	memset(&seed, 0xFF, sizeof(seed));
	shachain_init(&chain);

	for (i = 0; i < NUM_TESTS; i++) {
		struct sha256 expect;
		unsigned int num_known = chain.num_valid;

		shachain_from_seed(&seed, i, &expect);
		/* Screw it up. */
		expect.u.u8[0]++;

		/* Either it should fail, or it couldn't derive any others. */
		if (shachain_add_hash(&chain, i, &expect)) {
			ok1(chain.num_valid == num_known + 1);
			/* Fix it up in-place */
			chain.known[num_known].hash.u.u8[0]--;
		} else {
			expect.u.u8[0]--;
			ok1(shachain_add_hash(&chain, i, &expect));
		}
	}
	return exit_status();
}
