#include <ccan/crypto/shachain/shachain.h>
/* Include the C files directly. */
#include <ccan/crypto/shachain/shachain.c>
#include <ccan/tap/tap.h>

#define NUM_TESTS 50

int main(void)
{
	struct sha256 seed;
	struct shachain chain;
	struct sha256 expect[NUM_TESTS];
	size_t i, j;

	/* This is how many tests you plan to run */
	plan_tests(NUM_TESTS * 3 + NUM_TESTS * (NUM_TESTS + 1));

	memset(&seed, 0, sizeof(seed));
	/* Generate a whole heap. */
	for (i = 0; i < NUM_TESTS; i++) {
		shachain_from_seed(&seed, i, &expect[i]);
		if (i == 0)
			ok1(memcmp(&expect[i], &seed, sizeof(expect[i])));
		else
			ok1(memcmp(&expect[i], &expect[i-1], sizeof(expect[i])));
	}

	shachain_init(&chain);

	for (i = 0; i < NUM_TESTS; i++) {
		struct sha256 hash;

		ok1(shachain_add_hash(&chain, i, &expect[i]));
		for (j = 0; j <= i; j++) {
			ok1(shachain_get_hash(&chain, j, &hash));
			ok1(memcmp(&hash, &expect[j], sizeof(hash)) == 0);
		}
		ok1(!shachain_get_hash(&chain, i+1, &hash));
	}

	return exit_status();
}
