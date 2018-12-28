#define SHACHAIN_BITS 8

#include <ccan/crypto/shachain/shachain.h>
/* Include the C files directly. */
#include <ccan/crypto/shachain/shachain.c>
#include <ccan/tap/tap.h>

#include <stdio.h>

#define NUM_TESTS 255

int main(void)
{
	struct sha256 seed;
	struct shachain chain;
	struct sha256 expect[NUM_TESTS+1];
	int i, j;

	/* This is how many tests you plan to run */
	plan_tests(66559);

	memset(&seed, 0, sizeof(seed));
	/* Generate a whole heap; each should be different */
	for (i = 0; i <= NUM_TESTS; i++) {
		shachain_from_seed(&seed, i, &expect[i]);
		if (i == 0)
			ok1(memcmp(&expect[i], &seed, sizeof(expect[i])) == 0);
		else
			ok1(memcmp(&expect[i], &expect[i-1], sizeof(expect[i])));
	}

	shachain_init(&chain);

	for (i = NUM_TESTS; i > 0; i--) {
		struct sha256 hash;

		ok1(shachain_add_hash(&chain, i, &expect[i]));
		for (j = i; j <= NUM_TESTS; j++) {
			ok1(shachain_get_hash(&chain, j, &hash));
			ok1(memcmp(&hash, &expect[j], sizeof(hash)) == 0);
		}
		ok1(!shachain_get_hash(&chain, i-1, &hash));
	}

	/* Now add seed. */
	ok1(shachain_add_hash(&chain, 0, &expect[0]));
	for (j = 0; j <= NUM_TESTS; j++) {
		struct sha256 hash;
		ok1(shachain_get_hash(&chain, j, &hash));
		ok1(memcmp(&hash, &expect[j], sizeof(hash)) == 0);
	}

	return exit_status();
}
