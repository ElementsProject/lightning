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
	uint64_t i, j;

	/* This is how many tests you plan to run */
	plan_tests(NUM_TESTS * 4 + NUM_TESTS * (NUM_TESTS + 1) - 1);

	memset(&seed, 0, sizeof(seed));
	/* Generate a whole heap. */
	for (i = 0xFFFFFFFFFFFFFFFFULL;
	     i > 0xFFFFFFFFFFFFFFFFULL - NUM_TESTS;
	     i--) {
		int expidx = 0xFFFFFFFFFFFFFFFFULL - i;
		shachain_from_seed(&seed, i, &expect[expidx]);
		if (i != 0xFFFFFFFFFFFFFFFFULL)
			ok1(memcmp(&expect[expidx], &expect[expidx-1],
				   sizeof(expect[expidx])));
	}

	shachain_init(&chain);

	for (i = 0xFFFFFFFFFFFFFFFFULL;
	     i > 0xFFFFFFFFFFFFFFFFULL - NUM_TESTS;
	     i--) {
		struct sha256 hash;
		int expidx = 0xFFFFFFFFFFFFFFFFULL - i;
		ok1(shachain_next_index(&chain) == i);
		ok1(shachain_add_hash(&chain, i, &expect[expidx]));
		for (j = i; j != 0; j++) {
			ok1(shachain_get_hash(&chain, j, &hash));
			expidx = 0xFFFFFFFFFFFFFFFFULL - j;
			ok1(memcmp(&hash, &expect[expidx], sizeof(hash)) == 0);
		}
		ok1(!shachain_get_hash(&chain, i-1, &hash));
	}

	return exit_status();
}
