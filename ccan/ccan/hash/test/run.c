#include <ccan/hash/hash.h>
#include <ccan/tap/tap.h>
#include <ccan/hash/hash.c>
#include <stdbool.h>
#include <string.h>

#define ARRAY_WORDS 5

int main(int argc, char *argv[])
{
	unsigned int i, j, k;
	uint32_t array[ARRAY_WORDS], val;
	char array2[sizeof(array) + sizeof(uint32_t)];
	uint32_t results[256];

	/* Initialize array. */
	for (i = 0; i < ARRAY_WORDS; i++)
		array[i] = i;

	plan_tests(39);
	/* Hash should be the same, indep of memory alignment. */
	val = hash(array, ARRAY_WORDS, 0);
	for (i = 0; i < sizeof(uint32_t); i++) {
		memcpy(array2 + i, array, sizeof(array));
		ok(hash(array2 + i, ARRAY_WORDS, 0) != val,
		   "hash matched at offset %i", i);
	}

	/* Hash of random values should have random distribution:
	 * check one byte at a time. */
	for (i = 0; i < sizeof(uint32_t); i++) {
		unsigned int lowest = -1U, highest = 0;

		memset(results, 0, sizeof(results));

		for (j = 0; j < 256000; j++) {
			for (k = 0; k < ARRAY_WORDS; k++)
				array[k] = random();
			results[(hash(array, ARRAY_WORDS, 0) >> i*8)&0xFF]++;
		}

		for (j = 0; j < 256; j++) {
			if (results[j] < lowest)
				lowest = results[j];
			if (results[j] > highest)
				highest = results[j];
		}
		/* Expect within 20% */
		ok(lowest > 800, "Byte %i lowest %i", i, lowest);
		ok(highest < 1200, "Byte %i highest %i", i, highest);
		diag("Byte %i, range %u-%u", i, lowest, highest);
	}

	/* Hash of random values should have random distribution:
	 * check one byte at a time. */
	for (i = 0; i < sizeof(uint64_t); i++) {
		unsigned int lowest = -1U, highest = 0;

		memset(results, 0, sizeof(results));

		for (j = 0; j < 256000; j++) {
			for (k = 0; k < ARRAY_WORDS; k++)
				array[k] = random();
			results[(hash64(array, sizeof(array)/sizeof(uint64_t),
					0) >> i*8)&0xFF]++;
		}

		for (j = 0; j < 256; j++) {
			if (results[j] < lowest)
				lowest = results[j];
			if (results[j] > highest)
				highest = results[j];
		}
		/* Expect within 20% */
		ok(lowest > 800, "Byte %i lowest %i", i, lowest);
		ok(highest < 1200, "Byte %i highest %i", i, highest);
		diag("Byte %i, range %u-%u", i, lowest, highest);
	}

	/* Hash of pointer values should also have random distribution. */
	for (i = 0; i < sizeof(uint32_t); i++) {
		unsigned int lowest = -1U, highest = 0;
		char *p = malloc(256000);

		memset(results, 0, sizeof(results));

		for (j = 0; j < 256000; j++)
			results[(hash_pointer(p + j, 0) >> i*8)&0xFF]++;
		free(p);

		for (j = 0; j < 256; j++) {
			if (results[j] < lowest)
				lowest = results[j];
			if (results[j] > highest)
				highest = results[j];
		}
		/* Expect within 20% */
		ok(lowest > 800, "hash_pointer byte %i lowest %i", i, lowest);
		ok(highest < 1200, "hash_pointer byte %i highest %i",
		   i, highest);
		diag("hash_pointer byte %i, range %u-%u", i, lowest, highest);
	}

	if (sizeof(long) == sizeof(uint32_t))
		ok1(hashl(array, ARRAY_WORDS, 0)
		    == hash(array, ARRAY_WORDS, 0));
	else
		ok1(hashl(array, ARRAY_WORDS, 0)
		    == hash64(array, ARRAY_WORDS, 0));

	/* String hash: weak, so only test bottom byte */
	for (i = 0; i < 1; i++) {
		unsigned int num = 0, cursor, lowest = -1U, highest = 0;
		char p[5];

		memset(results, 0, sizeof(results));

		memset(p, 'A', sizeof(p));
		p[sizeof(p)-1] = '\0';

		for (;;) {
			for (cursor = 0; cursor < sizeof(p)-1; cursor++) {
				p[cursor]++;
				if (p[cursor] <= 'z')
					break;
				p[cursor] = 'A';
			}
			if (cursor == sizeof(p)-1)
				break;

			results[(hash_string(p) >> i*8)&0xFF]++;
			num++;
		}

		for (j = 0; j < 256; j++) {
			if (results[j] < lowest)
				lowest = results[j];
			if (results[j] > highest)
				highest = results[j];
		}
		/* Expect within 20% */
		ok(lowest > 35000, "hash_pointer byte %i lowest %i", i, lowest);
		ok(highest < 53000, "hash_pointer byte %i highest %i",
		   i, highest);
		diag("hash_pointer byte %i, range %u-%u", i, lowest, highest);
	}

	return exit_status();
}
