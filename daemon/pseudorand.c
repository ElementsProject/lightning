#include "pseudorand.h"
#include <assert.h>
#include <ccan/crypto/siphash24/siphash24.h>
#include <ccan/err/err.h>
#include <ccan/isaac/isaac64.h>
#include <ccan/likely/likely.h>
#include <sodium/randombytes.h>
#include <stdbool.h>
#include <string.h>

static struct isaac64_ctx isaac64;
static struct siphash_seed siphashseed;
static bool pseudorand_initted = false;

static void init_if_needed(void)
{
	if (unlikely(!pseudorand_initted)) {
		unsigned char seedbuf[16];

		randombytes_buf(seedbuf, sizeof(seedbuf));

		isaac64_init(&isaac64, seedbuf, sizeof(seedbuf));
		memcpy(&siphashseed, seedbuf, sizeof(siphashseed));
		pseudorand_initted = true;
	}
}

uint64_t pseudorand(uint64_t max)
{
	init_if_needed();

	assert(max);
	return isaac64_next_uint(&isaac64, max);
}

const struct siphash_seed *siphash_seed(void)
{
	init_if_needed();

	return &siphashseed;
}
