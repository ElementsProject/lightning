#include "config.h"
#include <assert.h>
#include <ccan/crypto/sha256/sha256.h>
#include <ccan/crypto/siphash24/siphash24.h>
#include <ccan/isaac/isaac64.h>
#include <ccan/likely/likely.h>
#include <common/pseudorand.h>
#include <sodium/randombytes.h>
#include <string.h>

static struct isaac64_ctx isaac64;
static struct siphash_seed siphashseed;
static bool pseudorand_initted = false;

static void init_if_needed(void)
{
	if (unlikely(!pseudorand_initted)) {
		unsigned char seedbuf[16];
		struct sha256 sha;

		randombytes_buf(seedbuf, sizeof(seedbuf));
		memcpy(&siphashseed, seedbuf, sizeof(siphashseed));

		/* In case isaac is reversible, don't leak seed. */
		sha256(&sha, seedbuf, sizeof(seedbuf));
		isaac64_init(&isaac64, sha.u.u8, sizeof(sha.u.u8));
		pseudorand_initted = true;
	}
}

uint64_t pseudorand(uint64_t max)
{
	init_if_needed();

	assert(max);
	return isaac64_next_uint(&isaac64, max);
}

uint64_t pseudorand_u64(void)
{
	init_if_needed();

	return isaac64_next_uint64(&isaac64);
}

double pseudorand_double(void)
{
	init_if_needed();

	return isaac64_next_double(&isaac64);
}

const struct siphash_seed *siphash_seed(void)
{
	init_if_needed();

	return &siphashseed;
}
