#include "pseudorand.h"
#include <assert.h>
#include <ccan/err/err.h>
#include <ccan/isaac/isaac64.h>
#include <ccan/likely/likely.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <stdbool.h>

static struct isaac64_ctx isaac64;
static bool pseudorand_initted = false;

uint64_t pseudorand(uint64_t max)
{
	if (unlikely(!pseudorand_initted)) {
		unsigned char seedbuf[16];

		/* PRNG */
		if (RAND_bytes(seedbuf, sizeof(seedbuf)) != 1)
			errx(1, "Could not seed PRNG: %s",
			     ERR_error_string(ERR_get_error(), NULL));

		isaac64_init(&isaac64, seedbuf, sizeof(seedbuf));
		pseudorand_initted = true;
	}
	assert(max);
	return isaac64_next_uint(&isaac64, max);
}
