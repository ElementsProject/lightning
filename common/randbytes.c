#include "config.h"
#include <assert.h>
#include <ccan/crypto/siphash24/siphash24.h>
#include <ccan/endian/endian.h>
#include <ccan/short_types/short_types.h>
#include <ccan/tal/tal.h>
#include <common/memleak.h>
#include <common/pseudorand.h>
#include <common/randbytes.h>
#include <common/utils.h>
#include <sodium/randombytes.h>
#include <stdbool.h>
#include <stdlib.h>
#include <unistd.h>

static bool used = false;
static u64 dev_seed = 0;

bool randbytes_overridden(void)
{
	return dev_seed != 0;
}

void randbytes_(void *bytes, size_t num_bytes, u64 *offset)
{
	static u64 offset_init;
	be64 pattern;

	used = true;
	if (!randbytes_overridden()) {
		randombytes_buf(bytes, num_bytes); /* discouraged: use randbytes() */
		return;
	}

	/* First time, start callers at different offsets */
	if (*offset == 0) {
		*offset = offset_init;
		offset_init += 1000;
	}

	/* Somewhat recognizable pattern */
	pattern = cpu_to_be64(dev_seed + (*offset)++);
	for (size_t i = 0; i < num_bytes; i += sizeof(pattern)) {
		size_t copy = num_bytes - i;
		if (copy > sizeof(pattern))
			copy = sizeof(pattern);

		memcpy((u8 *)bytes + i, &pattern, copy);
	}
}

/* We want different seeds for each plugin (hence argv0), and for each
 * lightmingd instance, (hence seed from environment) */
void dev_override_randbytes(const char *argv0, long int seed)
{
	struct siphash_seed hashseed;
	assert(!used);

	hashseed.u.u64[0] = seed;
	hashseed.u.u64[1] = 0;

	dev_seed = siphash24(&hashseed, argv0, strlen(argv0));
	assert(randbytes_overridden());
}
