/* MIT (BSD) license - see LICENSE file for details */
#include <ccan/crypto/shachain/shachain.h>
#include <ccan/ilog/ilog.h>
#include <limits.h>
#include <string.h>
#include <assert.h>

static void change_bit(unsigned char *arr, size_t index)
{
	arr[index / CHAR_BIT] ^= (1 << (index % CHAR_BIT));
}

/* We can only ever *unset* bits, so to must only have bits in from. */
static bool can_derive(shachain_index_t from, shachain_index_t to)
{
	return (~from & to) == 0;
}

static void derive(shachain_index_t from, shachain_index_t to,
		   const struct sha256 *from_hash,
		   struct sha256 *hash)
{
	shachain_index_t branches;
	int i;

	assert(can_derive(from, to));

	/* We start with the first hash. */
	*hash = *from_hash;

	/* This represents the bits set in from, and not to. */
	branches = from ^ to;
	for (i = ilog64(branches) - 1; i >= 0; i--) {
		if (((branches >> i) & 1)) {
			change_bit(hash->u.u8, i);
			sha256(hash, hash, sizeof(*hash));
		}
	}
}

void shachain_from_seed(const struct sha256 *seed, shachain_index_t index,
			struct sha256 *hash)
{
	derive((shachain_index_t)-1ULL, index, seed, hash);
}

void shachain_init(struct shachain *chain)
{
	chain->num_valid = 0;
	chain->max_index = 0;
}

bool shachain_add_hash(struct shachain *chain,
		       shachain_index_t index, const struct sha256 *hash)
{
	int i;

	/* You have to insert them in order! */
	assert(index == chain->max_index + 1 ||
	       (index == 0 && chain->num_valid == 0));
	
	for (i = 0; i < chain->num_valid; i++) {
		/* If we could derive this value, we don't need it,
		 * not any others (since they're in order). */
		if (can_derive(index, chain->known[i].index)) {
			struct sha256 expect;

			/* Make sure the others derive as expected! */
			derive(index, chain->known[i].index, hash, &expect);
			if (memcmp(&expect, &chain->known[i].hash,
				   sizeof(expect)) != 0)
				return false;
			break;
		}
	}

	/* This can happen if you skip indices! */
	assert(i < sizeof(chain->known) / sizeof(chain->known[0]));
	chain->known[i].index = index;
	chain->known[i].hash = *hash;
	chain->num_valid = i+1;
	chain->max_index = index;
	return true;
}

bool shachain_get_hash(const struct shachain *chain,
		       shachain_index_t index, struct sha256 *hash)
{
	int i;

	for (i = 0; i < chain->num_valid; i++) {
		/* If we can get from key to index only by resetting bits,
		 * we can derive from it => index has no bits key doesn't. */
		if (!can_derive(chain->known[i].index, index))
			continue;

		derive(chain->known[i].index, index, &chain->known[i].hash,
		       hash);
		return true;
	}
	return false;
}
