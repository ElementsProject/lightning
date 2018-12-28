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

static unsigned int count_trailing_zeroes(uint64_t index)
{
#if HAVE_BUILTIN_CTZLL
	return index ? (unsigned int)__builtin_ctzll(index) : SHACHAIN_BITS;
#else
	unsigned int i;

	for (i = 0; i < SHACHAIN_BITS; i++) {
		if (index & (1ULL << i))
			break;
	}
	return i;
#endif
}

static bool can_derive(uint64_t from, uint64_t to)
{
	uint64_t mask;

	/* Corner case: can always derive from seed. */
	if (from == 0)
		return true;

	/* Leading bits must be the same */
	mask = ~(((uint64_t)1 << count_trailing_zeroes(from))-1);
	return ((from ^ to) & mask) == 0;
}

static void derive(uint64_t from, uint64_t to,
		   const struct sha256 *from_hash,
		   struct sha256 *hash)
{
	uint64_t branches;
	int i;

	assert(can_derive(from, to));

	/* We start with the first hash. */
	*hash = *from_hash;

	/* This represents the bits set in to, and not from. */
	branches = from ^ to;
	for (i = ilog64(branches) - 1; i >= 0; i--) {
		if (((branches >> i) & 1)) {
			change_bit(hash->u.u8, i);
			sha256(hash, hash, sizeof(*hash));
		}
	}
}

void shachain_from_seed(const struct sha256 *seed, uint64_t index,
			struct sha256 *hash)
{
	derive(0, index, seed, hash);
}

uint64_t shachain_next_index(const struct shachain *chain)
{
	return chain->min_index - 1;
}

void shachain_init(struct shachain *chain)
{
	chain->num_valid = 0;
	/* This is 0 in the case where SHACHAIN_BITS is 64. */
	chain->min_index = (UINT64_MAX >> (64 - SHACHAIN_BITS)) + 1;
}

bool shachain_add_hash(struct shachain *chain,
		       uint64_t index, const struct sha256 *hash)
{
	unsigned int i, pos;

	/* You have to insert them in order! */
	assert(index == shachain_next_index(chain));

	pos = count_trailing_zeroes(index);

	/* All derivable answers must be valid. */
	/* FIXME: Is it sufficient to check just the next answer? */
	for (i = 0; i < pos; i++) {
		struct sha256 expect;

		/* Make sure the others derive as expected! */
		derive(index, chain->known[i].index, hash, &expect);
		if (memcmp(&expect, &chain->known[i].hash, sizeof(expect)))
			return false;
	}

	chain->known[pos].index = index;
	chain->known[pos].hash = *hash;
	if (pos + 1 > chain->num_valid)
		chain->num_valid = pos + 1;
	chain->min_index = index;
	return true;
}

bool shachain_get_hash(const struct shachain *chain,
		       uint64_t index, struct sha256 *hash)
{
	unsigned int i;

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
