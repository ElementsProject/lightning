/* CC0 (Public domain) - see LICENSE file for details */
#ifndef CCAN_HASH_H
#define CCAN_HASH_H
#include "config.h"
#include <stdint.h>
#include <stdlib.h>
#include <ccan/build_assert/build_assert.h>

/* Stolen mostly from: lookup3.c, by Bob Jenkins, May 2006, Public Domain.
 * 
 * http://burtleburtle.net/bob/c/lookup3.c
 */

/**
 * hash - fast hash of an array for internal use
 * @p: the array or pointer to first element
 * @num: the number of elements to hash
 * @base: the base number to roll into the hash (usually 0)
 *
 * The memory region pointed to by p is combined with the base to form
 * a 32-bit hash.
 *
 * This hash will have different results on different machines, so is
 * only useful for internal hashes (ie. not hashes sent across the
 * network or saved to disk).
 *
 * It may also change with future versions: it could even detect at runtime
 * what the fastest hash to use is.
 *
 * See also: hash64, hash_stable.
 *
 * Example:
 *	#include <ccan/hash/hash.h>
 *	#include <err.h>
 *	#include <stdio.h>
 *	#include <string.h>
 *
 *	// Simple demonstration: idential strings will have the same hash, but
 *	// two different strings will probably not.
 *	int main(int argc, char *argv[])
 *	{
 *		uint32_t hash1, hash2;
 *
 *		if (argc != 3)
 *			err(1, "Usage: %s <string1> <string2>", argv[0]);
 *
 *		hash1 = hash(argv[1], strlen(argv[1]), 0);
 *		hash2 = hash(argv[2], strlen(argv[2]), 0);
 *		printf("Hash is %s\n", hash1 == hash2 ? "same" : "different");
 *		return 0;
 *	}
 */
#define hash(p, num, base) hash_any((p), (num)*sizeof(*(p)), (base))

/**
 * hash_stable - hash of an array for external use
 * @p: the array or pointer to first element
 * @num: the number of elements to hash
 * @base: the base number to roll into the hash (usually 0)
 *
 * The array of simple integer types pointed to by p is combined with
 * the base to form a 32-bit hash.
 *
 * This hash will have the same results on different machines, so can
 * be used for external hashes (ie. hashes sent across the network or
 * saved to disk).  The results will not change in future versions of
 * this module.
 *
 * Note that it is only legal to hand an array of simple integer types
 * to this hash (ie. char, uint16_t, int64_t, etc).  In these cases,
 * the same values will have the same hash result, even though the
 * memory representations of integers depend on the machine
 * endianness.
 *
 * See also:
 *	hash64_stable
 *
 * Example:
 *	#include <ccan/hash/hash.h>
 *	#include <err.h>
 *	#include <stdio.h>
 *	#include <string.h>
 *
 *	int main(int argc, char *argv[])
 *	{
 *		if (argc != 2)
 *			err(1, "Usage: %s <string-to-hash>", argv[0]);
 *
 *		printf("Hash stable result is %u\n",
 *		       hash_stable(argv[1], strlen(argv[1]), 0));
 *		return 0;
 *	}
 */
#define hash_stable(p, num, base)					\
	(BUILD_ASSERT_OR_ZERO(sizeof(*(p)) == 8 || sizeof(*(p)) == 4	\
			      || sizeof(*(p)) == 2 || sizeof(*(p)) == 1) + \
	 sizeof(*(p)) == 8 ? hash_stable_64((p), (num), (base))		\
	 : sizeof(*(p)) == 4 ? hash_stable_32((p), (num), (base))	\
	 : sizeof(*(p)) == 2 ? hash_stable_16((p), (num), (base))	\
	 : hash_stable_8((p), (num), (base)))

/**
 * hash_u32 - fast hash an array of 32-bit values for internal use
 * @key: the array of uint32_t
 * @num: the number of elements to hash
 * @base: the base number to roll into the hash (usually 0)
 *
 * The array of uint32_t pointed to by @key is combined with the base
 * to form a 32-bit hash.  This is 2-3 times faster than hash() on small
 * arrays, but the advantage vanishes over large hashes.
 *
 * This hash will have different results on different machines, so is
 * only useful for internal hashes (ie. not hashes sent across the
 * network or saved to disk).
 */
uint32_t hash_u32(const uint32_t *key, size_t num, uint32_t base);

/**
 * hash_string - very fast hash of an ascii string
 * @str: the nul-terminated string
 *
 * The string is hashed, using a hash function optimized for ASCII and
 * similar strings.  It's weaker than the other hash functions.
 *
 * This hash may have different results on different machines, so is
 * only useful for internal hashes (ie. not hashes sent across the
 * network or saved to disk).  The results will be different from the
 * other hash functions in this module, too.
 */
static inline uint32_t hash_string(const char *string)
{
	/* This is Karl Nelson <kenelson@ece.ucdavis.edu>'s X31 hash.
	 * It's a little faster than the (much better) lookup3 hash(): 56ns vs
	 * 84ns on my 2GHz Intel Core Duo 2 laptop for a 10 char string. */
	uint32_t ret;

	for (ret = 0; *string; string++)
		ret = (ret << 5) - ret + *string;

	return ret;
}

/**
 * hash64 - fast 64-bit hash of an array for internal use
 * @p: the array or pointer to first element
 * @num: the number of elements to hash
 * @base: the 64-bit base number to roll into the hash (usually 0)
 *
 * The memory region pointed to by p is combined with the base to form
 * a 64-bit hash.
 *
 * This hash will have different results on different machines, so is
 * only useful for internal hashes (ie. not hashes sent across the
 * network or saved to disk).
 *
 * It may also change with future versions: it could even detect at runtime
 * what the fastest hash to use is.
 *
 * See also: hash.
 *
 * Example:
 *	#include <ccan/hash/hash.h>
 *	#include <err.h>
 *	#include <stdio.h>
 *	#include <string.h>
 *
 *	// Simple demonstration: idential strings will have the same hash, but
 *	// two different strings will probably not.
 *	int main(int argc, char *argv[])
 *	{
 *		uint64_t hash1, hash2;
 *
 *		if (argc != 3)
 *			err(1, "Usage: %s <string1> <string2>", argv[0]);
 *
 *		hash1 = hash64(argv[1], strlen(argv[1]), 0);
 *		hash2 = hash64(argv[2], strlen(argv[2]), 0);
 *		printf("Hash is %s\n", hash1 == hash2 ? "same" : "different");
 *		return 0;
 *	}
 */
#define hash64(p, num, base) hash64_any((p), (num)*sizeof(*(p)), (base))

/**
 * hash64_stable - 64 bit hash of an array for external use
 * @p: the array or pointer to first element
 * @num: the number of elements to hash
 * @base: the base number to roll into the hash (usually 0)
 *
 * The array of simple integer types pointed to by p is combined with
 * the base to form a 64-bit hash.
 *
 * This hash will have the same results on different machines, so can
 * be used for external hashes (ie. hashes sent across the network or
 * saved to disk).  The results will not change in future versions of
 * this module.
 *
 * Note that it is only legal to hand an array of simple integer types
 * to this hash (ie. char, uint16_t, int64_t, etc).  In these cases,
 * the same values will have the same hash result, even though the
 * memory representations of integers depend on the machine
 * endianness.
 *
 * See also:
 *	hash_stable
 *
 * Example:
 *	#include <ccan/hash/hash.h>
 *	#include <err.h>
 *	#include <stdio.h>
 *	#include <string.h>
 *
 *	int main(int argc, char *argv[])
 *	{
 *		if (argc != 2)
 *			err(1, "Usage: %s <string-to-hash>", argv[0]);
 *
 *		printf("Hash stable result is %llu\n",
 *		       (long long)hash64_stable(argv[1], strlen(argv[1]), 0));
 *		return 0;
 *	}
 */
#define hash64_stable(p, num, base)					\
	(BUILD_ASSERT_OR_ZERO(sizeof(*(p)) == 8 || sizeof(*(p)) == 4	\
			      || sizeof(*(p)) == 2 || sizeof(*(p)) == 1) + \
	 sizeof(*(p)) == 8 ? hash64_stable_64((p), (num), (base))	\
	 : sizeof(*(p)) == 4 ? hash64_stable_32((p), (num), (base))	\
	 : sizeof(*(p)) == 2 ? hash64_stable_16((p), (num), (base))	\
	 : hash64_stable_8((p), (num), (base)))


/**
 * hashl - fast 32/64-bit hash of an array for internal use
 * @p: the array or pointer to first element
 * @num: the number of elements to hash
 * @base: the base number to roll into the hash (usually 0)
 *
 * This is either hash() or hash64(), on 32/64 bit long machines.
 */
#define hashl(p, num, base)						\
	(BUILD_ASSERT_OR_ZERO(sizeof(long) == sizeof(uint32_t)		\
			      || sizeof(long) == sizeof(uint64_t)) +	\
	(sizeof(long) == sizeof(uint64_t)				\
	 ? hash64((p), (num), (base)) : hash((p), (num), (base))))

/* Our underlying operations. */
uint32_t hash_any(const void *key, size_t length, uint32_t base);
uint32_t hash_stable_64(const void *key, size_t n, uint32_t base);
uint32_t hash_stable_32(const void *key, size_t n, uint32_t base);
uint32_t hash_stable_16(const void *key, size_t n, uint32_t base);
uint32_t hash_stable_8(const void *key, size_t n, uint32_t base);
uint64_t hash64_any(const void *key, size_t length, uint64_t base);
uint64_t hash64_stable_64(const void *key, size_t n, uint64_t base);
uint64_t hash64_stable_32(const void *key, size_t n, uint64_t base);
uint64_t hash64_stable_16(const void *key, size_t n, uint64_t base);
uint64_t hash64_stable_8(const void *key, size_t n, uint64_t base);

/**
 * hash_pointer - hash a pointer for internal use
 * @p: the pointer value to hash
 * @base: the base number to roll into the hash (usually 0)
 *
 * The pointer p (not what p points to!) is combined with the base to form
 * a 32-bit hash.
 *
 * This hash will have different results on different machines, so is
 * only useful for internal hashes (ie. not hashes sent across the
 * network or saved to disk).
 *
 * Example:
 *	#include <ccan/hash/hash.h>
 *
 *	// Code to keep track of memory regions.
 *	struct region {
 *		struct region *chain;
 *		void *start;
 *		unsigned int size;
 *	};
 *	// We keep a simple hash table.
 *	static struct region *region_hash[128];
 *
 *	static void add_region(struct region *r)
 *	{
 *		unsigned int h = hash_pointer(r->start, 0);
 *
 *		r->chain = region_hash[h];
 *		region_hash[h] = r->chain;
 *	}
 *
 *	static struct region *find_region(const void *start)
 *	{
 *		struct region *r;
 *
 *		for (r = region_hash[hash_pointer(start, 0)]; r; r = r->chain)
 *			if (r->start == start)
 *				return r;
 *		return NULL;
 *	}
 */
static inline uint32_t hash_pointer(const void *p, uint32_t base)
{
	if (sizeof(p) % sizeof(uint32_t) == 0) {
		/* This convoluted union is the right way of aliasing. */
		union {
			uint32_t a[sizeof(p) / sizeof(uint32_t)];
			const void *p;
		} u;
		u.p = p;
		return hash_u32(u.a, sizeof(p) / sizeof(uint32_t), base);
	} else
		return hash(&p, 1, base);
}
#endif /* HASH_H */
