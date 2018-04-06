/* CC0 license (public domain) - see LICENSE file for details */
#ifndef CCAN_BITOPS_H
#define CCAN_BITOPS_H
#include "config.h"
#include <stdint.h>

#if defined(CCAN_DEBUG) || defined(CCAN_BITOPS_DEBUG)
#include <assert.h>
#define BITOPS_ASSERT_NONZERO(u) assert((u) != 0)
#else
#define BITOPS_ASSERT_NONZERO(u)
#endif

#if HAVE_BUILTIN_FFS && HAVE_BUILTIN_FFSL && HAVE_BUILTIN_FFSLL
/**
 * bitops_ffs32: find first set bit in a uint32_t
 *
 * Returns 1 for least signficant bit, 32 for most significant bit, 0
 * for no bits set.
 */
static inline int bitops_ffs32(uint32_t u)
{
	return __builtin_ffs(u);
}

/**
 * bitops_ffs64: find lowest set bit in a uint64_t
 *
 * Returns 1 for least signficant bit, 32 for most significant bit, 0
 * for no bits set.
 */
static inline int bitops_ffs64(uint64_t u)
{
	if (sizeof(u) == sizeof(long))
		return __builtin_ffsl(u);
	else
		return __builtin_ffsll(u);
}
#else
int bitops_ffs32(uint32_t u);
int bitops_ffs64(uint64_t u);
#define BITOPS_NEED_FFS 1
#endif

#if HAVE_BUILTIN_CLZ && HAVE_BUILTIN_CLZL && HAVE_BUILTIN_CLZLL
/**
 * bitops_clz32: count leading zeros in a uint32_t (must not be 0)
 *
 * Returns 0 if most signficant bit is set, 31 if only least
 * signficant bit is set.
 */
static inline int bitops_clz32(uint32_t u)
{
	BITOPS_ASSERT_NONZERO(u);
	return __builtin_clz(u);
}

/**
 * bitops_clz64: count leading zeros in a uint64_t (must not be 0)
 *
 * Returns 0 if most signficant bit is set, 63 if only least
 * signficant bit is set.
 */
static inline int bitops_clz64(uint64_t u)
{
	BITOPS_ASSERT_NONZERO(u);
	if (sizeof(u) == sizeof(long))
		return __builtin_clzl(u);
	else
		return __builtin_clzll(u);
}
#else
int bitops_clz32(uint32_t u);
int bitops_clz64(uint64_t u);
#define BITOPS_NEED_CLZ 1
#endif

#if HAVE_BUILTIN_CTZ && HAVE_BUILTIN_CTZL && HAVE_BUILTIN_CTZLL
/**
 * bitops_ctz32: count trailing zeros in a uint32_t (must not be 0)
 *
 * Returns 0 if least signficant bit is set, 31 if only most
 * signficant bit is set.
 */
static inline int bitops_ctz32(uint32_t u)
{
	BITOPS_ASSERT_NONZERO(u);
	return __builtin_ctz(u);
}

/**
 * bitops_ctz64: count trailing zeros in a uint64_t (must not be 0)
 *
 * Returns 0 if least signficant bit is set, 63 if only most
 * signficant bit is set.
 */
static inline int bitops_ctz64(uint64_t u)
{
	BITOPS_ASSERT_NONZERO(u);
	if (sizeof(u) == sizeof(long))
		return __builtin_ctzl(u);
	else
		return __builtin_ctzll(u);
}
#else
int bitops_ctz32(uint32_t u);
int bitops_ctz64(uint64_t u);
#define BITOPS_NEED_CTZ 1
#endif

/**
 * bitops_ls32: find lowest set bit in a uint32_t (must not be zero)
 *
 * Returns 0 for least signficant bit, 31 for most significant bit.
 */
static inline int bitops_ls32(uint32_t u)
{
	BITOPS_ASSERT_NONZERO(u);
	return bitops_ffs32(u) - 1;
}

/**
 * bitops_ls64: find lowest set bit in a uint64_t (must not be zero)
 *
 * Returns 0 for least signficant bit, 63 for most significant bit.
 */
static inline int bitops_ls64(uint64_t u)
{
	BITOPS_ASSERT_NONZERO(u);
	return bitops_ffs64(u) - 1;
}

/**
 * bitops_hs32: find highest set bit in a uint32_t (must not be zero)
 *
 * Returns 0 for least signficant bit, 31 for most significant bit.
 */
static inline int bitops_hs32(uint32_t u)
{
	BITOPS_ASSERT_NONZERO(u);
	return 31 - bitops_clz32(u);
}

/**
 * bitops_hs64: find highest set bit in a uint64_t (must not be zero)
 *
 * Returns 0 for least signficant bit, 63 for most significant bit.
 */
static inline int bitops_hs64(uint64_t u)
{
	BITOPS_ASSERT_NONZERO(u);
	return 63 - bitops_clz64(u);
}

/**
 * bitops_lc32: find lowest clear bit in a uint32_t (must not be 0xFFFFFFFF)
 *
 * Returns 0 for least signficant bit, 31 for most significant bit.
 */
static inline int bitops_lc32(uint32_t u)
{
	return bitops_ctz32(~u);
}

/**
 * bitops_lc64: find lowest clear bit in a uint64_t (must not be 0xFFFFFFFFFFFFFFFF)
 *
 * Returns 0 for least signficant bit, 63 for most significant bit.
 */
static inline int bitops_lc64(uint64_t u)
{
	return bitops_ctz64(~u);
}

/**
 * bitops_hc32: find highest clear bit in a uint32_t (must not be 0xFFFFFFFF)
 *
 * Returns 0 for least signficant bit, 31 for most significant bit.
 */
static inline int bitops_hc32(uint32_t u)
{
	return 31 - bitops_clz32(~u);
}

/**
 * bitops_hc64: find highest clear bit in a uint64_t (must not be 0xFFFFFFFFFFFFFFFF)
 *
 * Returns 0 for least signficant bit, 63 for most significant bit.
 */
static inline int bitops_hc64(uint64_t u)
{
	return 63 - bitops_clz64(~u);
}

#if HAVE_BUILTIN_POPCOUNT && HAVE_BUILTIN_POPCOUNTL && HAVE_BUILTIN_POPCOUNTLL
/**
 * bitops_weight32: count number of bits set in a uint32_t
 *
 * Returns 0 to 32.
 */
static inline int bitops_weight32(uint32_t u)
{
	return __builtin_popcount(u);
}

/**
 * bitops_weight64: count number of bits set in a uint64_t
 *
 * Returns 0 to 64.
 */
static inline int bitops_weight64(uint64_t u)
{
	if (sizeof(u) == sizeof(long))
		return __builtin_popcountl(u);
	else
		return __builtin_popcountll(u);
}
#else
int bitops_weight32(uint32_t u);
int bitops_weight64(uint64_t u);
#define BITOPS_NEED_WEIGHT 1
#endif
#endif /* CCAN_BITOPS_H */
