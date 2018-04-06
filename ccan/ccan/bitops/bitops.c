/* CC0 license (public domain) - see LICENSE file for details */
#include <ccan/bitops/bitops.h>
#include <stdlib.h>

/* We do naive replacement versions: good for testing, and really your
 * compiler should do better. */
#ifdef BITOPS_NEED_FFS
int bitops_ffs32(uint32_t u)
{
	int i;
	for (i = 0; i < 32; i++)
		if (u & ((uint32_t)1 << i))
			return i + 1;
	return 0;
}

int bitops_ffs64(uint64_t u)
{
	int i;
	for (i = 0; i < 64; i++)
		if (u & ((uint64_t)1 << i))
			return i + 1;
	return 0;
}
#endif

#ifdef BITOPS_NEED_CLZ
int bitops_clz32(uint32_t u)
{
	int i;
	for (i = 0; i < 32; i++)
		if (u & ((uint32_t)1 << (31 - i)))
			return i;
	abort();
}

int bitops_clz64(uint64_t u)
{
	int i;
	for (i = 0; i < 64; i++)
		if (u & ((uint64_t)1 << (63 - i)))
			return i;
	abort();
}
#endif

#ifdef BITOPS_NEED_CTZ
int bitops_ctz32(uint32_t u)
{
	BITOPS_ASSERT_NONZERO(u);
	return bitops_ffs32(u) - 1;
}

int bitops_ctz64(uint64_t u)
{
	BITOPS_ASSERT_NONZERO(u);
	return bitops_ffs64(u) - 1;
}
#endif

#ifdef BITOPS_NEED_WEIGHT
int bitops_weight32(uint32_t u)
{
	int i, num = 0;
	for (i = 0; i < 32; i++)
		if (u & ((uint32_t)1 << i))
			num++;
	return num;
}

int bitops_weight64(uint64_t u)
{
	int i, num = 0;
	for (i = 0; i < 64; i++)
		if (u & ((uint64_t)1 << i))
			num++;
	return num;
}
#endif
