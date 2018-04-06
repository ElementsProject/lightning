#define CCAN_BITOPS_DEBUG 1
#include <ccan/bitops/bitops.c>
#include <ccan/tap/tap.h>

int main(void)
{
	int i;

	/* This is how many tests you plan to run */
	plan_tests(68 + 6 * (31 + 63));

	for (i = 0; i < 32; i++)
		ok1(bitops_ffs32(1 << i) == i+1);
	ok1(bitops_ffs32(0) == 0);
	for (i = 0; i < 64; i++)
		ok1(bitops_ffs64((uint64_t)1 << i) == i+1);
	ok1(bitops_ffs64(0) == 0);

	/* Higher bits don't affect result */
	for (i = 0; i < 32; i++)
		ok1(bitops_ffs32(0xFFFFFFFFFFFFFFFFULL << i) == i+1);
	ok1(bitops_ffs32(0) == 0);
	for (i = 0; i < 64; i++)
		ok1(bitops_ffs64(0xFFFFFFFFFFFFFFFFULL << i) == i+1);
	ok1(bitops_ffs64(0) == 0);

	for (i = 0; i < 32; i++)
		ok1(bitops_clz32(1 << i) == 31 - i);
	for (i = 0; i < 64; i++)
		ok1(bitops_clz64((uint64_t)1 << i) == 63 - i);

	/* Lower bits don't effect results */
	for (i = 0; i < 32; i++)
		ok1(bitops_clz32((1 << i) + (1 << i)-1) == 31 - i);
	for (i = 0; i < 64; i++)
		ok1(bitops_clz64(((uint64_t)1 << i) + ((uint64_t)1 << i)-1)
		    == 63 - i);

	for (i = 0; i < 32; i++)
		ok1(bitops_ctz32(1 << i) == i);
	for (i = 0; i < 64; i++)
		ok1(bitops_ctz64((uint64_t)1 << i) == i);

	/* Higher bits don't affect result */
	for (i = 0; i < 32; i++)
		ok1(bitops_ctz32(0xFFFFFFFFFFFFFFFFULL << i) == i);
	for (i = 0; i < 64; i++)
		ok1(bitops_ctz64(0xFFFFFFFFFFFFFFFFULL << i) == i);

	/* Now we've tested low-level, test higher ones */
	ok1(bitops_ls32(1U) == 0);
	ok1(bitops_ls32(0xFFFFFFFF) == 0);
	ok1(bitops_ls32(1U << 31) == 31);
	ok1(bitops_ls32(0xFFFF0000) == 16);

	ok1(bitops_ls64(1U) == 0);
	ok1(bitops_ls64(0xFFFFFFFF) == 0);
	ok1(bitops_ls64(1U << 31) == 31);
	ok1(bitops_ls64(0xFFFF0000) == 16);
	ok1(bitops_ls64((uint64_t)1 << 32) == 32);
	ok1(bitops_ls64((uint64_t)1 << 63) == 63);
	ok1(bitops_ls64(0xFFFFFFFFFFFF0000ULL) == 16);
	ok1(bitops_ls64(0xFFFF000000000000ULL) == 48);

	ok1(bitops_hs32(1U) == 0);
	ok1(bitops_hs32(0xFFFFFFFF) == 31);
	ok1(bitops_hs32(1U << 31) == 31);
	ok1(bitops_hs32(0xFFFF0000) == 31);
	ok1(bitops_hs32(0x0000FFFF) == 15);

	ok1(bitops_hs64(1U) == 0);
	ok1(bitops_hs64(0xFFFFFFFF) == 31);
	ok1(bitops_hs64(1U << 31) == 31);
	ok1(bitops_hs64(0xFFFF0000) == 31);
	ok1(bitops_hs32(0x0000FFFF) == 15);
	ok1(bitops_hs64((uint64_t)1 << 32) == 32);
	ok1(bitops_hs64((uint64_t)1 << 63) == 63);
	ok1(bitops_hs64(0xFFFFFFFFFFFF0000ULL) == 63);
	ok1(bitops_hs64(0x0000FFFF00000000ULL) == 47);

	ok1(bitops_lc32(~(1U)) == 0);
	ok1(bitops_lc32(~(0xFFFFFFFF)) == 0);
	ok1(bitops_lc32(~(1U << 31)) == 31);
	ok1(bitops_lc32(~(0xFFFF0000)) == 16);

	ok1(bitops_lc64(~(1U)) == 0);
	ok1(bitops_lc64(~(0xFFFFFFFF)) == 0);
	ok1(bitops_lc64(~(1U << 31)) == 31);
	ok1(bitops_lc64(~(0xFFFF0000)) == 16);
	ok1(bitops_lc64(~((uint64_t)1 << 32)) == 32);
	ok1(bitops_lc64(~((uint64_t)1 << 63)) == 63);
	ok1(bitops_lc64(~(0xFFFFFFFFFFFF0000ULL)) == 16);
	ok1(bitops_lc64(~(0xFFFF000000000000ULL)) == 48);

	ok1(bitops_hc32(~(1U)) == 0);
	ok1(bitops_hc32(~(0xFFFFFFFF)) == 31);
	ok1(bitops_hc32(~(1U << 31)) == 31);
	ok1(bitops_hc32(~(0xFFFF0000)) == 31);
	ok1(bitops_hc32(~(0x0000FFFF)) == 15);

	ok1(bitops_hc64(~(1ULL)) == 0);
	ok1(bitops_hc64(~(0xFFFFFFFFULL)) == 31);
	ok1(bitops_hc64(~(1ULL << 31)) == 31);
	ok1(bitops_hc64(~(0xFFFF0000ULL)) == 31);
	ok1(bitops_hc64(~(0x0000FFFFULL)) == 15);
	ok1(bitops_hc64(~((uint64_t)1 << 32)) == 32);
	ok1(bitops_hc64(~((uint64_t)1 << 63)) == 63);
	ok1(bitops_hc64(~(0xFFFFFFFFFFFF0000ULL)) == 63);
	ok1(bitops_hc64(~(0x0000FFFF00000000ULL)) == 47);

	/* This exits depending on whether all tests passed */
	return exit_status();
}
