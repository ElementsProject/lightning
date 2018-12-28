#include <ccan/bitops/bitops.c>
#include <ccan/tap/tap.h>

/* Get naive versions */
#ifndef BITOPS_NEED_FFS
#define BITOPS_NEED_FFS
#endif

#ifndef BITOPS_NEED_CLZ
#define BITOPS_NEED_CLZ
#endif

#ifndef BITOPS_NEED_CTZ
#define BITOPS_NEED_CTZ
#endif

#ifndef BITOPS_NEED_WEIGHT
#define BITOPS_NEED_WEIGHT
#endif

int naive_bitops_ffs32(uint32_t u);
int naive_bitops_ffs64(uint64_t u);
int naive_bitops_clz32(uint32_t u);
int naive_bitops_clz64(uint64_t u);
int naive_bitops_ctz32(uint32_t u);
int naive_bitops_ctz64(uint64_t u);
int naive_bitops_weight32(uint32_t u);
int naive_bitops_weight64(uint64_t u);

#define bitops_ffs32 naive_bitops_ffs32
#define bitops_ffs64 naive_bitops_ffs64
#define bitops_clz32 naive_bitops_clz32
#define bitops_clz64 naive_bitops_clz64
#define bitops_ctz32 naive_bitops_ctz32
#define bitops_ctz64 naive_bitops_ctz64
#define bitops_weight32 naive_bitops_weight32
#define bitops_weight64 naive_bitops_weight64
#include <ccan/bitops/bitops.c>

static void test_against_naive32(uint32_t v)
{
	ok1(bitops_ffs32(v) == naive_bitops_ffs32(v));
	ok1(bitops_clz32(v) == naive_bitops_clz32(v));
	ok1(bitops_ctz32(v) == naive_bitops_ctz32(v));
	ok1(bitops_weight32(v) == naive_bitops_weight32(v));
}

static void test_against_naive64(uint64_t v)
{
	ok1(bitops_ffs64(v) == naive_bitops_ffs64(v));
	ok1(bitops_clz64(v) == naive_bitops_clz64(v));
	ok1(bitops_ctz64(v) == naive_bitops_ctz64(v));
	ok1(bitops_weight64(v) == naive_bitops_weight64(v));
}

int main(void)
{
	int i, j;
	uint64_t v;

	/* This is how many tests you plan to run */
	plan_tests(32 * 32 * 8 + (64 * 64) * 8 + 4 + 4);

	/* Various comparisons with any one or two bits set */
	for (i = 0; i < 32; i++) {
		for (j = 0; j < 32; j++) {
			v = ((uint64_t)1 << i) | ((uint64_t)1 << j);
			test_against_naive32(v);
			test_against_naive32(~v);
		}
	}

	for (i = 0; i < 64; i++) {
		for (j = 0; j < 64; j++) {
			v = ((uint64_t)1 << i) | ((uint64_t)1 << j);
			test_against_naive64(v);
			test_against_naive64(~v);
		}
	}

	test_against_naive64(0xFFFFFFFFFFFFFFFFULL);
	ok1(bitops_ffs32(0) == naive_bitops_ffs32(0));
	ok1(bitops_ffs64(0) == naive_bitops_ffs64(0));
	ok1(bitops_weight32(0) == naive_bitops_weight32(0));
	ok1(bitops_weight64(0) == naive_bitops_weight64(0));

	/* This exits depending on whether all tests passed */
	return exit_status();
}
