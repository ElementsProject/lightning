#include <ccan/crypto/sha256/sha256.h>
/* Include the C files directly. */
#include <ccan/crypto/sha256/sha256.c>
#include <ccan/tap/tap.h>
#include <stdio.h>

/* This is the test introduced for SHA-3, which checks for 33-bit overflow:
   "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmno"
   16777216 times.
*/
static uint32_t expected[] = {
	CPU_TO_BE32(0x50e72a0e), CPU_TO_BE32(0x26442fe2),
	CPU_TO_BE32(0x552dc393), CPU_TO_BE32(0x8ac58658),
	CPU_TO_BE32(0x228c0cbf), CPU_TO_BE32(0xb1d2ca87),
	CPU_TO_BE32(0x2ae43526), CPU_TO_BE32(0x6fcd055e)
};

/* Produced by actually running the code on x86. */
static const struct sha256_ctx after_16M_by_64 = {
#ifdef CCAN_CRYPTO_SHA256_USE_OPENSSL
	{ { LE32_TO_CPU(0x515e3215), LE32_TO_CPU(0x592f4ae0),
	    LE32_TO_CPU(0xd407a8fc), LE32_TO_CPU(0x1fad409b),
	    LE32_TO_CPU(0x51fa46cc), LE32_TO_CPU(0xea528ae5),
	    LE32_TO_CPU(0x5fa58ebb), LE32_TO_CPU(0x8be97931) },
	  0x0, 0x2,
	  { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
	  0x0, 0x20 }
#else
	{ LE32_TO_CPU(0x515e3215), LE32_TO_CPU(0x592f4ae0),
	  LE32_TO_CPU(0xd407a8fc), LE32_TO_CPU(0x1fad409b),
	  LE32_TO_CPU(0x51fa46cc), LE32_TO_CPU(0xea528ae5),
	  LE32_TO_CPU(0x5fa58ebb), LE32_TO_CPU(0x8be97931) },
	1073741824,
	{ .u32 = { 0x64636261, 0x68676665, 0x65646362, 0x69686766,
		   0x66656463, 0x6a696867, 0x67666564, 0x6b6a6968 } }
#endif
};

int main(void)
{
	struct sha256 h;
	struct sha256_ctx ctx;

	/* This is how many tests you plan to run */
	plan_tests(1);

	ctx = after_16M_by_64;
	sha256_done(&ctx, &h);

	ok1(memcmp(&h.u, expected, sizeof(expected)) == 0);

	/* This exits depending on whether all tests passed */
	return exit_status();
}
