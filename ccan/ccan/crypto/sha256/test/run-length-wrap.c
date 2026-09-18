#include <ccan/crypto/sha256/sha256.h>
/* Include the C files directly. */
#include <ccan/crypto/sha256/sha256.c>
#include <ccan/tap/tap.h>
#include <string.h>
#include <unistd.h>

/* Regression test for the 32-bit length-counter wrap (audit F2):
 * struct sha256_ctx.bytes is a size_t.  On ILP32 platforms it wraps
 * after 2^32 bytes hashed, so sha256_done() emits a length field of
 * (wrapped bytes) << 3 instead of the true bit count, and every
 * message of 4 GiB or more gets a wrong digest (2^32 bytes is 2^35
 * bits, well inside SHA-256's 2^64-bit limit).
 *
 * Seeding a raw context like run-33-bit-test.c does: set bytes to
 * 2^32 - 64, then update with 64 known bytes.  A correct 64-bit
 * counter yields the length field 2^35 and the digest below
 * (independently reproduced with a reference SHA-256 implementation
 * using an injected length field); a wrapped 32-bit size_t counter
 * yields a length field of 0 and a different digest.
 *
 * Passes on LP64 today, fails on ILP32 (-m32) today; must pass
 * everywhere after the repair. */
static const unsigned char expected[32] = {
	0xfc, 0x48, 0x52, 0x1c, 0x03, 0xa8, 0xd0, 0x5c,
	0xfb, 0x68, 0x4c, 0x07, 0x7e, 0xf7, 0x7b, 0x6a,
	0x14, 0x56, 0x65, 0x4b, 0x75, 0xe3, 0xe5, 0x1c,
	0x1e, 0x9d, 0xe6, 0x84, 0x84, 0xf9, 0x4c, 0x87
};

int main(void)
{
	struct sha256_ctx ctx = SHA256_INIT;
	struct sha256 h;
	unsigned char block[64];
	unsigned i;

	alarm(10);
	plan_tests(1);

	for (i = 0; i < sizeof(block); i++)
		block[i] = (unsigned char)(i * 3 + 1);

	/* == 2^32 - 64, representable in both ILP32 and LP64 size_t. */
	ctx.bytes = (size_t)0xFFFFFFC0ULL;
	sha256_update(&ctx, block, sizeof(block));
	sha256_done(&ctx, &h);

	ok1(memcmp(h.u.u8, expected, sizeof(expected)) == 0);

	return exit_status();
}
