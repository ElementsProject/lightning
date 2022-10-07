#include <ccan/crypto/sha256/sha256.h>
/* Include the C files directly. */
#include <ccan/crypto/sha256/sha256.c>
#include <ccan/tap/tap.h>

static unsigned char arr[] = {
	0x12,
#if HAVE_BIG_ENDIAN
	/* u16 */
	0x12, 0x34,
	/* u32 */
	0x12, 0x34, 0x56, 0x78,
	/* u64 */
	0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0,
#else
	/* u16 */
	0x34, 0x12,
	/* u32 */
	0x78, 0x56, 0x34, 0x12,
	/* u64 */
	0xf0, 0xde, 0xbc, 0x9a, 0x78, 0x56, 0x34, 0x12,
#endif
	/* le16 */
	0x34, 0x12,
	/* le32 */
	0x78, 0x56, 0x34, 0x12,
	/* le64 */
	0xf0, 0xde, 0xbc, 0x9a, 0x78, 0x56, 0x34, 0x12,
	/* be16 */
	0x12, 0x34,
	/* be32 */
	0x12, 0x34, 0x56, 0x78,
	/* be64 */
	0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0
};

int main(void)
{
	struct sha256 h, expected;
	struct sha256_ctx ctx;

	/* This is how many tests you plan to run */
	plan_tests(1);

	sha256_init(&ctx);
	sha256_u8(&ctx, 0x12);
	sha256_u16(&ctx, 0x1234);
	sha256_u32(&ctx, 0x12345678);
	sha256_u64(&ctx, 0x123456789abcdef0ULL);
	sha256_le16(&ctx, 0x1234);
	sha256_le32(&ctx, 0x12345678);
	sha256_le64(&ctx, 0x123456789abcdef0ULL);
	sha256_be16(&ctx, 0x1234);
	sha256_be32(&ctx, 0x12345678);
	sha256_be64(&ctx, 0x123456789abcdef0ULL);
	sha256_done(&ctx, &h);

	sha256(&expected, arr, sizeof(arr));
	ok1(memcmp(&h, &expected, sizeof(h)) == 0);

	/* This exits depending on whether all tests passed */
	return exit_status();
}
