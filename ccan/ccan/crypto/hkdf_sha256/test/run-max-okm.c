/* Auditor-added regression test (temporary, 2026-08-05 audit).
 *
 * RFC 5869 section 2.3 permits L <= 255*HashLen = 8160 octets of OKM,
 * but hkdf_sha256.c asserts okm_size < 255*32, rejecting the maximal
 * legal L = 8160 (the implementation computes it correctly: the round
 * counter reaches exactly 255).  This test aborts on the assert against
 * the current code and must pass once the bound is corrected to <=.
 *
 * Expected values: RFC5869 Appendix A Test Case 1 parameters; the
 * 8160-octet OKM was produced by an independent Python hmac/hashlib
 * HKDF-SHA256 implementation.  Its first 42 octets necessarily equal
 * the RFC's Test Case 1 OKM (HKDF-Expand is prefix-closed); the final
 * 32 octets are T(255) = HMAC(PRK, T(254) | info | 0xff), proving the
 * counter reached 255 without wrapping.
 */
#include <ccan/crypto/hkdf_sha256/hkdf_sha256.c>
#include <ccan/tap/tap.h>
#include <ccan/str/hex/hex.h>
#include <string.h>
#include <unistd.h>

static unsigned char okm[255 * 32];

int main(void)
{
	unsigned char ikm[22], salt[13], info[10];
	unsigned char expect[42];
	size_t i;

	alarm(10);
	plan_tests(2);

	for (i = 0; i < sizeof(ikm); i++)
		ikm[i] = 0x0b;
	for (i = 0; i < sizeof(salt); i++)
		salt[i] = i;
	for (i = 0; i < sizeof(info); i++)
		info[i] = 0xf0 + i;

	/* L = 8160 = 255*HashLen: the largest L RFC 5869 allows. */
	hkdf_sha256(okm, sizeof(okm), salt, sizeof(salt), ikm, sizeof(ikm),
		    info, sizeof(info));

	/* Prefix equals RFC5869 Test Case 1 OKM (42 octets). */
	hex_decode("3cb25f25faacd57a90434f64d0362f2a"
		   "2d2d0a90cf1a5a4c5db02d56ecc4c5bf"
		   "34007208d5b887185865", 84, expect, sizeof(expect));
	ok1(memcmp(okm, expect, sizeof(expect)) == 0);

	/* Final block is T(255) per independent reference. */
	hex_decode("76a3f78bcffe95fecf91923c22ad6ee6"
		   "4d48a6d1b981d7e523d5c0f22154ee88", 64,
		   expect, 32);
	ok1(memcmp(okm + sizeof(okm) - 32, expect, 32) == 0);

	return exit_status();
}
