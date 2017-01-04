/* From RFC5869 Appendix A
 *
 * https://tools.ietf.org/html/rfc5869
 */
#include <ccan/crypto/hkdf_sha256/hkdf_sha256.h>
#include <ccan/tap/tap.h>
#include <ccan/str/hex/hex.h>
#include <string.h>
#include <assert.h>

struct test {
	const char *ikm, *salt, *info, *okm;
};

static struct test tests[] = { {
	/* Test Case 1
	   Basic test case with SHA-256
	*/
	"0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b", /* (22 octets) */
	"000102030405060708090a0b0c", /* (13 octets) */
	"f0f1f2f3f4f5f6f7f8f9", /* (10 octets) */
	"3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865", /* (42 octets) */
	},
	{
	/* Test Case 2
	 *
	 * Test with SHA-256 and longer inputs/outputs */
	"000102030405060708090a0b0c0d0e0f"
	"101112131415161718191a1b1c1d1e1f"
	"202122232425262728292a2b2c2d2e2f"
	"303132333435363738393a3b3c3d3e3f"
	"404142434445464748494a4b4c4d4e4f", /* (80 octets) */
	"606162636465666768696a6b6c6d6e6f"
	"707172737475767778797a7b7c7d7e7f"
	"808182838485868788898a8b8c8d8e8f"
	"909192939495969798999a9b9c9d9e9f"
	"a0a1a2a3a4a5a6a7a8a9aaabacadaeaf", /* (80 octets )*/
	"b0b1b2b3b4b5b6b7b8b9babbbcbdbebf"
	"c0c1c2c3c4c5c6c7c8c9cacbcccdcecf"
	"d0d1d2d3d4d5d6d7d8d9dadbdcdddedf"
	"e0e1e2e3e4e5e6e7e8e9eaebecedeeef"
	"f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff", /* (80 octets) */
	"b11e398dc80327a1c8e7f78c596a4934"
	"4f012eda2d4efad8a050cc4c19afa97c"
	"59045a99cac7827271cb41c65e590e09"
	"da3275600c2f09b8367793a9aca3db71"
	"cc30c58179ec3e87c14c01d5c1f3434f"
	"1d87" /* (82 octets) */
	},
	{
	/*  Test Case 3
	 *
	 * Test with SHA-256 and zero-length salt/info
	 */
	"0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b", /* (22 octets) */
	"", /* (0 octets) */
	"", /* (0 octets) */
	"8da4e775a563c18f715f802a063c5a31"
	"b8a11f5c5ee1879ec3454e5f3c738d2d"
	"9d201395faa4b61a96c8" /* (42 octets) */
	}
};

static void *fromhex(const char *str, size_t *len)
{
	void *p;

	*len = hex_data_size(strlen(str));
	p = malloc(*len);
	if (!hex_decode(str, strlen(str), p, *len))
		abort();
	return p;
}

int main(void)
{
	size_t i;

	plan_tests(sizeof(tests) / sizeof(tests[0]));

	for (i = 0; i < sizeof(tests) / sizeof(tests[0]); i++) {
		size_t ksize, ssize, isize, okmsize;
		void *k, *s, *info, *expect, *okm;

		k = fromhex(tests[i].ikm, &ksize);
		s = fromhex(tests[i].salt, &ssize);
		info = fromhex(tests[i].info, &isize);
		expect = fromhex(tests[i].okm, &okmsize);
		okm = malloc(okmsize);
		hkdf_sha256(okm, okmsize, s, ssize, k, ksize, info, isize);
		ok1(memcmp(okm, expect, okmsize) == 0);

		free(k);
		free(s);
		free(info);
		free(expect);
		free(okm);
	}

	return exit_status();
}
