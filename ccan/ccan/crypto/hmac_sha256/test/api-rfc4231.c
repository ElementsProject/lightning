/* From RFC4231 "Identifiers and Test Vectors for HMAC-SHA-224, HMAC-SHA-256,
 * HMAC-SHA-384, and HMAC-SHA-512"
 *
 * https://tools.ietf.org/html/rfc4231
 */
#include <ccan/crypto/hmac_sha256/hmac_sha256.h>
#include <ccan/tap/tap.h>
#include <ccan/str/hex/hex.h>
#include <string.h>
#include <assert.h>

struct test {
	const char *key, *data, *hmac;
};

static struct test tests[] = { {
	/* Test Case 1 */
	"0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",	/* (20 bytes) */
	"4869205468657265",				/* ("Hi There") */
	"b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
	},
	/* Test Case 2:
	   Test with a key shorter than the length of the HMAC output. */
	{
	"4a656665",				/* ("Jefe") */
	/*  ("what do ya want for nothing?") */
	"7768617420646f2079612077616e7420666f72206e6f7468696e673f",
	"5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
	},
	{
        /* Test Case 3

	   Test with a combined length of key and data that is larger than 64
	   bytes (= block-size of SHA-224 and SHA-256).
	*/
	"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", /* (20 bytes) */
	"dddddddddddddddddddddddddddddddd"
	"dddddddddddddddddddddddddddddddd"
	"dddddddddddddddddddddddddddddddd"
	"dddd", /* (50 bytes) */
	"773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe"
	},
	{
	/* Test Case 4

	   Test with a combined length of key and data that is larger than 64
	   bytes (= block-size of SHA-224 and SHA-256).
	*/
	"0102030405060708090a0b0c0d0e0f10111213141516171819", /* (25 bytes) */
	"cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd"
	"cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd"
	"cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd"
	"cdcd", /* (50 bytes) */
	"82558a389a443c0ea4cc819899f2083a85f0faa3e578f8077a2e3ff46729665b"
	},
#if 0
	{
	/* Test Case 5

	   Test with a truncation of output to 128 bits.
	*/
	"0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c", /* (20 bytes) */
	"546573742057697468205472756e636174696f6e", /* ("Test With Truncation") */
	"a3b6167473100ee06e0c796c2955552b"
	},
#endif
	{
	/* Test Case 6

	   Test with a key larger than 128 bytes (= block-size of SHA-384 and
	   SHA-512).
	*/
	"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	"aaaaaa", /* (131 bytes) */
	"54657374205573696e67204c61726765"  /* ("Test Using Large") */
	"72205468616e20426c6f636b2d53697a"  /* ("r Than Block-Siz") */
	"65204b6579202d2048617368204b6579"  /* ("e Key - Hash Key") */
	"204669727374",                     /* (" First") */
	"60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54"
	},
	{
	/* Test Case 7

	   Test with a key and data that is larger than 128 bytes (= block-size
	   of SHA-384 and SHA-512). */
	"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	"aaaaaa", /* (131 bytes) */
	"54686973206973206120746573742075" /* ("This is a test u") */
	"73696e672061206c6172676572207468" /* ("sing a larger th") */
	"616e20626c6f636b2d73697a65206b65" /* ("an block-size ke") */
	"7920616e642061206c61726765722074" /* ("y and a larger t") */
	"68616e20626c6f636b2d73697a652064" /* ("han block-size d") */
	"6174612e20546865206b6579206e6565" /* ("ata. The key nee") */
	"647320746f2062652068617368656420" /* ("ds to be hashed ") */
	"6265666f7265206265696e6720757365" /* ("before being use") */
	"642062792074686520484d414320616c" /* ("d by the HMAC al") */
	"676f726974686d2e", /*                 ("gorithm.") */
	"9b09ffa71b942fcb27635fbcd5b0e944bfdc63644f0713938a7f51535c3a35e2"
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
	struct hmac_sha256 hmac;

	plan_tests(sizeof(tests) / sizeof(tests[0]) * 2);

	for (i = 0; i < sizeof(tests) / sizeof(tests[0]); i++) {
		size_t ksize, dsize, hmacsize;
		void *k, *d, *expect;
		struct hmac_sha256_ctx ctx;

		k = fromhex(tests[i].key, &ksize);
		d = fromhex(tests[i].data, &dsize);
		expect = fromhex(tests[i].hmac, &hmacsize);
		assert(hmacsize == sizeof(hmac));
		hmac_sha256(&hmac, k, ksize, d, dsize);
		ok1(memcmp(&hmac, expect, hmacsize) == 0);

		/* Now test partial API. */
		hmac_sha256_init(&ctx, k, ksize);
		hmac_sha256_update(&ctx, d, dsize / 2);
		hmac_sha256_update(&ctx, (char *)d + dsize/2, dsize - dsize/2);
		hmac_sha256_done(&ctx, &hmac);
		ok1(memcmp(&hmac, expect, hmacsize) == 0);

		free(k);
		free(d);
		free(expect);
	}

	return exit_status();
}
