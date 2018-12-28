/* MIT (BSD) license - see LICENSE file for details */
#include <ccan/crypto/hkdf_sha256/hkdf_sha256.h>
#include <ccan/crypto/hmac_sha256/hmac_sha256.h>
#include <assert.h>
#include <string.h>

void hkdf_sha256(void *okm, size_t okm_size,
		 const void *s, size_t ssize,
		 const void *k, size_t ksize,
		 const void *info, size_t isize)
{
	struct hmac_sha256 prk, t;
	struct hmac_sha256_ctx ctx;
	unsigned char c;

	assert(okm_size < 255 * sizeof(t));

	/* RFC 5869:
	 *
	 * 2.2.  Step 1: Extract
	 *
	 *   HKDF-Extract(salt, IKM) -> PRK
	 *
	 *    Options:
	 *       Hash     a hash function; HashLen denotes the length of the
	 *                hash function output in octets
	 *
	 *    Inputs:
	 *       salt     optional salt value (a non-secret random value);
	 *                if not provided, it is set to a string of HashLen zeros.
	 *       IKM      input keying material
	 *
	 *    Output:
	 *       PRK      a pseudorandom key (of HashLen octets)
	 *
	 *    The output PRK is calculated as follows:
	 *
	 *    PRK = HMAC-Hash(salt, IKM)
	 */
	hmac_sha256(&prk, s, ssize, k, ksize);

	/*
	 * 2.3.  Step 2: Expand
	 *
	 *    HKDF-Expand(PRK, info, L) -> OKM
	 *
	 *    Options:
	 *       Hash     a hash function; HashLen denotes the length of the
	 *                hash function output in octets
	 *
	 *    Inputs:
	 *       PRK      a pseudorandom key of at least HashLen octets
	 *                (usually, the output from the extract step)
	 *       info     optional context and application specific information
	 *                (can be a zero-length string)
	 *       L        length of output keying material in octets
	 *                (<= 255*HashLen)
	 *
	 *    Output:
	 *       OKM      output keying material (of L octets)
	 *
	 *    The output OKM is calculated as follows:
	 *
	 *    N = ceil(L/HashLen)
	 *    T = T(1) | T(2) | T(3) | ... | T(N)
	 *    OKM = first L octets of T
	 *
	 *    where:
	 *    T(0) = empty string (zero length)
	 *    T(1) = HMAC-Hash(PRK, T(0) | info | 0x01)
	 *    T(2) = HMAC-Hash(PRK, T(1) | info | 0x02)
	 *    T(3) = HMAC-Hash(PRK, T(2) | info | 0x03)
	 *    ...
	 *
	 *    (where the constant concatenated to the end of each T(n) is a
	 *    single octet.)
	 */
	c = 1;
	hmac_sha256_init(&ctx, &prk, sizeof(prk));
	hmac_sha256_update(&ctx, info, isize);
	hmac_sha256_update(&ctx, &c, 1);
	hmac_sha256_done(&ctx, &t);

	while (okm_size > sizeof(t)) {
		memcpy(okm, &t, sizeof(t));
		okm = (char *)okm + sizeof(t);
		okm_size -= sizeof(t);

		c++;
		hmac_sha256_init(&ctx, &prk, sizeof(prk));
		hmac_sha256_update(&ctx, &t, sizeof(t));
		hmac_sha256_update(&ctx, info, isize);
		hmac_sha256_update(&ctx, &c, 1);
		hmac_sha256_done(&ctx, &t);
	}
	memcpy(okm, &t, okm_size);
}
