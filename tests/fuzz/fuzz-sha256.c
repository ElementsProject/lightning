/* This is a differential fuzz test comparing the output from CCAN's sha256
 * implementation against OpenSSL's.
 */
#include "config.h"
#include <assert.h>
#include <ccan/crypto/sha256/sha256.h>
#include <ccan/mem/mem.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <tests/fuzz/libfuzz.h>

static EVP_MD *sha256_algo;

void init(int *argc, char ***argv)
{
	sha256_algo = EVP_MD_fetch(NULL, "SHA-256", NULL);
	assert(sha256_algo);
}

/* Test that splitting the data and hashing via multiple updates yields the same
 * result as not splitting the data. */
static void test_split_update(int num_splits, const struct sha256 *expected,
			      const u8 *data, size_t size)
{
	const size_t split_size = size / (num_splits + 1);
	struct sha256_ctx ctx = SHA256_INIT;
	struct sha256 actual;

	for (int i = 0; i < num_splits; ++i) {
		sha256_update(&ctx, data, split_size);
		data += split_size;
		size -= split_size;
	}
	sha256_update(&ctx, data, size); /* Hash remaining data. */

	sha256_done(&ctx, &actual);
	assert(memeq(expected, sizeof(*expected), &actual, sizeof(actual)));
}

/* Test that the hash calculated by CCAN matches OpenSSL's hash. */
static void test_vs_openssl(const struct sha256 *expected, const u8 *data,
			    size_t size)
{
	u8 openssl_hash[SHA256_DIGEST_LENGTH];
	unsigned hash_size;

	assert(EVP_Digest(data, size, openssl_hash, &hash_size, sha256_algo,
			  NULL));
	assert(hash_size == SHA256_DIGEST_LENGTH);
	assert(memeq(expected, sizeof(*expected), openssl_hash,
		     sizeof(openssl_hash)));
}

void run(const u8 *data, size_t size)
{
	struct sha256 expected;
	u8 num_splits;

	if (size < 1)
		return;

	num_splits = *data;
	++data;
	--size;

	sha256(&expected, data, size);

	test_split_update(num_splits, &expected, data, size);
	test_vs_openssl(&expected, data, size);
}
