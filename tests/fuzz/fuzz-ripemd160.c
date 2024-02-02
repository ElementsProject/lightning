/* This is a differential fuzz test comparing the output from CCAN's ripemd160
 * implementation against OpenSSL's.
 */
#include "config.h"
#include <assert.h>
#include <ccan/crypto/ripemd160/ripemd160.h>
#include <ccan/mem/mem.h>
#include <openssl/evp.h>
#include <openssl/provider.h>
#include <openssl/ripemd.h>
#include <tests/fuzz/libfuzz.h>

static EVP_MD *ripemd160_algo;

/* Some versions of OpenSSL removed ripemd160 from the default provider. Check
 * and load the legacy provider if necessary. */
void init(int *argc, char ***argv)
{
	const char data[] = "hash test data";
	u8 openssl_hash[RIPEMD160_DIGEST_LENGTH];
	unsigned hash_size;

	ripemd160_algo = EVP_MD_fetch(NULL, "RIPEMD-160", NULL);
	if (!ripemd160_algo) {
		OSSL_PROVIDER_load(NULL, "legacy");
		ripemd160_algo = EVP_MD_fetch(NULL, "RIPEMD-160", NULL);
		assert(ripemd160_algo);
	}

	assert(EVP_Digest(data, sizeof(data), openssl_hash, &hash_size,
			  ripemd160_algo, NULL));
	assert(hash_size == RIPEMD160_DIGEST_LENGTH);
}

/* Test that splitting the data and hashing via multiple updates yields the same
 * result as not splitting the data. */
static void test_split_update(int num_splits, const struct ripemd160 *expected,
			      const u8 *data, size_t size)
{
	const size_t split_size = size / (num_splits + 1);
	struct ripemd160_ctx ctx = RIPEMD160_INIT;
	struct ripemd160 actual;

	for (int i = 0; i < num_splits; ++i) {
		ripemd160_update(&ctx, data, split_size);
		data += split_size;
		size -= split_size;
	}
	ripemd160_update(&ctx, data, size); /* Hash remaining data. */

	ripemd160_done(&ctx, &actual);
	assert(memeq(expected, sizeof(*expected), &actual, sizeof(actual)));
}

/* Test that the hash calculated by CCAN matches OpenSSL's hash. */
static void test_vs_openssl(const struct ripemd160 *expected, const u8 *data,
			    size_t size)
{
	u8 openssl_hash[RIPEMD160_DIGEST_LENGTH];
	unsigned hash_size;

	assert(EVP_Digest(data, size, openssl_hash, &hash_size, ripemd160_algo,
			  NULL));
	assert(hash_size == RIPEMD160_DIGEST_LENGTH);
	assert(memeq(expected, sizeof(*expected), openssl_hash,
		     sizeof(openssl_hash)));
}

void run(const u8 *data, size_t size)
{
	struct ripemd160 expected;
	u8 num_splits;

	if (size < 1)
		return;

	num_splits = *data;
	++data;
	--size;

	ripemd160(&expected, data, size);

	test_split_update(num_splits, &expected, data, size);
	test_vs_openssl(&expected, data, size);
}
