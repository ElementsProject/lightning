/* This is a differential fuzz test comparing CCAN's HMAC‑SHA256 implementation
 * against OpenSSL's HMAC.
 */
#include "config.h"
#include <assert.h>
#include <ccan/crypto/hmac_sha256/hmac_sha256.h>
#include <ccan/mem/mem.h>
#include <openssl/hmac.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <tests/fuzz/libfuzz.h>

static unsigned char *hmac_key;
static size_t hmac_key_len;

static EVP_MAC *hmac_sha256_algo;

void init(int *argc, char ***argv)
{
	hmac_sha256_algo = EVP_MAC_fetch(NULL, "HMAC", NULL);
	assert(hmac_sha256_algo);
}

/* Test that splitting the data and updating via multiple calls yields the same
 * result as processing the data in a single pass.
 */
static void test_split_update(int num_splits, const struct hmac_sha256 *expected,
                              const u8 *data, size_t size)
{
	const size_t split_size = size / (num_splits + 1);
	struct hmac_sha256_ctx ctx;
	struct hmac_sha256 actual;

	hmac_sha256_init(&ctx, hmac_key, hmac_key_len);
	for (int i = 0; i < num_splits; ++i) {
		hmac_sha256_update(&ctx, data, split_size);
		data += split_size;
		size -= split_size;
	}
	hmac_sha256_update(&ctx, data, size); /* Process remaining data. */
	hmac_sha256_done(&ctx, &actual);
	assert(memeq(expected, sizeof(*expected), &actual, sizeof(actual)));
}

/* Test that the HMAC calculated by CCAN matches OpenSSL's HMAC. */
static void test_vs_openssl(const struct hmac_sha256 *expected, const u8 *data, size_t size)
{
	u8 openssl_hash[SHA256_DIGEST_LENGTH];
	size_t hash_size;
	EVP_MAC_CTX *ctx;
	OSSL_PARAM params[] = {
		OSSL_PARAM_construct_utf8_string("digest", "SHA256", 0),
		OSSL_PARAM_END
	};

	ctx = EVP_MAC_CTX_new(hmac_sha256_algo);
	assert(ctx);

	assert(EVP_MAC_init(ctx, hmac_key, hmac_key_len, params));
	assert(EVP_MAC_update(ctx, data, size));
	assert(EVP_MAC_final(ctx, openssl_hash, &hash_size, sizeof(openssl_hash)));
	EVP_MAC_CTX_free(ctx);

	assert(hash_size == SHA256_DIGEST_LENGTH);
	assert(memeq(expected, sizeof(*expected), openssl_hash, sizeof(openssl_hash)));
}

void run(const u8 *data, size_t size)
{
	struct hmac_sha256 expected;
	u8 num_splits;

	if (size < 1)
		return;
	hmac_key_len = (size_t) data[0];
	++data; --size;

	if (size < hmac_key_len)
		return;
	hmac_key = (unsigned char*) data;
	data += hmac_key_len; size -= hmac_key_len;

	if (size < 1)
		return;
	num_splits = *data;
	++data; --size;

	/* Compute expected HMAC using the one-shot function. */
	hmac_sha256(&expected, hmac_key, hmac_key_len, data, size);
	test_split_update(num_splits, &expected, data, size);
	test_vs_openssl(&expected, data, size);
}

