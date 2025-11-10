#include "config.h"
#include <assert.h>

#include <ccan/mem/mem.h>
#include <common/hsm_secret.h>
#include <common/setup.h>
#include <stdlib.h>
#include <tests/fuzz/libfuzz.h>

void init(int *argc, char ***argv)
{
	/* Don't run as a unit test under valgrind: too slow! */
#ifndef FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION
	if (getenv("VALGRIND") && strcmp(getenv("VALGRIND"), "1") == 0) {
		common_shutdown();
		exit(0);
	}
#endif
}

void run(const uint8_t *data, size_t size)
{
	/* LibFuzzer won't generate inputs larger than
	 * crypto_pwhash_argon2id_PASSWD_MAX in practice, but hey. */
	if (size > sizeof(struct secret) && size < crypto_pwhash_argon2id_PASSWD_MAX) {
		struct secret *hsm_secret, *encryption_key;
		char *passphrase;
		u8 encrypted_data[ENCRYPTED_HSM_SECRET_LEN];
		struct hsm_secret *decrypted_hsm;
		enum hsm_secret_error err;

		/* Take the first 32 bytes as the plaintext hsm_secret seed,
		 * and the remaining ones as the passphrase. */
		hsm_secret = (struct secret *)tal_dup_arr(NULL, u8, data, sizeof(struct secret), 0);
		mlock_tal_memory(hsm_secret);
		passphrase = to_string(NULL, data + sizeof(struct secret), size - sizeof(struct secret));

		/* A valid seed, a valid passphrase. This should not fail. */
		encryption_key = get_encryption_key(NULL, passphrase);
		assert(encryption_key);

		/* Roundtrip: encrypt then decrypt */
		assert(encrypt_legacy_hsm_secret(encryption_key, hsm_secret, encrypted_data));
		decrypted_hsm = extract_hsm_secret(NULL, encrypted_data, ENCRYPTED_HSM_SECRET_LEN,
						   passphrase, &err);
		assert(decrypted_hsm);
		assert(err == HSM_SECRET_OK);
		assert(decrypted_hsm->type == HSM_SECRET_ENCRYPTED);
		assert(memeq(hsm_secret->data, sizeof(hsm_secret->data),
			     decrypted_hsm->secret_data, sizeof(hsm_secret->data)));

		tal_free(hsm_secret);
		tal_free(passphrase);
		tal_free(encryption_key);
		tal_free(decrypted_hsm);
	}
}
