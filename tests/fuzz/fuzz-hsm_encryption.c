#include "config.h"
#include <assert.h>

#include <ccan/mem/mem.h>
#include <common/hsm_encryption.h>
#include <tests/fuzz/libfuzz.h>

void init(int *argc, char ***argv)
{
}

void run(const uint8_t *data, size_t size)
{
	/* LibFuzzer won't generate inputs larger than
	 * crypto_pwhash_argon2id_PASSWD_MAX in practice, but hey. */
	if (size > sizeof(struct secret) && size < crypto_pwhash_argon2id_PASSWD_MAX) {
		struct secret *hsm_secret, decrypted_hsm_secret, encryption_key;
		char *passphrase;
		struct encrypted_hsm_secret encrypted_secret;
		const char *emsg;

		/* Take the first 32 bytes as the plaintext hsm_secret seed,
		 * and the remaining ones as the passphrase. */
		hsm_secret = (struct secret *)tal_dup_arr(NULL, u8, data, sizeof(struct secret), 0);
		passphrase = to_string(NULL, data + sizeof(struct secret), size - sizeof(struct secret));

		/* A valid seed, a valid passphrase. This should not fail. */
		assert(!hsm_secret_encryption_key_with_exitcode(passphrase, &encryption_key, &emsg));
		/* Roundtrip */
		assert(encrypt_hsm_secret(&encryption_key, hsm_secret,
					  &encrypted_secret));
		assert(decrypt_hsm_secret(&encryption_key, &encrypted_secret,
					  &decrypted_hsm_secret));
		assert(memeq(hsm_secret->data, sizeof(hsm_secret->data),
			     decrypted_hsm_secret.data,
			     sizeof(decrypted_hsm_secret.data)));

		discard_key(hsm_secret);
		tal_free(passphrase);
	}
}
