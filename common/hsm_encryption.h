#ifndef LIGHTNING_COMMON_HSM_ENCRYPTION_H
#define LIGHTNING_COMMON_HSM_ENCRYPTION_H
#include "config.h"
#include <bitcoin/privkey.h>
#include <ccan/short_types/short_types.h>
#include <ccan/tal/tal.h>
#include <sodium.h>

/* Length of the encrypted hsm secret header. */
#define HS_HEADER_LEN crypto_secretstream_xchacha20poly1305_HEADERBYTES
/* From libsodium: "The ciphertext length is guaranteed to always be message
 * length + ABYTES" */
#define HS_CIPHERTEXT_LEN \
	(sizeof(struct secret) + crypto_secretstream_xchacha20poly1305_ABYTES)
/* Total length of an encrypted hsm_secret */
#define ENCRYPTED_HSM_SECRET_LEN (HS_HEADER_LEN + HS_CIPHERTEXT_LEN)

struct encrypted_hsm_secret {
	u8 data[ENCRYPTED_HSM_SECRET_LEN];
};

/** Derive the hsm_secret encryption key from a passphrase.
 * @pass: the passphrase string.
 * @encryption_key: the output key derived from the passphrase.
 *
 * On success, NULL is returned. On error, a human-readable error is.
 */
char *hsm_secret_encryption_key(const char *pass, struct secret *encryption_key);

/** Encrypt the hsm_secret using a previously derived encryption key.
 * @encryption_key: the key derived from the passphrase.
 * @hsm_secret: the plaintext hsm_secret to encrypt.
 * @output: the resulting encrypted hsm_secret.
 *
 * Return false on encryption failure.
 */
bool encrypt_hsm_secret(const struct secret *encryption_key,
			const struct secret *hsm_secret,
			struct encrypted_hsm_secret *output);

/** Decrypt the hsm_secret using a previously derived encryption key.
 * @encryption_key: the key derived from the passphrase.
 * @cipher: the encrypted hsm_secret to decrypt.
 * @output: the resulting hsm_secret.
 *
 * Return false on decryption failure.
 */
bool decrypt_hsm_secret(const struct secret *encryption_key,
			const struct encrypted_hsm_secret *cipher,
			struct secret *output);

/** Unlock and zeroize the encryption key memory after use.
 * @key: the encryption key. If taken, it will be tal_free'd
 */
void discard_key(struct secret *key TAKES);

/** Read hsm_secret encryption pass from stdin, disabling echoing.
 * @reason: if NULL is returned, will point to the human-readable error.
 *
 * Caller must free the string as it does tal-reallocate getline's output.
 */
char *read_stdin_pass(char **reason);

#endif /* LIGHTNING_COMMON_HSM_ENCRYPTION_H */
