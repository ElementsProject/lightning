#ifndef LIGHTNING_COMMON_HSM_SECRET_H
#define LIGHTNING_COMMON_HSM_SECRET_H
#include "config.h"
#include <sys/types.h>
#include <ccan/tal/tal.h>
#include <bitcoin/privkey.h>
#include <sodium.h>

/* Length constants for encrypted HSM secret files */
#define HS_HEADER_LEN crypto_secretstream_xchacha20poly1305_HEADERBYTES
#define HS_CIPHERTEXT_LEN \
	(sizeof(struct secret) + crypto_secretstream_xchacha20poly1305_ABYTES)
#define ENCRYPTED_HSM_SECRET_LEN (HS_HEADER_LEN + HS_CIPHERTEXT_LEN)
#define PASSPHRASE_HASH_LEN 32
#define HSM_SECRET_PLAIN_SIZE 32

enum hsm_secret_type {
	HSM_SECRET_PLAIN = 0,           /* Legacy 32-byte format */
	HSM_SECRET_ENCRYPTED = 1,       /* Legacy 73-byte encrypted format */
	HSM_SECRET_MNEMONIC_NO_PASS = 2,    /* Mnemonic without passphrase */
	HSM_SECRET_MNEMONIC_WITH_PASS = 3,  /* Mnemonic with passphrase */
    HSM_SECRET_INVALID = 4,
};

enum hsm_secret_error {
	HSM_SECRET_OK = 0,
	HSM_SECRET_ERR_PASSPHRASE_REQUIRED,
	HSM_SECRET_ERR_PASSPHRASE_NOT_NEEDED,
	HSM_SECRET_ERR_WRONG_PASSPHRASE,
	HSM_SECRET_ERR_INVALID_MNEMONIC,
	HSM_SECRET_ERR_ENCRYPTION_FAILED,
	HSM_SECRET_ERR_WORDLIST_FAILED,
	HSM_SECRET_ERR_SEED_DERIVATION_FAILED,
	HSM_SECRET_ERR_INVALID_FORMAT,
	HSM_SECRET_ERR_TERMINAL,
	HSM_SECRET_ERR_MEMORY
};

/**
 * Represents the content of the hsm_secret file, either a raw seed or a mnemonic.
 */
struct hsm_secret {
	struct secret secret;
	char *mnemonic; /* NULL if not derived from mnemonic */
    enum hsm_secret_type type;
};

struct encrypted_hsm_secret {
    u8 data[ENCRYPTED_HSM_SECRET_LEN];
};

/**
 * Checks whether the hsm_secret data requires a passphrase to decrypt.
 * Handles legacy, encrypted, and mnemonic-based formats.
 */
bool hsm_secret_needs_passphrase(const u8 *hsm_secret, size_t len);

/**
 * Parse and decrypt an hsm_secret file.
 *
 * @ctx - a tal context
 * @hsm_secret - raw file contents
 * @len - length of file
 * @passphrase - passphrase, or NULL if not needed
 * @err - optional pointer to set error code on failure
 * 
 * Returns parsed `struct hsm_secret` or NULL on error.
 */
struct hsm_secret *extract_hsm_secret(const tal_t *ctx,
				      const u8 *hsm_secret, size_t len,
				      const char *passphrase,
				      enum hsm_secret_error *err);

/**
 * Encrypt a given hsm_secret using a provided encryption key.
 * @encryption_key - derived from passphrase (via Argon2)
 * @hsm_secret - plaintext secret to encrypt
 * @output - output struct containing encrypted data
 *
 * Returns true on success.
 */
bool encrypt_legacy_hsm_secret(const struct secret *encryption_key,
			const struct secret *hsm_secret,
			struct encrypted_hsm_secret *output);

/**
 * Securely discard an encryption key from memory.
 * Frees memory if TAKEN.
 */
void discard_key(struct secret *key TAKES);

/**
 * Returns:
 *   -1: file error (sets errno)
 *    0: file is not encrypted
 *    1: file is encrypted
 */
int is_legacy_hsm_secret_encrypted(const char *path);

/**
 * Reads a passphrase from stdin, disabling terminal echo.
 * Returns a newly allocated string on success, NULL on error.
 * @ctx - tal context for allocation
 * @err - on failure, this will be set to the error code
 * 
 * Returns allocated passphrase or NULL on error.
 */
const char *read_stdin_pass(const tal_t *ctx, enum hsm_secret_error *err);

/**
 * Derive encryption key from passphrase using Argon2id.
 * @ctx - tal context for allocation
 * @passphrase - the passphrase to derive from
 * 
 * Returns allocated secret or NULL on failure.
 */
struct secret *get_encryption_key(const tal_t *ctx, const char *passphrase);

/**
 * Convert error code to human-readable string.
 * @err - the error code to convert
 * 
 * Returns a string describing the error.
 */
const char *hsm_secret_error_str(enum hsm_secret_error err);

/**
 * Detect the type of hsm_secret based on its content and length.
 * @hsm_secret - raw file contents
 * @len - length of file
 * 
 * Returns the detected type.
 */
enum hsm_secret_type detect_hsm_secret_type(const u8 *hsm_secret, size_t len);

/**
 * Validate passphrase for mnemonic-based secrets.
 * @hsm_secret - raw file contents
 * @len - length of file
 * @passphrase - passphrase to validate
 * 
 * Returns true if passphrase is valid or not needed.
 */
bool validate_mnemonic_passphrase(const u8 *hsm_secret, size_t len, const char *passphrase);

/**
 * Reads a BIP39 mnemonic from stdin with validation.
 * Returns a newly allocated string on success, NULL on error.
 * @ctx - tal context for allocation
 * @err - optional pointer to set error code on failure
 * 
 * Returns tal-allocated mnemonic string or NULL on error.
 */
const char *read_stdin_mnemonic(const tal_t *ctx, enum hsm_secret_error *err);

#endif /* LIGHTNING_COMMON_HSM_SECRET_H */
