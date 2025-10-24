#ifndef LIGHTNING_COMMON_HSM_SECRET_H
#define LIGHTNING_COMMON_HSM_SECRET_H
#include "config.h"
#include <bitcoin/privkey.h>
#include <ccan/crypto/sha256/sha256.h>
#include <ccan/short_types/short_types.h>
#include <ccan/tal/tal.h>
#include <sodium.h>
#include <sys/types.h>

/* Length constants for encrypted HSM secret files */
#define HS_HEADER_LEN crypto_secretstream_xchacha20poly1305_HEADERBYTES
#define HS_CIPHERTEXT_LEN \
	(sizeof(struct secret) + crypto_secretstream_xchacha20poly1305_ABYTES)
#define ENCRYPTED_HSM_SECRET_LEN (HS_HEADER_LEN + HS_CIPHERTEXT_LEN)

enum hsm_secret_type {
	HSM_SECRET_PLAIN = 0,               /* Legacy 32-byte format */
	HSM_SECRET_ENCRYPTED = 1,           /* Legacy 73-byte encrypted format */
	HSM_SECRET_MNEMONIC_NO_PASS = 2,    /* Mnemonic without passphrase */
	HSM_SECRET_MNEMONIC_WITH_PASS = 3,  /* Mnemonic with passphrase */
	HSM_SECRET_INVALID = 4,             /* When all else fails, blame the user */
};

enum hsm_secret_error {
	HSM_SECRET_OK = 0,
	HSM_SECRET_ERR_PASSPHRASE_REQUIRED,
	HSM_SECRET_ERR_PASSPHRASE_NOT_NEEDED,
	HSM_SECRET_ERR_WRONG_PASSPHRASE,
	HSM_SECRET_ERR_INVALID_MNEMONIC,
	HSM_SECRET_ERR_ENCRYPTION_FAILED,
	HSM_SECRET_ERR_SEED_DERIVATION_FAILED,
	HSM_SECRET_ERR_INVALID_FORMAT,
	HSM_SECRET_ERR_TERMINAL,
	HSM_SECRET_ERR_MEMORY
};

/**
 * Represents the content of the hsm_secret file, either a raw seed or a mnemonic.
 */
struct hsm_secret {
	enum hsm_secret_type type;
	u8 *secret_data;          /* Variable length: 32 bytes (legacy) or 64 bytes (mnemonic) */
	struct secret secret;     /* Legacy 32-byte field for compatibility */
	const char *mnemonic;           /* NULL if not derived from mnemonic */
};

/**
 * Get the secret bytes from an hsm_secret.
 * Returns secret_data if available, otherwise falls back to legacy secret.data.
 */
const u8 *hsm_secret_bytes(const struct hsm_secret *hsm);

/**
 * Get the secret size from an hsm_secret.
 * Returns tal_bytelen of secret_data if available, otherwise 32 bytes for legacy.
 */
size_t hsm_secret_size(const struct hsm_secret *hsm);

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
 * get_encryption_key - Derive encryption key from passphrase using Argon2.
 * @ctx - tal context for allocation
 * @passphrase - the passphrase to derive from
 *
 * Returns derived encryption key, or NULL on error.
 * The returned key is memory-locked and has a destructor to clear it.
 */
struct secret *get_encryption_key(const tal_t *ctx, const char *passphrase);

/**
 * Encrypt a given hsm_secret using a provided encryption key.
 * @encryption_key - derived from passphrase (via Argon2)
 * @hsm_secret - plaintext secret to encrypt
 * @output - output buffer for encrypted data (must be ENCRYPTED_HSM_SECRET_LEN bytes)
 *
 * Returns true on success.
 */
bool encrypt_legacy_hsm_secret(const struct secret *encryption_key,
			const struct secret *hsm_secret,
			u8 *output);

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
 * Reads a BIP39 mnemonic from stdin with validation.
 * Returns a newly allocated string on success, NULL on error.
 * @ctx - tal context for allocation
 * @err - optional pointer to set error code on failure
 *
 * Returns tal-allocated mnemonic string or NULL on error.
 */
const char *read_stdin_mnemonic(const tal_t *ctx, enum hsm_secret_error *err);

/**
 * Derive seed hash from mnemonic + passphrase.
 * @mnemonic - the BIP39 mnemonic
 * @passphrase - the passphrase (can be NULL)
 * @seed_hash - output parameter for the derived seed hash
 *
 * Returns true on success, false on failure.
 */
bool derive_seed_hash(const char *mnemonic, const char *passphrase, struct sha256 *seed_hash);

/**
 * Check if hsm_secret file is encrypted (legacy format only).
 * @path - path to the hsm_secret file
 *
 * Returns 1 if encrypted, 0 if not encrypted, -1 on error.
 */
int is_legacy_hsm_secret_encrypted(const char *path);

/**
 * Zero and unlock a secret's memory.
 * @secret - the secret to destroy
 */
void destroy_secret(struct secret *secret);

/**
 * Convert hsm_secret_type enum to human-readable string.
 * @type - the hsm_secret_type to convert
 *
 * Returns a string describing the type.
 */
const char *format_type_name(enum hsm_secret_type type);

/**
 * Wrapper around grab_file that removes the NUL terminator.
 * @ctx - tal context for allocation
 * @filename - path to the file to read
 * @len - output parameter for the file length (excluding NUL terminator)
 *
 * Returns file contents with NUL terminator removed, or NULL on error.
 * Unlike grab_file, the returned data does not include the NUL terminator.
 */
u8 *grab_file_contents(const tal_t *ctx, const char *filename, size_t *len);

/**
 * Derive encryption key from passphrase using Argon2.
 * @ctx - tal context for allocation
 * @passphrase - the passphrase to derive from
 *
 * Returns derived encryption key, or NULL on error.
 * The returned key is memory-locked and has a destructor to clear it.
 */
struct secret *get_encryption_key(const tal_t *ctx, const char *passphrase);

#endif /* LIGHTNING_COMMON_HSM_SECRET_H */
