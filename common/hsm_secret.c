#include "config.h"
#include <ccan/tal/str/str.h>
#include <ccan/tal/tal.h>
#include <common/errcode.h>
#include <common/utils.h>
#include <common/hsm_secret.h>
#include <errno.h>
#include <termios.h>
#include <unistd.h>
#include <ccan/crypto/sha256/sha256.h>  
#include <ccan/mem/mem.h>               
#include <sodium.h>                     
#include <wally_bip39.h>                
#include <sys/stat.h>                   

/* Length of the encrypted hsm secret header. */
#define HS_HEADER_LEN crypto_secretstream_xchacha20poly1305_HEADERBYTES
/* From libsodium: "The ciphertext length is guaranteed to always be message
 * length + ABYTES" */
#define HS_CIPHERTEXT_LEN \
	(sizeof(struct secret) + crypto_secretstream_xchacha20poly1305_ABYTES)
/* Total length of an encrypted hsm_secret */
#define ENCRYPTED_HSM_SECRET_LEN (HS_HEADER_LEN + HS_CIPHERTEXT_LEN)

static void destroy_secret(struct secret *secret)
{
	sodium_munlock(secret->data, sizeof(secret->data));
}

struct secret *get_encryption_key(const tal_t *ctx, const char *passphrase)
{
	struct secret *secret = tal(ctx, struct secret);
	const u8 salt[16] = "c-lightning\0\0\0\0\0";

	/* Check bounds. */
	if (strlen(passphrase) < crypto_pwhash_argon2id_PASSWD_MIN) {
		return tal_free(secret);
	} else if (strlen(passphrase) > crypto_pwhash_argon2id_PASSWD_MAX) {
		return tal_free(secret);
	}

	/* Don't swap the encryption key ! */
	if (sodium_mlock(secret->data, sizeof(secret->data)) != 0)
		return tal_free(secret);
	tal_add_destructor(secret, destroy_secret);

	/* Now derive the key. */
	if (crypto_pwhash(secret->data, sizeof(secret->data), passphrase, strlen(passphrase), salt,
			  /* INTERACTIVE needs 64 MiB of RAM, MODERATE needs 256,
			   * and SENSITIVE needs 1024. */
			  crypto_pwhash_argon2id_OPSLIMIT_MODERATE,
			  crypto_pwhash_argon2id_MEMLIMIT_MODERATE,
			  crypto_pwhash_ALG_ARGON2ID13) != 0) {
		return tal_free(secret);
	}

	return secret;
}

bool hsm_secret_needs_passphrase(const u8 *hsm_secret, size_t len)
{
	enum hsm_secret_type type = detect_hsm_secret_type(hsm_secret, len);
	
	switch (type) {
	case HSM_SECRET_ENCRYPTED:
	case HSM_SECRET_MNEMONIC_WITH_PASS:
		return true;
	case HSM_SECRET_PLAIN:
	case HSM_SECRET_MNEMONIC_NO_PASS:
	case HSM_SECRET_INVALID:
		return false;
	}
	return false;
}

enum hsm_secret_type detect_hsm_secret_type(const u8 *hsm_secret, size_t len)
{
	/* Legacy 32-byte plain format */
	if (len == HSM_SECRET_PLAIN_SIZE)
		return HSM_SECRET_PLAIN;
	
	/* Legacy 73-byte encrypted format */
	if (len == ENCRYPTED_HSM_SECRET_LEN)
		return HSM_SECRET_ENCRYPTED;
	
	/* Check if it starts with our type bytes (mnemonic formats) */
	if (len > 32) {
		if (memeqzero(hsm_secret, 32))
			return HSM_SECRET_MNEMONIC_NO_PASS;
		else
			return HSM_SECRET_MNEMONIC_WITH_PASS;
	}	
	return HSM_SECRET_INVALID;
}

static void hash_passphrase(const char *passphrase, u8 hash[PASSPHRASE_HASH_LEN])
{
	struct sha256 sha;
	sha256(&sha, passphrase, strlen(passphrase));
	memcpy(hash, sha.u.u8, PASSPHRASE_HASH_LEN);
}

/* Validate the passphrase for a mnemonic secret */
bool validate_mnemonic_passphrase(const u8 *hsm_secret, size_t len, const char *passphrase)
{
	enum hsm_secret_type type = detect_hsm_secret_type(hsm_secret, len);
	
	if (type != HSM_SECRET_MNEMONIC_WITH_PASS)
		return true; /* No validation needed */

	/* First 32 bytes are the stored passphrase hash */
	const u8 *stored_hash = hsm_secret;
	u8 computed_hash[32];
	
	hash_passphrase(passphrase, computed_hash);
	return memcmp(stored_hash, computed_hash, 32) == 0;
}

static bool decrypt_hsm_secret(const struct secret *encryption_key,
			       const struct encrypted_hsm_secret *cipher,
			       struct secret *output)
{
	crypto_secretstream_xchacha20poly1305_state crypto_state;

	/* The header part */
	if (crypto_secretstream_xchacha20poly1305_init_pull(&crypto_state, cipher->data,
							    encryption_key->data) != 0)
		return false;
	/* The ciphertext part */
	if (crypto_secretstream_xchacha20poly1305_pull(&crypto_state, output->data,
						       NULL, 0,
						       cipher->data + HS_HEADER_LEN,
						       HS_CIPHERTEXT_LEN,
						       NULL, 0) != 0)
		return false;

	return true;
}

/* Helper function to convert error codes to human-readable messages */
const char *hsm_secret_error_str(enum hsm_secret_error err)
{
	switch (err) {
	case HSM_SECRET_OK:
		return "Success";
	case HSM_SECRET_ERR_PASSPHRASE_REQUIRED:
		return "Passphrase required but not provided";
	case HSM_SECRET_ERR_PASSPHRASE_NOT_NEEDED:
		return "Passphrase provided but not needed";
	case HSM_SECRET_ERR_WRONG_PASSPHRASE:
		return "Wrong passphrase";
	case HSM_SECRET_ERR_INVALID_MNEMONIC:
		return "Invalid mnemonic";
	case HSM_SECRET_ERR_ENCRYPTION_FAILED:
		return "Encryption failed";
	case HSM_SECRET_ERR_WORDLIST_FAILED:
		return "Could not load wordlist";
	case HSM_SECRET_ERR_SEED_DERIVATION_FAILED:
		return "Could not derive seed from mnemonic";
	case HSM_SECRET_ERR_INVALID_FORMAT:
		return "Invalid hsm_secret format";
	case HSM_SECRET_ERR_TERMINAL:
		return "Terminal error";
	case HSM_SECRET_ERR_MEMORY:
		return "Memory error";
	}
	return "Unknown error";
}
static struct hsm_secret *extract_plain_secret(const tal_t *ctx, 
					       const u8 *hsm_secret, 
					       size_t len, 
					       enum hsm_secret_error *err)
{
	struct hsm_secret *hsms = tal(ctx, struct hsm_secret);
	
	hsms->type = HSM_SECRET_PLAIN;
	hsms->mnemonic = NULL;
	memcpy(&hsms->secret, hsm_secret, sizeof(hsms->secret));
	
	*err = HSM_SECRET_OK;
	return hsms;
}
static struct hsm_secret *extract_encrypted_secret(const tal_t *ctx,
						   const u8 *hsm_secret,
						   size_t len,
						   const char *passphrase,
						   enum hsm_secret_error *err)
{
	struct hsm_secret *hsms = tal(ctx, struct hsm_secret);
	struct secret *encryption_key;
	bool decrypt_success;
	
	if (!passphrase) {
		*err = HSM_SECRET_ERR_PASSPHRASE_REQUIRED;
		return tal_free(hsms);
	}
	encryption_key = get_encryption_key(tmpctx, passphrase);
	if (!encryption_key) {
		*err = HSM_SECRET_ERR_WRONG_PASSPHRASE;
		return tal_free(hsms);
	}
	
	/* Clear secret data first in case of partial decryption */
	memset(&hsms->secret, 0, sizeof(hsms->secret));
	
	/* Attempt decryption */
	decrypt_success = decrypt_hsm_secret(encryption_key, (const struct encrypted_hsm_secret *)hsm_secret, &hsms->secret);
	
	/* Clear encryption key immediately after use */
	discard_key(encryption_key);
	
	if (!decrypt_success) {
		/* Clear any partial decryption data */
		memset(&hsms->secret, 0, sizeof(hsms->secret));
		*err = HSM_SECRET_ERR_WRONG_PASSPHRASE;
		return tal_free(hsms);
	}
	
	hsms->type = HSM_SECRET_ENCRYPTED;
	hsms->mnemonic = NULL;
	
	*err = HSM_SECRET_OK;
	return hsms;
}

static struct hsm_secret *extract_mnemonic_secret(const tal_t *ctx,
						  const u8 *hsm_secret,
						  size_t len,
						  const char *passphrase,
						  enum hsm_secret_error *err)
{
	struct hsm_secret *hsms = tal(ctx, struct hsm_secret);
	struct words *words;
	const u8 *mnemonic_start;
	size_t mnemonic_len;
	enum hsm_secret_type type;
	
	type = detect_hsm_secret_type(hsm_secret, len);
	hsms->type = type;
	
	/* Extract mnemonic portion (skip first 32 bytes which are passphrase hash) */
	mnemonic_start = hsm_secret + PASSPHRASE_HASH_LEN;
	mnemonic_len = len - PASSPHRASE_HASH_LEN;
	
	/* Validate passphrase if required */
	if (type == HSM_SECRET_MNEMONIC_WITH_PASS) {
		if (!passphrase) {
			*err = HSM_SECRET_ERR_PASSPHRASE_REQUIRED;
			return tal_free(hsms);
		}
		
		if (!validate_mnemonic_passphrase(hsm_secret, len, passphrase)) {
			*err = HSM_SECRET_ERR_WRONG_PASSPHRASE;
			return tal_free(hsms);
		}
	} else {
		if (passphrase) {
			*err = HSM_SECRET_ERR_PASSPHRASE_NOT_NEEDED;
			return tal_free(hsms);
		}
	}
	
	/* Copy and validate mnemonic */
	hsms->mnemonic = tal_strndup(hsms, (const char *)mnemonic_start, mnemonic_len);
	
	/* Load wordlist and validate mnemonic */
	if (bip39_get_wordlist("en", &words) != WALLY_OK) {
		*err = HSM_SECRET_ERR_WORDLIST_FAILED;
		return tal_free(hsms);
	}
	
	if (bip39_mnemonic_validate(words, hsms->mnemonic) != WALLY_OK) {
		*err = HSM_SECRET_ERR_INVALID_MNEMONIC;
		return tal_free(hsms);
	}
	
	/* Derive the seed from the mnemonic */
	u8 bip32_seed[BIP39_SEED_LEN_512];
	size_t bip32_seed_len;
	const char *seed_passphrase = (type == HSM_SECRET_MNEMONIC_WITH_PASS) ? passphrase : NULL;
	
	if (bip39_mnemonic_to_seed(hsms->mnemonic, seed_passphrase, bip32_seed, sizeof(bip32_seed), &bip32_seed_len) != WALLY_OK) {
		*err = HSM_SECRET_ERR_SEED_DERIVATION_FAILED;
		return tal_free(hsms);
	}
	
	/* We only use the first 32 bytes for the hsm_secret */
	memcpy(hsms->secret.data, bip32_seed, sizeof(hsms->secret.data));
	
	*err = HSM_SECRET_OK;
	return hsms;
}

/* If hsm_secret_needs_passphrase, passphrase must not be NULL.
 * Returns NULL on failure. */
struct hsm_secret *extract_hsm_secret(const tal_t *ctx,
				      const u8 *hsm_secret, size_t len,
				      const char *passphrase,
				      enum hsm_secret_error *err)
{
	enum hsm_secret_type type = detect_hsm_secret_type(hsm_secret, len);
	
	switch (type) {
	case HSM_SECRET_PLAIN:
		return extract_plain_secret(ctx, hsm_secret, len, err);
	case HSM_SECRET_ENCRYPTED:
		return extract_encrypted_secret(ctx, hsm_secret, len, passphrase, err);
	case HSM_SECRET_MNEMONIC_NO_PASS:
		return extract_mnemonic_secret(ctx, hsm_secret, len, NULL, err);
	case HSM_SECRET_MNEMONIC_WITH_PASS:
		return extract_mnemonic_secret(ctx, hsm_secret, len, passphrase, err);
	case HSM_SECRET_INVALID:
		*err = HSM_SECRET_ERR_INVALID_FORMAT;
		return NULL;
	}
}

bool encrypt_legacy_hsm_secret(const struct secret *encryption_key,
			const struct secret *hsm_secret,
			struct encrypted_hsm_secret *output)
{
	crypto_secretstream_xchacha20poly1305_state crypto_state;

	if (crypto_secretstream_xchacha20poly1305_init_push(&crypto_state, output->data,
							    encryption_key->data) != 0)
		return false;
	if (crypto_secretstream_xchacha20poly1305_push(&crypto_state,
						       output->data + HS_HEADER_LEN,
						       NULL, hsm_secret->data,
						       sizeof(hsm_secret->data),
						       /* Additional data and tag */
						       NULL, 0, 0))
		return false;

	return true;
}

/* Returns -1 on error (and sets errno), 0 if not encrypted, 1 if it is */
int is_legacy_hsm_secret_encrypted(const char *path)
{
	struct stat st;

        if (stat(path, &st) != 0)
		return -1;

        return st.st_size == ENCRYPTED_HSM_SECRET_LEN;
}

void discard_key(struct secret *key TAKES)
{
	/* sodium_munlock() also zeroes the memory. */
	sodium_munlock(key->data, sizeof(key->data));
	if (taken(key))
		tal_free(key);
}

static void destroy_passphrase(char *passphrase)
{
	sodium_memzero(passphrase, tal_bytelen(passphrase));
	sodium_munlock(passphrase, tal_bytelen(passphrase));
}

/* Disable terminal echo if needed */
static bool disable_echo(struct termios *saved_term)
{
	if (!isatty(fileno(stdin)))
		return false;

	if (tcgetattr(fileno(stdin), saved_term) != 0)
		return false;

	struct termios tmp = *saved_term;
	tmp.c_lflag &= ~ECHO;

	if (tcsetattr(fileno(stdin), TCSANOW, &tmp) != 0)
		return false;

	return true;
}

/* Restore terminal echo if it was disabled */
static void restore_echo(const struct termios *saved_term)
{
	tcsetattr(fileno(stdin), TCSANOW, saved_term);
}

/* Read line from stdin (uses malloc internally) */
static char *read_line(void)
{
	char *line = NULL;
	size_t size = 0;

	if (getline(&line, &size, stdin) < 0) {
		free(line);
		return NULL;
	}

	/* Strip newline */
	size_t len = strlen(line);
	if (len > 0 && line[len - 1] == '\n')
		line[len - 1] = '\0';

	return line;
}

const char *read_stdin_pass(const tal_t *ctx, enum hsm_secret_error *err)
{
	*err = HSM_SECRET_OK;

	struct termios saved_term;
	bool echo_disabled = disable_echo(&saved_term);
	if (isatty(fileno(stdin)) && !echo_disabled) {
		*err = HSM_SECRET_ERR_TERMINAL;
		return NULL;
	}

	char *input = read_line();
	if (!input) {
		if (echo_disabled)
			restore_echo(&saved_term);
		*err = HSM_SECRET_ERR_INVALID_FORMAT;
		return NULL;
	}

	size_t len = strlen(input);
	char *passphrase = tal_arr(ctx, char, len + 1);
	strcpy(passphrase, input);
	free(input);

	/* Memory locking is mandatory: failure means we're on an insecure system */
	if (sodium_mlock(passphrase, len + 1) != 0)
		abort();

	tal_add_destructor(passphrase, destroy_passphrase);

	if (echo_disabled)
		restore_echo(&saved_term);

	return passphrase;
}

/* Add this function to hsm_secret.c */
const char *read_stdin_mnemonic(const tal_t *ctx, enum hsm_secret_error *err)
{
	*err = HSM_SECRET_OK;

	printf("Introduce your BIP39 word list separated by space (at least 12 words):\n");
	fflush(stdout);

	char *line = NULL;
	size_t size = 0;
	if (getline(&line, &size, stdin) < 0) {
		free(line);
		*err = HSM_SECRET_ERR_INVALID_FORMAT;
		return NULL;
	}

	/* Strip newline */
	size_t len = strlen(line);
	if (len > 0 && line[len - 1] == '\n')
		line[len - 1] = '\0';

	/* Validate mnemonic */
	struct words *words;
	if (bip39_get_wordlist("en", &words) != WALLY_OK) {
		free(line);
		*err = HSM_SECRET_ERR_WORDLIST_FAILED;
		return NULL;
	}

	if (bip39_mnemonic_validate(words, line) != WALLY_OK) {
		free(line);
		*err = HSM_SECRET_ERR_INVALID_MNEMONIC;
		return NULL;
	}

	/* Convert to tal string */
	char *mnemonic = tal_strdup(ctx, line);
	free(line);

	return mnemonic;
}






