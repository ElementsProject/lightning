#include "config.h"
#include <assert.h>
#include <ccan/mem/mem.h>
#include <ccan/tal/grab_file/grab_file.h>
#include <ccan/tal/str/str.h>
#include <common/errcode.h>
#include <common/hsm_secret.h>
#include <common/memleak.h>
#include <common/utils.h>
#include <errno.h>
#include <sys/stat.h>
#include <termios.h>
#include <unistd.h>
#include <wally_bip39.h>

/* HSM secret size constants */
#define HSM_SECRET_PLAIN_SIZE 32
#define HSM_SECRET_MNEMONIC_SIZE 64

/* Length of the encrypted hsm secret header. */
#define HS_HEADER_LEN crypto_secretstream_xchacha20poly1305_HEADERBYTES
/* From libsodium: "The ciphertext length is guaranteed to always be message
 * length + ABYTES" */
#define HS_CIPHERTEXT_LEN \
	(sizeof(struct secret) + crypto_secretstream_xchacha20poly1305_ABYTES)
/* Total length of an encrypted hsm_secret */
#define ENCRYPTED_HSM_SECRET_LEN (HS_HEADER_LEN + HS_CIPHERTEXT_LEN)
#define PASSPHRASE_HASH_LEN 32
#define HSM_SECRET_PLAIN_SIZE 32

/* Helper function to validate a mnemonic string */
static bool validate_mnemonic(const char *mnemonic, enum hsm_secret_error *err)
{
	struct words *words;
	bool ok;

	tal_wally_start();
	if (bip39_get_wordlist("en", &words) != WALLY_OK) {
		abort();
	}

	ok = (bip39_mnemonic_validate(words, mnemonic) == WALLY_OK);

	/* Wordlists can persist, so provide a common context! */
	tal_wally_end(notleak_with_children(tal(NULL, char)));

	if (!ok) {
		*err = HSM_SECRET_ERR_INVALID_MNEMONIC;
		return false;
	}

	return true;
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
	mlock_tal_memory(secret);

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
	switch (detect_hsm_secret_type(hsm_secret, len)) {
	case HSM_SECRET_ENCRYPTED:
	case HSM_SECRET_MNEMONIC_WITH_PASS:
		return true;
	case HSM_SECRET_PLAIN:
	case HSM_SECRET_MNEMONIC_NO_PASS:
	case HSM_SECRET_INVALID:
		return false;
	}
	abort();
}

enum hsm_secret_type detect_hsm_secret_type(const u8 *hsm_secret, size_t len)
{
	/* Check for invalid cases first and return early */
	if (len < HSM_SECRET_PLAIN_SIZE)
		return HSM_SECRET_INVALID;

	/* Legacy 32-byte plain format */
	if (len == HSM_SECRET_PLAIN_SIZE)
		return HSM_SECRET_PLAIN;

	/* Legacy 73-byte encrypted format */
	if (len == ENCRYPTED_HSM_SECRET_LEN)
		return HSM_SECRET_ENCRYPTED;
	assert(len > sizeof(struct sha256));
	/* Check if it starts with our type bytes (mnemonic formats) */
	if (memeqzero(hsm_secret, 32))
		return HSM_SECRET_MNEMONIC_NO_PASS;
	else
		return HSM_SECRET_MNEMONIC_WITH_PASS;
}

struct bip32_seed {
	u8 seed[BIP39_SEED_LEN_512];
};

static bool mnemonic_to_seed(const char *mnemonic, const char *passphrase,
			     struct bip32_seed *bip32_seed)
{
	size_t len;

	tal_wally_start();
	if (bip39_mnemonic_to_seed(mnemonic, passphrase,
				   bip32_seed->seed, sizeof(bip32_seed->seed),
				   &len) != WALLY_OK) {
		tal_wally_end(tmpctx);
		return false;
	}
	/* libwally only allocate the salt temporarily, so context
	 * doesn't matter. */
	tal_wally_end(tmpctx);

	assert(len == sizeof(bip32_seed->seed));
	return true;
}

/* Helper function to derive seed hash from mnemonic + passphrase */
bool derive_seed_hash(const char *mnemonic, const char *passphrase, struct sha256 *seed_hash)
{
	struct bip32_seed bip32_seed;

	if (!passphrase) {
		/* No passphrase - return zero hash */
		memset(seed_hash, 0, sizeof(*seed_hash));
		return true;
	}

	if (!mnemonic_to_seed(mnemonic, passphrase, &bip32_seed))
		return false;

	sha256(seed_hash, bip32_seed.seed, sizeof(bip32_seed.seed));
	return true;
}

static bool decrypt_hsm_secret(const struct secret *encryption_key,
			       const u8 *cipher,
			       struct secret *output)
{
	crypto_secretstream_xchacha20poly1305_state crypto_state;

	/* The header part */
	if (crypto_secretstream_xchacha20poly1305_init_pull(&crypto_state, cipher,
							    encryption_key->data) != 0)
		return false;
	/* The ciphertext part */
	if (crypto_secretstream_xchacha20poly1305_pull(&crypto_state, output->data,
						       NULL, 0,
						       cipher + HS_HEADER_LEN,
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

	assert(len == HSM_SECRET_PLAIN_SIZE);
	hsms->type = HSM_SECRET_PLAIN;
	hsms->mnemonic = NULL;

	/* Allocate and populate secret_data (new field) */
	hsms->secret_data = tal_dup_arr(hsms, u8, hsm_secret, HSM_SECRET_PLAIN_SIZE, 0);

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

	/* Attempt decryption */
	struct secret temp_secret;
	decrypt_success = decrypt_hsm_secret(encryption_key, hsm_secret, &temp_secret);
	if (!decrypt_success) {
		*err = HSM_SECRET_ERR_WRONG_PASSPHRASE;
		return tal_free(hsms);
	}

	/* Duplicate decrypted secret data */
	hsms->secret_data = tal_dup_arr(hsms, u8, temp_secret.data, HSM_SECRET_PLAIN_SIZE, 0);

	hsms->type = HSM_SECRET_ENCRYPTED;
	hsms->mnemonic = NULL;

	*err = HSM_SECRET_OK;
	return hsms;
}

static struct hsm_secret *extract_mnemonic_secret(const tal_t *ctx,
						  const u8 *hsm_secret,
						  size_t len,
						  const char *passphrase,
						  enum hsm_secret_type type,
						  enum hsm_secret_error *err)
{
	struct hsm_secret *hsms = tal(ctx, struct hsm_secret);
	const u8 *mnemonic_start;
	size_t mnemonic_len;
	struct bip32_seed bip32_seed;

	assert(type == HSM_SECRET_MNEMONIC_NO_PASS || type == HSM_SECRET_MNEMONIC_WITH_PASS);
	hsms->type = type;

	/* Extract mnemonic portion (skip first 32 bytes which are passphrase hash) */
	mnemonic_start = hsm_secret + PASSPHRASE_HASH_LEN;

	assert(len > PASSPHRASE_HASH_LEN);
	mnemonic_len = len - PASSPHRASE_HASH_LEN;

	/* Copy into convenient string form */
	hsms->mnemonic = tal_strndup(hsms, (const char *)mnemonic_start, mnemonic_len);

	/* Validate passphrase if required */
	if (type == HSM_SECRET_MNEMONIC_WITH_PASS) {
		if (!passphrase) {
			*err = HSM_SECRET_ERR_PASSPHRASE_REQUIRED;
			return tal_free(hsms);
		}

		/* Validate passphrase by comparing stored hash with computed hash */
		struct sha256 stored_hash, computed_hash;
		memcpy(&stored_hash, hsm_secret, sizeof(stored_hash));
		if (!derive_seed_hash(hsms->mnemonic, passphrase, &computed_hash)) {
			*err = HSM_SECRET_ERR_SEED_DERIVATION_FAILED;
			return tal_free(hsms);
		}
		if (!sha256_eq(&stored_hash, &computed_hash)) {
			*err = HSM_SECRET_ERR_WRONG_PASSPHRASE;
			return tal_free(hsms);
		}
	} else {
		if (passphrase) {
			*err = HSM_SECRET_ERR_PASSPHRASE_NOT_NEEDED;
			return tal_free(hsms);
		}
	}

	/* Validate mnemonic */
	if (!validate_mnemonic(hsms->mnemonic, err)) {
		return tal_free(hsms);
	}

	if (!mnemonic_to_seed(hsms->mnemonic, passphrase, &bip32_seed)) {
		*err = HSM_SECRET_ERR_SEED_DERIVATION_FAILED;
		return tal_free(hsms);
	}

	/* Allocate and populate secret_data with full 64-byte seed */
	hsms->secret_data = tal_dup_arr(hsms, u8, bip32_seed.seed, sizeof(bip32_seed.seed), 0);

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

	/* Switch will cause gcc to complain if a type isn't handled. */
	switch (type) {
	case HSM_SECRET_PLAIN:
		return extract_plain_secret(ctx, hsm_secret, len, err);

	case HSM_SECRET_ENCRYPTED:
		return extract_encrypted_secret(ctx, hsm_secret, len, passphrase, err);

	case HSM_SECRET_MNEMONIC_NO_PASS:
	case HSM_SECRET_MNEMONIC_WITH_PASS:
		return extract_mnemonic_secret(ctx, hsm_secret, len, passphrase, type, err);

	case HSM_SECRET_INVALID:
		*err = HSM_SECRET_ERR_INVALID_FORMAT;
		return NULL;
	}

	/* detect_hsm_secret_type promised to return a valid type. */
	abort();
}

bool encrypt_legacy_hsm_secret(const struct secret *encryption_key,
			const struct secret *hsm_secret,
			u8 *output)
{
	crypto_secretstream_xchacha20poly1305_state crypto_state;

	if (crypto_secretstream_xchacha20poly1305_init_push(&crypto_state, output,
							    encryption_key->data) != 0)
		return false;
	if (crypto_secretstream_xchacha20poly1305_push(&crypto_state,
						       output + HS_HEADER_LEN,
						       NULL, hsm_secret->data,
						       sizeof(hsm_secret->data),
						       /* Additional data and tag */
						       NULL, 0, 0))
		return false;

	return true;
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

/* Read line from stdin (uses tal allocation) */
static char *read_line(const tal_t *ctx)
{
	char *line = NULL;
	size_t size = 0;

	if (getline(&line, &size, stdin) < 0) {
		free(line);
		return NULL;
	}

	/* Strip newline */
	size_t len = strlen(line);
	if (strends(line, "\n"))
		len--;

	/* Convert to tal string */
	char *result = tal_strndup(ctx, line, len);
	free(line);
	return result;
}

const char *read_stdin_pass(const tal_t *ctx, enum hsm_secret_error *err)
{
	struct termios saved_term;
	bool echo_disabled = disable_echo(&saved_term);
	if (isatty(fileno(stdin)) && !echo_disabled) {
		*err = HSM_SECRET_ERR_TERMINAL;
		return NULL;
	}

	char *input = read_line(ctx);
	if (!input) {
		if (echo_disabled)
			restore_echo(&saved_term);
		*err = HSM_SECRET_ERR_INVALID_FORMAT;
		return NULL;
	}

	mlock_tal_memory(input);

	if (echo_disabled)
		restore_echo(&saved_term);

	*err = HSM_SECRET_OK;
	return input;
}

const char *read_stdin_mnemonic(const tal_t *ctx, enum hsm_secret_error *err)
{
	printf("Introduce your BIP39 word list separated by space (at least 12 words):\n");
	fflush(stdout);

	char *line = read_line(ctx);
	if (!line) {
		*err = HSM_SECRET_ERR_INVALID_FORMAT;
		return NULL;
	}

	/* Validate mnemonic */
	if (!validate_mnemonic(line, err)) {
		return NULL;
	}

	*err = HSM_SECRET_OK;
	return line;
}

int is_legacy_hsm_secret_encrypted(const char *path)
{
	struct stat st;

	if (stat(path, &st) != 0)
		return -1;

	return st.st_size == ENCRYPTED_HSM_SECRET_LEN;
}

const char *format_type_name(enum hsm_secret_type type)
{
	switch (type) {
	case HSM_SECRET_PLAIN:
		return "plain (32-byte binary)";
	case HSM_SECRET_ENCRYPTED:
		return "encrypted (73-byte binary)";
	case HSM_SECRET_MNEMONIC_NO_PASS:
		return "mnemonic (no password)";
	case HSM_SECRET_MNEMONIC_WITH_PASS:
		return "mnemonic (with password)";
	case HSM_SECRET_INVALID:
		return "invalid";
	}
	return "unknown";
}

u8 *grab_file_contents(const tal_t *ctx, const char *filename, size_t *len)
{
	u8 *contents = grab_file_raw(ctx, filename);
	if (len)
		*len = tal_bytelen(contents);

	return contents;
}

bool is_mnemonic_secret(size_t secret_len)
{
	return secret_len == HSM_SECRET_MNEMONIC_SIZE;
}

bool use_bip86_derivation(size_t secret_len)
{
	/* BIP86 was introduced alongside mnemonic support, so they're available together */
	return is_mnemonic_secret(secret_len);
}
