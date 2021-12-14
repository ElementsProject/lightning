#include "config.h"
#include <common/errcode.h>
#include <common/hsm_encryption.h>
#include <termios.h>
#include <unistd.h>

int hsm_secret_encryption_key_with_exitcode(const char *pass, struct secret *key,
					      char **err_msg)
{
	u8 salt[16] = "c-lightning\0\0\0\0\0";

	/* Don't swap the encryption key ! */
	if (sodium_mlock(key->data, sizeof(key->data)) != 0) {
		*err_msg = "Could not lock hsm_secret encryption key memory.";
		return HSM_GENERIC_ERROR;
	}

	/* Check bounds. */
	if (strlen(pass) < crypto_pwhash_argon2id_PASSWD_MIN) {
		*err_msg = "Password too short to be able to derive a key from it.";
		return HSM_BAD_PASSWORD;
	} else if (strlen(pass) > crypto_pwhash_argon2id_PASSWD_MAX) {
		*err_msg = "Password too long to be able to derive a key from it.";
		return HSM_BAD_PASSWORD;
	}

	/* Now derive the key. */
	if (crypto_pwhash(key->data, sizeof(key->data), pass, strlen(pass), salt,
			  /* INTERACTIVE needs 64 MiB of RAM, MODERATE needs 256,
			   * and SENSITIVE needs 1024. */
			  crypto_pwhash_argon2id_OPSLIMIT_MODERATE,
			  crypto_pwhash_argon2id_MEMLIMIT_MODERATE,
			  crypto_pwhash_ALG_ARGON2ID13) != 0) {
		*err_msg = "Could not derive a key from the password.";
		return HSM_BAD_PASSWORD;
	}

	return 0;
}

bool encrypt_hsm_secret(const struct secret *encryption_key,
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

bool decrypt_hsm_secret(const struct secret *encryption_key,
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

void discard_key(struct secret *key TAKES)
{
	/* sodium_munlock() also zeroes the memory. */
	sodium_munlock(key->data, sizeof(key->data));
	if (taken(key))
		tal_free(key);
}

/* Read a line from stdin, do not take the newline character into account. */
static bool getline_stdin_pass(char **passwd, size_t *passwd_size)
{
	if (getline(passwd, passwd_size, stdin) < 0)
		return false;

	if ((*passwd)[strlen(*passwd) - 1] == '\n')
		(*passwd)[strlen(*passwd) - 1] = '\0';

	return true;
}

char *read_stdin_pass_with_exit_code(char **reason, int *exit_code)
{
	struct termios current_term, temp_term;
	char *passwd = NULL;
	size_t passwd_size = 0;

	if (isatty(fileno(stdin))) {
		/* Set a temporary term, same as current but with ECHO disabled. */
		if (tcgetattr(fileno(stdin), &current_term) != 0) {
			*reason = "Could not get current terminal options.";
			*exit_code = HSM_PASSWORD_INPUT_ERR;
			return NULL;
		}
		temp_term = current_term;
		temp_term.c_lflag &= ~ECHO;
		if (tcsetattr(fileno(stdin), TCSANOW, &temp_term) != 0) {
			*reason = "Could not disable pass echoing.";
			*exit_code = HSM_PASSWORD_INPUT_ERR;
			return NULL;
		}

		if (!getline_stdin_pass(&passwd, &passwd_size)) {
			*reason = "Could not read pass from stdin.";
			*exit_code = HSM_PASSWORD_INPUT_ERR;
			return NULL;
		}

		/* Restore the original terminal */
		if (tcsetattr(fileno(stdin), TCSANOW, &current_term) != 0) {
			*reason = "Could not restore terminal options.";
			free(passwd);
			*exit_code = HSM_PASSWORD_INPUT_ERR;
			return NULL;
		}
	} else if (!getline_stdin_pass(&passwd, &passwd_size)) {
		*reason = "Could not read pass from stdin.";
		*exit_code = HSM_PASSWORD_INPUT_ERR;
		return NULL;
	}
	return passwd;
}
