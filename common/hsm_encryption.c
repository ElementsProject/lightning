#include <ccan/tal/str/str.h>
#include <common/hsm_encryption.h>
#include <sodium/utils.h>
#include <termios.h>

char *hsm_secret_encryption_key(const char *pass, struct secret *key)
{
	u8 salt[16] = "c-lightning\0\0\0\0\0";

	/* Don't swap the encryption key ! */
	if (sodium_mlock(key->data, sizeof(key->data)) != 0)
		return "Could not lock hsm_secret encryption key memory.";

	/* Check bounds. */
	if (strlen(pass) < crypto_pwhash_argon2id_PASSWD_MIN)
		return "Password too short to be able to derive a key from it.";
	if (strlen(pass) > crypto_pwhash_argon2id_PASSWD_MAX)
		return "Password too long to be able to derive a key from it.";

	/* Now derive the key. */
	if (crypto_pwhash(key->data, sizeof(key->data), pass, strlen(pass), salt,
			  /* INTERACTIVE needs 64 MiB of RAM, MODERATE needs 256,
			   * and SENSITIVE needs 1024. */
			  crypto_pwhash_argon2id_OPSLIMIT_MODERATE,
			  crypto_pwhash_argon2id_MEMLIMIT_MODERATE,
			  crypto_pwhash_ALG_ARGON2ID13) != 0)
		return "Could not derive a key from the password.";

	return NULL;
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

void discard_key(struct secret *key TAKES)
{
	/* sodium_munlock() also zeroes the memory. */
	sodium_munlock(key->data, sizeof(key->data));
	if (taken(key))
		tal_free(key);
}

char *read_stdin_pass(char **reason)
{
	struct termios current_term, temp_term;
	char *passwd = NULL;
	size_t passwd_size = 0;

	/* Set a temporary term, same as current but with ECHO disabled. */
	if (tcgetattr(fileno(stdin), &current_term) != 0) {
		*reason = "Could not get current terminal options.";
		return NULL;
	}
	temp_term = current_term;
	temp_term.c_lflag &= ~ECHO;
	if (tcsetattr(fileno(stdin), TCSAFLUSH, &temp_term) != 0) {
		*reason = "Could not disable pass echoing.";
		return NULL;
	}

	/* Read the password, do not take the newline character into account. */
	if (getline(&passwd, &passwd_size, stdin) < 0) {
		*reason = "Could not read pass from stdin.";
		return NULL;
	}
	if (passwd[strlen(passwd) - 1] == '\n')
		passwd[strlen(passwd) - 1] = '\0';

	/* Restore the original terminal */
	if (tcsetattr(fileno(stdin), TCSAFLUSH, &current_term) != 0) {
		*reason = "Could not restore terminal options.";
		free(passwd);
		return NULL;
	}

	return passwd;
}
