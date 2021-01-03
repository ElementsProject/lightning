#include <common/hsm_encryption.h>
#include <sodium.h>
#include <sodium/utils.h>


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

void discard_key(struct secret *key TAKES)
{
	/* sodium_munlock() also zeroes the memory. */
	sodium_munlock(key->data, sizeof(key->data));
	if (taken(key))
		tal_free(key);
}
