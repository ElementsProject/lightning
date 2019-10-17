#include <bitcoin/privkey.h>
#include <ccan/array_size/array_size.h>
#include <ccan/noerr/noerr.h>
#include <ccan/read_write_all/read_write_all.h>
#include <errno.h>
#include <fcntl.h>
#include <plugins/libplugin.h>
#include <sodium.h>
#include <sys/stat.h>
#include <unistd.h>


static void init(struct plugin_conn *rpc UNUSED,
                 const char *buffer UNUSED,
                 const jsmntok_t *config UNUSED)
{
	if (sodium_init() == -1)
		plugin_err("Could not initialize libsodium.");
	plugin_log(LOG_INFORM, "hsmtools initialized.");
}

static bool ensure_hsm_secret_exists(int fd)
{
	if (fsync(fd) != 0) {
		close(fd);
		return false;
	}
	if (close(fd) != 0)
		return false;

	fd = open(".", O_RDONLY);
	if (fd < 0)
		return false;
	if (fsync(fd) != 0) {
		close(fd);
		return false;
	}

	close(fd);
	return true;
}

static struct command_result *json_decrypt_hsm(struct command *cmd,
                                               const char *buffer,
                                               const jsmntok_t *params)
{
	int fd;
	const char *passwd;
	struct stat st;
	struct secret key, hsm_secret;
	u8 salt[16] = "c-lightning\0\0\0\0\0";
	crypto_secretstream_xchacha20poly1305_state crypto_state;
	u8 header[crypto_secretstream_xchacha20poly1305_HEADERBYTES];
	/* The cipher size is static with xchacha20poly1305. */
	u8 cipher[sizeof(struct secret) + crypto_secretstream_xchacha20poly1305_ABYTES];

	if (!param(cmd, buffer, params,
		   p_req("password", param_string, &passwd),
		   NULL))
		return command_param_failed();

	/* We can use a relative path as libplugin chdir into lightning_dir
	 * before calling us. */
	if (stat("hsm_secret", &st) != 0)
		return command_done_err(cmd, errno, "Could not stat hsm_secret", NULL);
	if (st.st_size <= 32)
		return command_done_err(cmd, errno, "hsm_secret is not encrypted", NULL);
	fd = open("hsm_secret", O_RDONLY);
	if (fd < 0)
		return command_done_err(cmd, errno, "Could not open hsm_secret", NULL);

	if (!read_all(fd, header, crypto_secretstream_xchacha20poly1305_HEADERBYTES))
		return command_done_err(cmd, PLUGIN_ERROR,
		                        "Could not read cipher header", NULL);
	if (!read_all(fd, cipher, sizeof(cipher)))
		return command_done_err(cmd, PLUGIN_ERROR,
		                        "Could not read cipher body", NULL);

	/* Derive the encryption key from the password provided, and try to decrypt
	 * the cipher. */
	if (crypto_pwhash(key.data, sizeof(key.data), passwd, strlen(passwd), salt,
	                  crypto_pwhash_argon2id_OPSLIMIT_MODERATE,
	                  crypto_pwhash_argon2id_MEMLIMIT_MODERATE,
	                  crypto_pwhash_ALG_ARGON2ID13) != 0)
		return command_done_err(cmd, PLUGIN_ERROR,
		                        "Could not derive a key from the password.", NULL);
	if (crypto_secretstream_xchacha20poly1305_init_pull(&crypto_state, header,
	                                                    key.data) != 0)
		return command_done_err(cmd, PLUGIN_ERROR,
		                        "Could not initialize the crypto state", NULL);
	if (crypto_secretstream_xchacha20poly1305_pull(&crypto_state, hsm_secret.data,
	                                               NULL, 0, cipher, sizeof(cipher),
	                                               NULL, 0) != 0)
		return command_done_err(cmd, PLUGIN_ERROR,
		                        "Could not retrieve the seed. Wrong password ?", NULL);
	close(fd);

	/* Create a backup file, "just in case". */
	rename("hsm_secret", "hsm_secret.backup");
	fd = open("hsm_secret", O_CREAT|O_EXCL|O_WRONLY, 0400);
	if (fd < 0)
		return command_done_err(cmd, errno, "Could not open new hsm_secret", NULL);

	if (!write_all(fd, &hsm_secret, sizeof(hsm_secret))) {
		unlink_noerr("hsm_secret");
		close(fd);
		rename("hsm_secret.backup", "hsm_secret");
		return command_done_err(cmd, errno,
		                        "Failure writing plaintext seed to hsm_secret.",
		                        NULL);
	}

	/* Be as paranoïd as in hsmd with the file state on disk. */
	if (!ensure_hsm_secret_exists(fd)) {
		unlink_noerr("hsm_secret");
		rename("hsm_secret.backup", "hsm_secret");
		return command_done_err(cmd, errno,
		                        "Could not ensure hsm_secret existence.", NULL);
	}
	unlink_noerr("hsm_secret.backup");

	return command_success_str(cmd, "Succesfully decrypted hsm_secret, be "
	                                "careful now.");
}


static struct command_result *json_encrypt_hsm(struct command *cmd,
                                               const char *buffer,
                                               const jsmntok_t *params)
{
	int fd;
	const char *passwd;
	struct stat st;
	struct secret key, hsm_secret;
	u8 salt[16] = "c-lightning\0\0\0\0\0";
	crypto_secretstream_xchacha20poly1305_state crypto_state;
	u8 header[crypto_secretstream_xchacha20poly1305_HEADERBYTES];
	/* The cipher size is static with xchacha20poly1305. */
	u8 cipher[sizeof(struct secret) + crypto_secretstream_xchacha20poly1305_ABYTES];

	if (!param(cmd, buffer, params,
		   p_req("password", param_string, &passwd),
		   NULL))
		return command_param_failed();

	/* We can use a relative path as libplugin chdir into lightning_dir
	 * before calling us. */
	if (stat("hsm_secret", &st) != 0)
		return command_done_err(cmd, errno, "Could not stat hsm_secret", NULL);
	if (st.st_size > 32)
		return command_done_err(cmd, errno, "hsm_secret is already encrypted", NULL);
	fd = open("hsm_secret", O_RDONLY);
	if (fd < 0)
		return command_done_err(cmd, errno, "Could not open hsm_secret", NULL);
	if (!read_all(fd, &hsm_secret, sizeof(hsm_secret)))
		return command_done_err(cmd, errno, "Could not read hsm_secret", NULL);

	/* Derive the encryption key from the password provided, and try to encrypt
	 * the seed. */
	if (crypto_pwhash(key.data, sizeof(key.data), passwd, strlen(passwd), salt,
	                  crypto_pwhash_argon2id_OPSLIMIT_MODERATE,
	                  crypto_pwhash_argon2id_MEMLIMIT_MODERATE,
	                  crypto_pwhash_ALG_ARGON2ID13) != 0)
		return command_done_err(cmd, PLUGIN_ERROR,
		                        "Could not derive a key from the password.", NULL);
	if (crypto_secretstream_xchacha20poly1305_init_push(&crypto_state, header,
	                                                    key.data) != 0)
		return command_done_err(cmd, PLUGIN_ERROR,
		                        "Could not initialize the crypto state", NULL);
	if (crypto_secretstream_xchacha20poly1305_push(&crypto_state, cipher,
	                                               NULL, hsm_secret.data,
	                                               sizeof(hsm_secret.data),
	                                               NULL, 0, 0) != 0)
		return command_done_err(cmd, PLUGIN_ERROR,
		                        "Could not encrypt the seed.", NULL);

	/* Create a backup file, "just in case". */
	rename("hsm_secret", "hsm_secret.backup");
	fd = open("hsm_secret", O_CREAT|O_EXCL|O_WRONLY, 0400);
	if (fd < 0)
		return command_done_err(cmd, errno,
		                        "Could not open new hsm_secret", NULL);

	/* Write the encrypted hsm_secret. */
	if (!write_all(fd, header, sizeof(header))
		|| !write_all(fd, cipher, sizeof(cipher))) {
		unlink_noerr("hsm_secret");
		close(fd);
		rename("hsm_secret.backup", "hsm_secret");
		return command_done_err(cmd, errno,
		                        "Failure writing cipher to hsm_secret.", NULL);
	}
	if (!write_all(fd, cipher, sizeof(cipher))) {
		unlink_noerr("hsm_secret");
		close(fd);
		rename("hsm_secret.backup", "hsm_secret");
		return command_done_err(cmd, errno,
		                        "Failure writing cipher to hsm_secret.", NULL);
	}

	/* Be as paranoïd as in hsmd with the file state on disk. */
	if (!ensure_hsm_secret_exists(fd)) {
		unlink_noerr("hsm_secret");
		rename("hsm_secret.backup", "hsm_secret");
		return command_done_err(cmd, errno,
		                        "Could not ensure hsm_secret existence.", NULL);
	}
	unlink_noerr("hsm_secret.backup");

	return command_success_str(cmd,
	                           "Succesfully encrypted hsm_secret. You'll now "
	                           "have to pass the --encrypted-hsm startup "
	                           "option.");
}

static const struct plugin_command commands[] = {
	{
		"decrypthsm",
		"utility",
		"Decrypt an encrypted hsm_secret.",
		"Decrypt the seed used to derive the HD wallet master seed stored in"
		" hsm_secret, previously encrypted using {password}.",
		json_decrypt_hsm
	},
	{
		"encrypthsm",
		"utility",
		"Encrypt hsm_secret content.",
		"Encrypt the seed used to derive the HD wallet master seed (what is stored in hsm_secret)"
		" with {password}.",
		json_encrypt_hsm
	}
};

int main(int argc, char *argv[])
{
	setup_locale();
	plugin_main(argv, init, PLUGIN_RESTARTABLE, commands, ARRAY_SIZE(commands), NULL);
}
