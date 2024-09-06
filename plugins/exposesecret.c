#include "config.h"
#include <bitcoin/privkey.h>
#include <ccan/array_size/array_size.h>
#include <ccan/crypto/hkdf_sha256/hkdf_sha256.h>
#include <ccan/crypto/sha256/sha256.h>
#include <ccan/tal/grab_file/grab_file.h>
#include <ccan/tal/str/str.h>
#include <common/bech32.h>
#include <common/codex32.h>
#include <common/json_param.h>
#include <common/json_stream.h>
#include <errno.h>
#include <plugins/libplugin.h>

/* Information this plugin wants to keep. */
struct exposesecret {
	char *exposure_passphrase;
	struct pubkey our_node_id;
	const char *our_node_alias;
};

static struct exposesecret *exposesecret_data(struct plugin *plugin)
{
	return plugin_get_data(plugin, struct exposesecret);
}

/* Don't let compiler do clever things, which would allow the caller
 * to measure time, and figure out how much of the passphrase matched! */
static bool compare_passphrases(const char *a, const char *b)
{
	struct sha256 a_sha, b_sha;

	/* Technically, this gives information about passphrase length, but
	 * they can also just brute force it if it is small, so this doesn't
	 * add much!  Also, hashing messes with timing quite a bit. */
	sha256(&a_sha, a, strlen(a));
	sha256(&b_sha, b, strlen(b));

	return sha256_eq(&a_sha, &b_sha);
}

static struct command_result *json_exposesecret(struct command *cmd,
						const char *buffer,
						const jsmntok_t *params)
{
	const struct exposesecret *exposesecret = exposesecret_data(cmd->plugin);
	struct json_stream *js;
	u8 *contents;
	const char *id, *passphrase, *err;
	struct secret hsm_secret;
	struct privkey node_privkey;
	struct pubkey node_id;
	char *bip93;
	u32 salt = 0;

	if (!param_check(cmd, buffer, params,
			 p_req("passphrase", param_string, &passphrase),
			 p_opt("identifier", param_string, &id),
			 NULL))
		return command_param_failed();

	if (!exposesecret->exposure_passphrase)
		return command_fail(cmd, LIGHTNINGD, "exposesecrets-passphrase is not set");

	/* Technically, this could become a timing oracle. */
	if (!compare_passphrases(exposesecret->exposure_passphrase, passphrase))
		return command_fail(cmd, LIGHTNINGD, "passphrase does not match exposesecrets-passphrase");

	contents = grab_file(tmpctx, "hsm_secret");
	if (!contents)
		return command_fail(cmd, LIGHTNINGD, "Could not open hsm_secret: %s", strerror(errno));

	/* grab_file adds a \0 byte at the end for convenience */
	if (tal_bytelen(contents) == sizeof(hsm_secret) + 1) {
		memcpy(&hsm_secret, contents, sizeof(hsm_secret));
	} else {
		return command_fail(cmd, LIGHTNINGD, "Not a valid hsm_secret file?  Bad length (maybe encrypted?)");
	}

	/* Before we expose it, check it's correct! */
	hkdf_sha256(&node_privkey, sizeof(node_privkey),
		    &salt, sizeof(salt),
		    &hsm_secret,
		    sizeof(hsm_secret),
		    "nodeid", 6);

	/* Should not happen! */
	if (!pubkey_from_privkey(&node_privkey, &node_id))
		return command_fail(cmd, LIGHTNINGD, "Invalid private key?");

	if (!pubkey_eq(&node_id, &exposesecret->our_node_id))
		return command_fail(cmd, LIGHTNINGD, "This hsm_secret is not for the current node");

	/* If they didn't give an identifier, we make an appropriate one! */
	if (!id) {
		size_t off = 0;
		/* If we run out of alias, use x. */
		char idstr[] = "xxxx";

		for (size_t i = 0; idstr[off]; i++) {
			unsigned char c = exposesecret->our_node_alias[i];
			if (c == 0)
				break;
			if (c >= sizeof(bech32_charset_rev))
				continue;
			/* Convert to lower case */
 			c = tolower(c);
			/* Must be a valid bech32 char now */
			if (bech32_charset_rev[c] == -1)
				continue;
			idstr[off++] = c;
		}

		id = tal_strdup(cmd, idstr);
	}

	/* This also cannot fail! */
	err = codex32_secret_encode(tmpctx, "cl", id, 0, hsm_secret.data, 32, &bip93);
	if (err)
		return command_fail(cmd, LIGHTNINGD, "Unexpected failure encoding hsm_secret: %s", err);

	/* If we're just checking, stop */
	if (command_check_only(cmd))
		return command_check_done(cmd);

	js = jsonrpc_stream_success(cmd);
	json_add_string(js, "identifier", id);
	json_add_string(js, "codex32", bip93);
	return command_finished(cmd, js);
}

static const char *init(struct plugin *plugin,
			const char *buf UNUSED, const jsmntok_t *config UNUSED)
{
	struct exposesecret *exposesecret = exposesecret_data(plugin);
	rpc_scan(plugin, "getinfo",
		 take(json_out_obj(NULL, NULL, NULL)),
		 "{id:%,alias:%}",
		 JSON_SCAN(json_to_pubkey, &exposesecret->our_node_id),
		 JSON_SCAN_TAL(exposesecret, json_strdup, &exposesecret->our_node_alias));
	return NULL;
}

static const struct plugin_command commands[] = {
	{
		"exposesecret",
		json_exposesecret,
	}
};

int main(int argc, char *argv[])
{
	setup_locale();

	struct exposesecret *exposesecret = talz(NULL, struct exposesecret);
	plugin_main(argv, init, take(exposesecret),
		    PLUGIN_RESTARTABLE, true, NULL, commands, ARRAY_SIZE(commands),
	            NULL, 0, NULL, 0, NULL, 0,
		    plugin_option("exposesecret-passphrase", "string",
				  "Enable exposesecret command to allow HSM Secret backup, with this passphrase",
				  charp_option, NULL, &exposesecret->exposure_passphrase),
		    NULL);
}
