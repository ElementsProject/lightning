#include "config.h"
#include <ccan/err/err.h>
#include <ccan/fdpass/fdpass.h>
#include <common/ecdh.h>
#include <common/errcode.h>
#include <common/hsm_encryption.h>
#include <common/hsm_version.h>
#include <common/invoice_path_id.h>
#include <common/json_command.h>
#include <common/json_param.h>
#include <common/jsonrpc_errors.h>
#include <common/type_to_string.h>
#include <errno.h>
#include <hsmd/hsmd_wiregen.h>
#include <lightningd/hsm_control.h>
#include <lightningd/jsonrpc.h>
#include <lightningd/lightningd.h>
#include <lightningd/subd.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <wally_bip32.h>
#include <wire/wire_sync.h>

static int hsm_get_fd(struct lightningd *ld,
		      const struct node_id *id,
		      u64 dbid,
		      int capabilities)
{
	int hsm_fd;
	u8 *msg;

	msg = towire_hsmd_client_hsmfd(NULL, id, dbid, capabilities);
	if (!wire_sync_write(ld->hsm_fd, take(msg)))
		fatal("Could not write to HSM: %s", strerror(errno));

	msg = wire_sync_read(tmpctx, ld->hsm_fd);
	if (!fromwire_hsmd_client_hsmfd_reply(msg))
		fatal("Bad reply from HSM: %s", tal_hex(tmpctx, msg));

	hsm_fd = fdpass_recv(ld->hsm_fd);
	if (hsm_fd < 0)
		fatal("Could not read fd from HSM: %s", strerror(errno));
	return hsm_fd;
}

int hsm_get_client_fd(struct lightningd *ld,
		      const struct node_id *id,
		      u64 dbid,
		      int capabilities)
{
	assert(dbid);

	return hsm_get_fd(ld, id, dbid, capabilities);
}

int hsm_get_global_fd(struct lightningd *ld, int capabilities)
{
	return hsm_get_fd(ld, &ld->id, 0, capabilities);
}

static unsigned int hsm_msg(struct subd *hsmd,
			    const u8 *msg, const int *fds UNUSED)
{
	/* We only expect one thing from the HSM that's not a STATUS message */
	struct node_id client_id;
	u8 *bad_msg;
	char *desc;

	if (!fromwire_hsmstatus_client_bad_request(tmpctx, msg, &client_id,
						   &desc, &bad_msg))
		fatal("Bad status message from hsmd: %s", tal_hex(tmpctx, msg));

	/* This should, of course, never happen. */
	log_broken(hsmd->log, "client %s %s (request %s)",
		   type_to_string(tmpctx, struct node_id, &client_id),
		   desc, tal_hex(tmpctx, bad_msg));
	return 0;
}

struct ext_key *hsm_init(struct lightningd *ld)
{
	u8 *msg;
	int fds[2];
	struct ext_key *bip32_base;

	/* We actually send requests synchronously: only status is async. */
	if (socketpair(AF_LOCAL, SOCK_STREAM, 0, fds) != 0)
		err(EXITCODE_HSM_GENERIC_ERROR, "Could not create hsm socketpair");

	ld->hsm = new_global_subd(ld, "lightning_hsmd",
				  hsmd_wire_name,
				  hsm_msg,
				  take(&fds[1]), NULL);
	if (!ld->hsm)
		err(EXITCODE_HSM_GENERIC_ERROR, "Could not subd hsm");

	/* If hsm_secret is encrypted and the --encrypted-hsm startup option is
	 * not passed, don't let hsmd use the first 32 bytes of the cypher as the
	 * actual secret. */
	if (!ld->config.keypass) {
		if (is_hsm_secret_encrypted("hsm_secret") == 1)
			errx(EXITCODE_HSM_ERROR_IS_ENCRYPT, "hsm_secret is encrypted, you need to pass the "
			     "--encrypted-hsm startup option.");
	}

	ld->hsm_fd = fds[0];
	if (!wire_sync_write(ld->hsm_fd, towire_hsmd_init(tmpctx,
							 &chainparams->bip32_key_version,
							 chainparams,
							 ld->config.keypass,
							 IFDEV(ld->dev_force_privkey, NULL),
							 IFDEV(ld->dev_force_bip32_seed, NULL),
							 IFDEV(ld->dev_force_channel_secrets, NULL),
							  IFDEV(ld->dev_force_channel_secrets_shaseed, NULL),
							  HSM_MIN_VERSION,
							  HSM_MAX_VERSION)))
		err(EXITCODE_HSM_GENERIC_ERROR, "Writing init msg to hsm");

	bip32_base = tal(ld, struct ext_key);
	msg = wire_sync_read(tmpctx, ld->hsm_fd);
	if (!fromwire_hsmd_init_reply_v2(msg,
					 &ld->id, bip32_base,
					 &ld->bolt12_base)) {
		/* v1 had x-only pubkey */
		u8 pubkey32[33];
		/* And gave us a secret to use for onion_reply paths */
		struct secret onion_reply_secret;

		pubkey32[0] = SECP256K1_TAG_PUBKEY_EVEN;
		if (!fromwire_hsmd_init_reply_v1(msg,
					 &ld->id, bip32_base,
					 pubkey32 + 1,
					 &onion_reply_secret)) {
			if (ld->config.keypass)
				errx(EXITCODE_HSM_BAD_PASSWORD, "Wrong password for encrypted hsm_secret.");
			errx(EXITCODE_HSM_GENERIC_ERROR, "HSM did not give init reply");
		}
		if (!pubkey_from_der(pubkey32, sizeof(pubkey32),
				     &ld->bolt12_base))
			errx(EXITCODE_HSM_GENERIC_ERROR,
			     "HSM gave invalid v1 bolt12_base");
	}

	/* This is equivalent to makesecret("bolt12-invoice-base") */
	msg = towire_hsmd_derive_secret(NULL, tal_dup_arr(tmpctx, u8,
							  (const u8 *)INVOICE_PATH_BASE_STRING,
							  strlen(INVOICE_PATH_BASE_STRING), 0));
	if (!wire_sync_write(ld->hsm_fd, take(msg)))
		err(EXITCODE_HSM_GENERIC_ERROR, "Writing derive_secret msg to hsm");

	msg = wire_sync_read(tmpctx, ld->hsm_fd);
	if (!fromwire_hsmd_derive_secret_reply(msg, &ld->invoicesecret_base))
		err(EXITCODE_HSM_GENERIC_ERROR, "Bad derive_secret_reply");

	return bip32_base;
}

static struct command_result *json_makesecret(struct command *cmd,
					   const char *buffer,
					   const jsmntok_t *obj UNNEEDED,
					   const jsmntok_t *params)
{
	u8 *data;
	const char *strdata;
	struct json_stream *response;
	struct secret secret;

	if (!param(cmd, buffer, params,
		   p_opt("hex", param_bin_from_hex, &data),
		   p_opt("string", param_string, &strdata),
		   NULL))
		return command_param_failed();

	if (strdata) {
		if (data)
			return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
					    "Cannot have both hex and string");
		data = tal_dup_arr(cmd, u8, (u8 *)strdata, strlen(strdata), 0);
	} else {
		if (!data)
			return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
					    "Must have either hex or string");
	}


	u8 *msg = towire_hsmd_derive_secret(cmd, data);
	if (!wire_sync_write(cmd->ld->hsm_fd, take(msg)))
		return command_fail(cmd, LIGHTNINGD,
                     "Could not write to HSM: %s", strerror(errno));


	msg = wire_sync_read(tmpctx, cmd->ld->hsm_fd);
	if (!fromwire_hsmd_derive_secret_reply(msg, &secret))
		return command_fail(cmd, LIGHTNINGD,
                     "Bad reply from HSM: %s", strerror(errno));


	response = json_stream_success(cmd);
	json_add_secret(response, "secret", &secret);
	return command_success(cmd, response);
}

static const struct json_command makesecret_command = {
	"makesecret",
	"utility",
	&json_makesecret,
	"Get a pseudorandom secret key, using some {hex} data."
};
AUTODATA(json_command, &makesecret_command);
