#include "config.h"
#include <ccan/err/err.h>
#include <ccan/fdpass/fdpass.h>
#include <ccan/tal/str/str.h>
#include <common/bolt12_id.h>
#include <common/errcode.h>
#include <common/hsm_capable.h>
#include <common/hsm_secret.h>
#include <common/hsm_version.h>
#include <common/json_command.h>
#include <errno.h>
#include <hsmd/hsmd_wiregen.h>
#include <lightningd/hsm_control.h>
#include <lightningd/jsonrpc.h>
#include <lightningd/lightningd.h>
#include <lightningd/subd.h>
#include <wally_bip32.h>
#include <wire/wire_sync.h>

static int hsm_get_fd(struct lightningd *ld,
		      const struct node_id *id,
		      u64 dbid,
		      u64 permissions)
{
	const u8 *msg;

	msg = towire_hsmd_client_hsmfd(NULL, id, dbid, permissions);
	msg = hsm_sync_req(tmpctx, ld, take(msg));
	if (!fromwire_hsmd_client_hsmfd_reply(msg))
		fatal("Bad reply from HSM: %s", tal_hex(tmpctx, msg));

	return fdpass_recv(ld->hsm_fd);
}

int hsm_get_client_fd(struct lightningd *ld,
		      const struct node_id *id,
		      u64 dbid,
		      u64 permissions)
{
	assert(dbid);

	return hsm_get_fd(ld, id, dbid, permissions);
}

int hsm_get_global_fd(struct lightningd *ld, u64 permissions)
{
	int fd = hsm_get_fd(ld, &ld->our_nodeid, 0, permissions);

	if (fd < 0)
		fatal("Could not read fd from HSM: %s", strerror(errno));
	return fd;
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
		   fmt_node_id(tmpctx, &client_id),
		   desc, tal_hex(tmpctx, bad_msg));
	return 0;
}

/* Is this capability supported by the HSM? (So far, always a message
 * number) */
bool hsm_capable(struct lightningd *ld, u32 msgtype)
{
	return hsm_is_capable(ld->hsm_capabilities, msgtype);
}

struct ext_key *hsm_init(struct lightningd *ld)
{
	u8 *msg;
	int fds[2];
	struct ext_key *bip32_base;
	u32 hsm_version;
	struct pubkey unused;

	/* We actually send requests synchronously: only status is async. */
	if (socketpair(AF_LOCAL, SOCK_STREAM, 0, fds) != 0)
		err(EXITCODE_HSM_GENERIC_ERROR, "Could not create hsm socketpair");

	ld->hsm = new_global_subd(ld, "lightning_hsmd",
				  hsmd_wire_name,
				  hsm_msg,
				  take(&fds[1]), NULL);
	if (!ld->hsm)
		err(EXITCODE_HSM_GENERIC_ERROR, "Could not subd hsm");

	ld->hsm_fd = fds[0];

	if (ld->developer) {
		struct tlv_hsmd_dev_preinit_tlvs *tlv;

		tlv = tlv_hsmd_dev_preinit_tlvs_new(tmpctx);
		tlv->fail_preapprove = tal_dup(tlv, bool,
					       &ld->dev_hsmd_fail_preapprove);
		tlv->no_preapprove_check = tal_dup(tlv, bool,
						   &ld->dev_hsmd_no_preapprove_check);
		tlv->warn_on_overgrind = tal_dup(tlv, bool,
						 &ld->dev_hsmd_warn_on_overgrind);

		msg = towire_hsmd_dev_preinit(tmpctx, tlv);
		if (!wire_sync_write(ld->hsm_fd, msg))
		    err(EXITCODE_HSM_GENERIC_ERROR, "Writing preinit msg to hsm");
	}

	/* Create TLV for passphrase if needed */
	struct tlv_hsmd_init_tlvs *tlv = NULL;
	if (ld->hsm_passphrase) {
		tlv = tlv_hsmd_init_tlvs_new(tmpctx);
		tlv->hsm_passphrase = tal_strdup(tlv, ld->hsm_passphrase);
	}

	if (!wire_sync_write(ld->hsm_fd, towire_hsmd_init(tmpctx,
							  &chainparams->bip32_key_version,
							  chainparams,
							  NULL,
							  ld->dev_force_privkey,
							  ld->dev_force_bip32_seed,
							  ld->dev_force_channel_secrets,
							  ld->dev_force_channel_secrets_shaseed,
							  HSM_MIN_VERSION,
							  HSM_MAX_VERSION,
							  tlv)))
		err(EXITCODE_HSM_GENERIC_ERROR, "Writing init msg to hsm");

	bip32_base = tal(ld, struct ext_key);
	msg = wire_sync_read(tmpctx, ld->hsm_fd);

	/* Check for init reply failure first */
	u32 error_code;
	char *error_message;
	if (fromwire_hsmd_init_reply_failure(tmpctx, msg, &error_code, &error_message)) {
		/* HSM initialization failed: tell user the error (particularly to give feedback if it's a bad passphrase! */
		errx(error_code, "HSM initialization failed: %s", error_message);
	}

	/* Check for successful init reply */
	if (fromwire_hsmd_init_reply_v4(ld, msg,
					&hsm_version,
					&ld->hsm_capabilities,
					&ld->our_nodeid, bip32_base,
					&unused)) {
		/* nothing to do. */
	} else {
		/* Unknown message type */
		errx(EXITCODE_HSM_GENERIC_ERROR, "HSM sent unknown message type");
	}

	if (!pubkey_from_node_id(&ld->our_pubkey, &ld->our_nodeid))
		errx(EXITCODE_HSM_GENERIC_ERROR, "HSM gave invalid node id %s",
		     fmt_node_id(tmpctx, &ld->our_nodeid));

	if (hsm_version < HSM_MIN_VERSION)
		errx(EXITCODE_HSM_GENERIC_ERROR,
		     "HSM version %u below minimum %u",
		     hsm_version, HSM_MIN_VERSION);
	if (hsm_version > HSM_MAX_VERSION)
		errx(EXITCODE_HSM_GENERIC_ERROR,
		     "HSM version %u above maximum %u",
		     hsm_version, HSM_MAX_VERSION);

	/* Debugging help */
	for (size_t i = 0; i < tal_count(ld->hsm_capabilities); i++) {
		log_debug(ld->hsm->log, "capability +%s",
			  hsmd_wire_name(ld->hsm_capabilities[i]));
	}

	if (feature_offered(ld->our_features->bits[INIT_FEATURE],
			    OPT_ANCHORS_ZERO_FEE_HTLC_TX)
	    && !hsm_capable(ld, WIRE_HSMD_SIGN_ANCHORSPEND)) {
		fatal("anchors needs HSM capable of signing anchors!");
	}

	if (feature_offered(ld->our_features->bits[INIT_FEATURE],
			    OPT_SPLICE)
	    && !hsm_capable(ld, WIRE_HSMD_SIGN_SPLICE_TX)) {
		fatal("--experimental-splicing needs HSM capable of signing splices!");
	}

	/* Try to get BIP86 base key from HSM (works only for mnemonic secrets) */
	ld->bip86_base = tal(ld, struct ext_key);
	msg = towire_hsmd_derive_bip86_key(NULL, 0, false);
	const u8 *reply = hsm_sync_req(tmpctx, ld, take(msg));
	if (fromwire_hsmd_derive_bip86_key_reply(reply, ld->bip86_base)) {
		/* BIP86 derivation succeeded - we have a mnemonic-based secret */
		log_info(ld->log, "Using BIP86 for new addresses, BIP32 for channels (mnemonic HSM secret)");
		/* Keep bip32_base for channel operations, database, etc. */
	} else {
		/* BIP86 derivation failed - we have a legacy secret */
		log_info(ld->log, "Using BIP32 derivation for all operations (legacy HSM secret)");
		ld->bip86_base = tal_free(ld->bip86_base);
		/* bip32_base was already set by the HSM init reply */
	}

	/* This is equivalent to makesecret("bolt12-invoice-base") */
	msg = towire_hsmd_derive_secret(NULL, tal_dup_arr(tmpctx, u8,
							  (const u8 *)BOLT12_ID_BASE_STRING,
							  strlen(BOLT12_ID_BASE_STRING), 0));
	if (!wire_sync_write(ld->hsm_fd, take(msg)))
		err(EXITCODE_HSM_GENERIC_ERROR, "Writing derive_secret msg to hsm");

	msg = wire_sync_read(tmpctx, ld->hsm_fd);
	if (!fromwire_hsmd_derive_secret_reply(msg, &ld->invoicesecret_base))
		err(EXITCODE_HSM_GENERIC_ERROR, "Bad derive_secret_reply");

	/* This is equivalent to makesecret("node-alias-base") */
	msg = towire_hsmd_derive_secret(NULL, tal_dup_arr(tmpctx, u8,
							  (const u8 *)NODE_ALIAS_BASE_STRING,
							  strlen(NODE_ALIAS_BASE_STRING), 0));
	if (!wire_sync_write(ld->hsm_fd, take(msg)))
		err(EXITCODE_HSM_GENERIC_ERROR, "Writing derive_secret msg to hsm");

	msg = wire_sync_read(tmpctx, ld->hsm_fd);
	if (!fromwire_hsmd_derive_secret_reply(msg, &ld->nodealias_base))
		err(EXITCODE_HSM_GENERIC_ERROR, "Bad derive_secret_reply");

	return bip32_base;
}

/*~ There was a nasty LND bug report where the user issued an address which it
 * couldn't spend, presumably due to a bitflip.  We check every address using our
 * hsm, to be sure it's valid.  Expensive, but not as expensive as losing BTC! */
/* Verify a derived public key with the HSM */

/*~ There was a nasty LND bug report where the user issued an address which it
 * couldn't spend, presumably due to a bitflip.  We check every address using our
 * hsm, to be sure it's valid.  Expensive, but not as expensive as losing BTC! */
void bip32_pubkey(struct lightningd *ld, struct pubkey *pubkey, u32 index)
{
	const uint32_t flags = BIP32_FLAG_KEY_PUBLIC | BIP32_FLAG_SKIP_HASH;
	struct ext_key ext;

	if (index >= BIP32_INITIAL_HARDENED_CHILD)
		fatal("Can't derive key %u (too large!)", index);

	if (bip32_key_from_parent(ld->bip32_base, index, flags, &ext) != WALLY_OK)
		fatal("Can't derive key %u", index);

	if (!secp256k1_ec_pubkey_parse(secp256k1_ctx, &pubkey->pubkey,
				       ext.pub_key, sizeof(ext.pub_key)))
		fatal("Can't parse derived key %u", index);

	/* Don't assume hsmd supports it! */
	if (hsm_capable(ld, WIRE_HSMD_CHECK_PUBKEY)) {
		bool ok;
		const u8 *msg = towire_hsmd_check_pubkey(NULL, index, pubkey);
		msg = hsm_sync_req(tmpctx, ld, take(msg));
		if (!fromwire_hsmd_check_pubkey_reply(msg, &ok))
			fatal("Invalid check_pubkey_reply from hsm");

		if (!ok)
			fatal("HSM said key derivation of %u != %s",
			      index, fmt_pubkey(tmpctx, pubkey));
	}
}

/* Derive BIP86 public key from the base key */
void bip86_pubkey(struct lightningd *ld, struct pubkey *pubkey, u32 index)
{
	const uint32_t flags = BIP32_FLAG_KEY_PUBLIC | BIP32_FLAG_SKIP_HASH;
	struct ext_key ext;
	u32 path[2];

	if (index >= BIP32_INITIAL_HARDENED_CHILD)
		fatal("Can't derive key %u (too large!)", index);

	/* BIP86 path: m/86'/0'/0'/0/index */
	path[0] = 0; /* change (0 for receive) */
	path[1] = index; /* address_index */

	assert(ld->bip86_base != NULL);

	if (bip32_key_from_parent_path(ld->bip86_base, path, 2, flags, &ext) != WALLY_OK)
		fatal("Can't derive key %u", index);

	if (!secp256k1_ec_pubkey_parse(secp256k1_ctx, &pubkey->pubkey,
				       ext.pub_key, sizeof(ext.pub_key)))
		fatal("Can't parse derived key %u", index);

	/* Don't assume hsmd supports it! */
	if (hsm_capable(ld, WIRE_HSMD_CHECK_BIP86_PUBKEY)) {
		bool ok;
		const u8 *msg = towire_hsmd_check_bip86_pubkey(NULL, index, pubkey);
		msg = hsm_sync_req(tmpctx, ld, take(msg));
		if (!fromwire_hsmd_check_bip86_pubkey_reply(msg, &ok))
			fatal("Invalid check_bip86_pubkey_reply from hsm");

		if (!ok)
			fatal("HSM said BIP86 key derivation of %u != %s",
			      index, fmt_pubkey(tmpctx, pubkey));
	}
}

const u8 *hsm_sync_req(const tal_t *ctx, struct lightningd *ld, const u8 *msg)
{
	int type = fromwire_peektype(msg);
	if (!wire_sync_write(ld->hsm_fd, msg))
		fatal("Writing %s hsm", hsmd_wire_name(type));
	msg = wire_sync_read(ctx, ld->hsm_fd);
	if (!msg)
		fatal("EOF reading from HSM after %s",
		      hsmd_wire_name(type));
	return msg;
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

	if (!param_check(cmd, buffer, params,
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

	if (command_check_only(cmd))
		return command_check_done(cmd);

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
	&json_makesecret,
};
AUTODATA(json_command, &makesecret_command);
