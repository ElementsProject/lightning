#include "config.h"
#include <common/bech32.h>
#include <common/configdir.h>
#include <common/json_command.h>
#include <common/json_param.h>
#include <errno.h>
#include <hsmd/hsmd_wiregen.h>
#include <lightningd/hsm_control.h>
#include <lightningd/plugin.h>

/* These tables copied from zbase32 src:
 * copyright 2002-2007 Zooko "Zooko" Wilcox-O'Hearn
 * mailto:zooko@zooko.com
 *
 * Permission is hereby granted to any person obtaining a copy of this work to
 * deal in this work without restriction (including the rights to use, modify,
 * distribute, sublicense, and/or sell copies).
 */
static const char*const zbase32_chars="ybndrfg8ejkmcpqxot1uwisza345h769";

/* revchars: index into this table with the ASCII value of the char.  The result is the value of that quintet. */
static const u8 zbase32_revchars[]={ 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 18, 255, 25, 26, 27, 30, 29, 7, 31, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 24, 1, 12, 3, 8, 5, 6, 28, 21, 9, 10, 255, 11, 2, 16, 13, 14, 4, 22, 17, 19, 255, 20, 15, 0, 23, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, };

static const char *to_zbase32(const tal_t *ctx, const u8 *msg, size_t srclen)
{
	size_t outlen;
	char *out = tal_arr(ctx, char, (srclen * 8 + 4) / 5 + 1);

	outlen = 0;
	if (!bech32_convert_bits((uint8_t *)out, &outlen, 5, msg, srclen, 8, true))
		return tal_free(out);
	assert(outlen < tal_bytelen(out));
	for (size_t i = 0; i < outlen; i++)
		out[i] = zbase32_chars[(unsigned)out[i]];
	out[outlen] = '\0';
	return out;
}

static const u8 *from_zbase32(const tal_t *ctx, const char *msg)
{
	u5 *u5arr;
	u8 *u8arr;
	size_t len;

	u5arr = tal_arr(tmpctx, u5, strlen(msg));
	for (size_t i = 0; i < tal_bytelen(u5arr); i++) {
		u5arr[i] = zbase32_revchars[(unsigned char)msg[i]];
		if (u5arr[i] > 31)
			return NULL;
	}

	u8arr = tal_arr(ctx, u8, (tal_bytelen(u5arr) * 5 + 7) / 8);
	len = 0;
	if (!bech32_convert_bits(u8arr, &len, 8,
				 u5arr, tal_bytelen(u5arr), 5, false))
		return tal_free(u8arr);
	return len == tal_bytelen(u8arr) ? u8arr : tal_free(u8arr);
}

static struct command_result *json_signmessage(struct command *cmd,
					       const char *buffer,
					       const jsmntok_t *obj UNNEEDED,
					       const jsmntok_t *params)
{
	const char *message;
	secp256k1_ecdsa_recoverable_signature rsig;
	struct json_stream *response;
	u8 sig[65];
	const u8 *msg;
	int recid;

	if (!param_check(cmd, buffer, params,
			 p_req("message", param_string, &message),
			 NULL))
		return command_param_failed();

	if (strlen(message) > 65535)
		return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
				    "Message must be < 64k");

	if (command_check_only(cmd))
		return command_check_done(cmd);

	msg = towire_hsmd_sign_message(NULL,
				      tal_dup_arr(tmpctx, u8, (u8 *)message,
						  strlen(message), 0));
	msg = hsm_sync_req(tmpctx, cmd->ld, take(msg));
	if (!fromwire_hsmd_sign_message_reply(msg, &rsig))
		fatal("HSM gave bad hsm_sign_message_reply %s",
		      tal_hex(msg, msg));

	secp256k1_ecdsa_recoverable_signature_serialize_compact(secp256k1_ctx,
								sig+1, &recid,
								&rsig);
	response = json_stream_success(cmd);
	json_add_hex(response, "signature", sig+1, sizeof(sig)-1);
	sig[0] = recid;
	json_add_hex(response, "recid", sig, 1);

	/* From https://twitter.com/rusty_twit/status/1182102005914800128:
	 * @roasbeef & @bitconner point out that #lnd algo is:
	 *   zbase32(SigRec(SHA256(SHA256("Lightning Signed Message:" + msg)))).
	 * zbase32 from https://philzimmermann.com/docs/human-oriented-base-32-encoding.txt
	 * and SigRec has first byte 31 + recovery id, followed by 64 byte sig.
	 * #specinatweet */
	sig[0] += 31;
	json_add_string(response, "zbase",
			to_zbase32(response, sig, sizeof(sig)));
	return command_success(cmd, response);
}

static const struct json_command json_signmessage_cmd = {
	"signmessage",
	json_signmessage,
	"Create a digital signature of {message}",
};
AUTODATA(json_command, &json_signmessage_cmd);

struct command_and_node {
	struct command *cmd;
	struct node_id id;
};

/* topology tells us if it's a known node by returning details. */
static void listnodes_done(const char *buffer,
			   const jsmntok_t *toks,
			   const jsmntok_t *idtok UNUSED,
			   struct command_and_node *can)
{
	struct json_stream *response;
	const jsmntok_t *t;

	t = json_get_member(buffer, toks, "result");
	if (t)
		t = json_get_member(buffer, t, "nodes");

	if (!t || t->size == 0) {
		response = json_stream_fail(can->cmd,
					    SIGNMESSAGE_PUBKEY_NOT_FOUND,
					    "pubkey not found in the graph");
		json_add_node_id(response, "claimed_key", &can->id);
		json_object_end(response);
		was_pending(command_failed(can->cmd, response));
		return;
	}
	response = json_stream_success(can->cmd);
	json_add_node_id(response, "pubkey", &can->id);
	json_add_bool(response, "verified", t && t->size == 1);
	was_pending(command_success(can->cmd, response));
}

static struct command_result *json_checkmessage(struct command *cmd,
						const char *buffer,
						const jsmntok_t *obj UNNEEDED,
						const jsmntok_t *params)
{
	struct pubkey *pubkey, reckey;
	const u8 *u8sig;
	const char *message, *zb;
	secp256k1_ecdsa_recoverable_signature rsig;
	struct sha256_ctx sctx = SHA256_INIT;
	struct sha256_double shad;
	struct json_stream *response;

	if (!param_check(cmd, buffer, params,
			 p_req("message", param_string, &message),
			 p_req("zbase", param_string, &zb),
			 p_opt("pubkey", param_pubkey, &pubkey),
		   NULL))
		return command_param_failed();

	u8sig = from_zbase32(tmpctx, zb);
	if (!u8sig)
		return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
				    "zbase is not valid zbase32");

	if (tal_bytelen(u8sig) != 65)
		return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
				    "zbase is too %s",
				    tal_bytelen(u8sig) < 65 ? "short" : "long");

	if (!secp256k1_ecdsa_recoverable_signature_parse_compact(secp256k1_ctx,
								 &rsig,
								 u8sig + 1,
								 u8sig[0] - 31))
		return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
				    "cannot parse zbase signature");

	if (command_check_only(cmd))
		return command_check_done(cmd);

	sha256_update(&sctx, "Lightning Signed Message:",
		      strlen("Lightning Signed Message:"));
	sha256_update(&sctx, message, strlen(message));
	sha256_double_done(&sctx, &shad);

	if (!secp256k1_ecdsa_recover(secp256k1_ctx, &reckey.pubkey, &rsig,
				     shad.sha.u.u8)) {
		response = json_stream_success(cmd);
		json_add_bool(response, "verified", false);
		return command_success(cmd, response);
	}

	/* If they didn't specify pubkey, we only accept the signature if it's
	 * in the graph (thus, they've signed something with it).  This idea
	 * was stolen directly from lnd, thanks @roasbeef.
	 *
	 * FIXME: We could also look through known invoices: AFAICT you can't
	 * make two (different) signed messages with the same recovered key
	 * unless you know the secret key */
	if (!pubkey) {
		struct jsonrpc_request *req;
		struct plugin *plugin;
		struct command_and_node *can = tal(cmd, struct command_and_node);

		node_id_from_pubkey(&can->id, &reckey);
		can->cmd = cmd;

		/* Only works if we have listnodes! */
		plugin = find_plugin_for_command(cmd->ld, "listnodes");
		if (plugin) {
			req = jsonrpc_request_start(cmd, "listnodes",
						    cmd->id,
						    plugin->non_numeric_ids,
						    command_logger(cmd),
						    NULL, listnodes_done,
						    can);
			json_add_node_id(req->stream, "id", &can->id);
			jsonrpc_request_end(req);
			plugin_request_send(plugin, req);
			return command_still_pending(cmd);
		}
	}

	response = json_stream_success(cmd);
	json_add_pubkey(response, "pubkey", &reckey);
	json_add_bool(response, "verified",
		      pubkey && pubkey_eq(pubkey, &reckey));
	return command_success(cmd, response);
}

static const struct json_command json_checkmessage_cmd = {
	"checkmessage",
	json_checkmessage,
	"Verify a digital signature {zbase} of {message} signed with {pubkey}",
};
AUTODATA(json_command, &json_checkmessage_cmd);
