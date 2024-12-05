#include "config.h"
#include <ccan/mem/mem.h>
#include <common/blindedpath.h>
#include <common/blinding.h>
#include <common/configdir.h>
#include <common/ecdh.h>
#include <common/json_command.h>
#include <common/json_param.h>
#include <connectd/connectd_wiregen.h>
#include <lightningd/channel.h>
#include <lightningd/onion_message.h>
#include <lightningd/peer_control.h>
#include <lightningd/plugin_hook.h>
#include <lightningd/subd.h>
#include <sodium/randombytes.h>

struct onion_message_hook_payload {
	/* Optional */
	struct blinded_path *reply_path;
	struct secret *pathsecret;
	struct tlv_onionmsg_tlv *om;
};

static void json_add_blindedpath(struct plugin *plugin,
				 struct json_stream *stream,
				 const char *fieldname,
				 const struct blinded_path *path)
{
	json_object_start(stream, fieldname);
	if (path->first_node_id.is_pubkey) {
		json_add_pubkey(stream, "first_node_id", &path->first_node_id.pubkey);
	} else {
		json_add_short_channel_id(stream, "first_scid", path->first_node_id.scidd.scid);
		json_add_u32(stream, "first_scid_dir", path->first_node_id.scidd.dir);
	}
	if (lightningd_deprecated_in_ok(plugin->plugins->ld,
					plugin->log,
					plugin->plugins->ld->deprecated_ok,
					"onion_message_recv", "blinding",
					"v24.11", "v25.05",
					NULL)) {
		json_add_pubkey(stream, "blinding", &path->first_path_key);
	}
	json_add_pubkey(stream, "first_path_key", &path->first_path_key);
	json_array_start(stream, "hops");
	for (size_t i = 0; i < tal_count(path->path); i++) {
		json_object_start(stream, NULL);
		json_add_pubkey(stream, "blinded_node_id",
				&path->path[i]->blinded_node_id);
		json_add_hex_talarr(stream, "encrypted_recipient_data",
				    path->path[i]->encrypted_recipient_data);
		json_object_end(stream);
	};
	json_array_end(stream);
	json_object_end(stream);
}

static void onion_message_serialize(struct onion_message_hook_payload *payload,
				    struct json_stream *stream,
				    struct plugin *plugin)
{
	json_object_start(stream, "onion_message");
	if (payload->pathsecret)
		json_add_secret(stream, "pathsecret", payload->pathsecret);

	if (payload->reply_path)
		json_add_blindedpath(plugin, stream, "reply_blindedpath",
				     payload->reply_path);

	if (payload->om->invoice_request)
		json_add_hex_talarr(stream, "invoice_request",
				    payload->om->invoice_request);
	if (payload->om->invoice)
		json_add_hex_talarr(stream, "invoice", payload->om->invoice);

	if (payload->om->invoice_error)
		json_add_hex_talarr(stream, "invoice_error",
				    payload->om->invoice_error);

	json_array_start(stream, "unknown_fields");
	for (size_t i = 0; i < tal_count(payload->om->fields); i++) {
		if (payload->om->fields[i].meta)
			continue;
		json_object_start(stream, NULL);
		json_add_u64(stream, "number", payload->om->fields[i].numtype);
		json_add_hex(stream, "value",
			     payload->om->fields[i].value,
			     payload->om->fields[i].length);
		json_object_end(stream);
	}
	json_array_end(stream);

	json_object_end(stream);
}

static void
onion_message_hook_cb(struct onion_message_hook_payload *payload STEALS)
{
	/* plugin_hook_continue checks the "result"; anything other than continue
	 * just stops. */
	tal_free(payload);
}

/* This is for unsolicted messages */
REGISTER_PLUGIN_HOOK(onion_message_recv,
		     plugin_hook_continue,
		     onion_message_hook_cb,
		     onion_message_serialize,
		     struct onion_message_hook_payload *);

/* This is for messages claiming to be using our paths: caller must
 * check pathsecret! */
 REGISTER_PLUGIN_HOOK(onion_message_recv_secret,
		     plugin_hook_continue,
		     onion_message_hook_cb,
		     onion_message_serialize,
		     struct onion_message_hook_payload *);


void handle_onionmsg_to_us(struct lightningd *ld, const u8 *msg)
{
	struct onion_message_hook_payload *payload;
	u8 *submsg;
	size_t submsglen;
	const u8 *subptr;

	payload = tal(tmpctx, struct onion_message_hook_payload);
	if (!fromwire_connectd_got_onionmsg_to_us(payload, msg,
						  &payload->pathsecret,
						  &payload->reply_path,
						  &submsg)) {
		log_broken(ld->log, "bad got_onionmsg_tous: %s",
			   tal_hex(tmpctx, msg));
		return;
	}

	if (ld->dev_ignore_modern_onion)
		return;

	submsglen = tal_bytelen(submsg);
	subptr = submsg;
	payload->om = fromwire_tlv_onionmsg_tlv(payload, &subptr, &submsglen);
	if (!payload->om) {
		log_broken(ld->log, "bad got_onionmsg_tous om: %s",
			   tal_hex(tmpctx, msg));
		return;
	}
	tal_free(submsg);

	/* Make sure connectd gets this right. */
	log_debug(ld->log, "Got onionmsg%s%s",
		  payload->pathsecret ? " with pathsecret": "",
		  payload->reply_path ? " reply_path": "");

	/* We'll free this on return */
	tal_steal(ld, payload);
	if (payload->pathsecret)
		plugin_hook_call_onion_message_recv_secret(ld, NULL, payload);
	else
		plugin_hook_call_onion_message_recv(ld, NULL, payload);
}

static void inject_onionmsg_reply(struct subd *connectd,
				  const u8 *reply,
				  const int *fds UNUSED,
				  struct command *cmd)
{
	char *err;

	if (!fromwire_connectd_inject_onionmsg_reply(cmd, reply, &err)) {
		log_broken(connectd->ld->log, "bad onionmsg_reply: %s",
			   tal_hex(tmpctx, reply));
		return;
	}

	if (strlen(err) == 0)
		was_pending(command_success(cmd, json_stream_success(cmd)));
	else
		was_pending(command_fail(cmd, LIGHTNINGD, "%s", err));
}

static struct command_result *json_injectonionmessage(struct command *cmd,
						      const char *buffer,
						      const jsmntok_t *obj UNNEEDED,
						      const jsmntok_t *params)
{
	struct pubkey *path_key;
	u8 *msg;

	if (!param_check(cmd, buffer, params,
			 p_req("path_key", param_pubkey, &path_key),
			 p_req("message", param_bin_from_hex, &msg),
			 NULL))
		return command_param_failed();

	if (!feature_offered(cmd->ld->our_features->bits[NODE_ANNOUNCE_FEATURE],
			     OPT_ONION_MESSAGES))
		return command_fail(cmd, LIGHTNINGD,
				    "experimental-onion-messages not enabled");

	if (tal_count(msg) > 65535) {
		return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
				    "onion message too long");
	}

	if (command_check_only(cmd))
		return command_check_done(cmd);

	subd_req(cmd, cmd->ld->connectd,
		 take(towire_connectd_inject_onionmsg(NULL, path_key, msg)),
		 -1, 0, inject_onionmsg_reply, cmd);
	return command_still_pending(cmd);
}

static const struct json_command injectonionmessage_command = {
	"injectonionmessage",
	json_injectonionmessage,
};
AUTODATA(json_command, &injectonionmessage_command);

static struct command_result *json_decryptencrypteddata(struct command *cmd,
							const char *buffer,
							const jsmntok_t *obj UNNEEDED,
							const jsmntok_t *params)
{
	u8 *encdata, *decrypted;
	struct pubkey *path_key, next_path_key;
	struct secret ss;
	struct sha256 h;
	struct json_stream *response;

	if (!param_check(cmd, buffer, params,
			 p_req("encrypted_data", param_bin_from_hex, &encdata),
			 p_req("path_key", param_pubkey, &path_key),
			 NULL))
		return command_param_failed();

	/* BOLT #4:
	 *
	 * - MUST compute:
	 *   - $`ss_i = SHA256(k_i * E_i)`$ (standard ECDH)
	 *...
	 *   - $`rho_i = HMAC256(\text{"rho"}, ss_i)`$
	 * - MUST decrypt the `encrypted_recipient_data` field using $`rho_i`$
	 */
	ecdh(path_key, &ss);

	decrypted = decrypt_encmsg_raw(cmd, &ss, encdata);
	if (!decrypted)
		return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
				    "Decryption failed!");

	if (command_check_only(cmd))
		return command_check_done(cmd);

	/* BOLT #4:
	 *
	 *   - $`E_{i+1} = SHA256(E_i || ss_i) * E_i`$
	 */
	blinding_hash_e_and_ss(path_key, &ss, &h);
	blinding_next_path_key(path_key, &h, &next_path_key);

	response = json_stream_success(cmd);
	json_object_start(response, "decryptencrypteddata");
	json_add_hex_talarr(response, "decrypted", decrypted);
	json_add_pubkey(response, "next_path_key", &next_path_key);
	json_object_end(response);
	return command_success(cmd, response);
}

static const struct json_command decryptencrypteddata_command = {
	"decryptencrypteddata",
	json_decryptencrypteddata,
};
AUTODATA(json_command, &decryptencrypteddata_command);
