#include "config.h"
#include <ccan/mem/mem.h>
#include <common/blindedpath.h>
#include <common/blinding.h>
#include <common/configdir.h>
#include <common/ecdh.h>
#include <common/json_command.h>
#include <common/json_param.h>
#include <common/json_stream.h>
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

static void onion_message_serialize(struct onion_message_hook_payload *payload,
				    struct json_stream *stream,
				    struct plugin *plugin)
{
	json_object_start(stream, "onion_message");
	if (payload->pathsecret)
		json_add_secret(stream, "pathsecret", payload->pathsecret);

	if (payload->reply_path)
		json_add_blinded_path(stream, "reply_blindedpath",
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

struct onion_hop {
	struct pubkey node;
	u8 *tlv;
};

static struct command_result *param_onion_hops(struct command *cmd,
					       const char *name,
					       const char *buffer,
					       const jsmntok_t *tok,
					       struct onion_hop **hops)
{
	size_t i;
	const jsmntok_t *t;

	if (tok->type != JSMN_ARRAY || tok->size == 0)
		return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
				    "%s must be an (non-empty) array", name);

	*hops = tal_arr(cmd, struct onion_hop, tok->size);
	json_for_each_arr(i, t, tok) {
		const char *err;

		err = json_scan(cmd, buffer, t, "{id:%,tlv:%}",
				JSON_SCAN(json_to_pubkey, &(*hops)[i].node),
				JSON_SCAN_TAL(tmpctx, json_tok_bin_from_hex,
					      &(*hops)[i].tlv));
		if (err)
			return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
					    "%s[%zu]: %s", name, i, err);
	}
	return NULL;
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
	struct onion_hop *hops;
	struct pubkey *blinding;
	struct sphinx_path *sphinx_path;
	struct onionpacket *op;
	struct secret *path_secrets;
	size_t onion_size;

	if (!param_check(cmd, buffer, params,
			 p_req("blinding", param_pubkey, &blinding),
			 p_req("hops", param_onion_hops, &hops),
			 NULL))
		return command_param_failed();

	if (!feature_offered(cmd->ld->our_features->bits[NODE_ANNOUNCE_FEATURE],
			     OPT_ONION_MESSAGES))
		return command_fail(cmd, LIGHTNINGD,
				    "experimental-onion-messages not enabled");

	/* Create an onion which encodes this. */
	sphinx_path = sphinx_path_new(cmd, NULL);
	for (size_t i = 0; i < tal_count(hops); i++)
		sphinx_add_hop(sphinx_path, &hops[i].node, hops[i].tlv);

	/* BOLT-onion-message #4:
	 * - SHOULD set `onion_message_packet` `len` to 1366 or 32834.
	 */
	if (sphinx_path_payloads_size(sphinx_path) <= ROUTING_INFO_SIZE)
		onion_size = ROUTING_INFO_SIZE;
	else
		onion_size = 32768; /* VERSION_SIZE + HMAC_SIZE + PUBKEY_SIZE == 66 */

	op = create_onionpacket(tmpctx, sphinx_path, onion_size, &path_secrets);
	if (!op)
		return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
				    "Creating onion failed (tlvs too long?)");

	if (command_check_only(cmd))
		return command_check_done(cmd);

	subd_req(cmd, cmd->ld->connectd,
		 take(towire_connectd_inject_onionmsg(NULL,
						      blinding,
						      serialize_onionpacket(tmpctx, op))),
		 -1, 0, inject_onionmsg_reply, cmd);
	return command_still_pending(cmd);
}

static const struct json_command injectonionmessage_command = {
	"injectonionmessage",
	"utility",
	json_injectonionmessage,
	"Unwrap using {blinding}, encoded over {hops} (id, tlv)"
};
AUTODATA(json_command, &injectonionmessage_command);

static struct command_result *json_decryptencrypteddata(struct command *cmd,
							const char *buffer,
							const jsmntok_t *obj UNNEEDED,
							const jsmntok_t *params)
{
	u8 *encdata, *decrypted;
	struct pubkey *blinding, next_blinding;
	struct secret ss;
	struct sha256 h;
	struct json_stream *response;

	if (!param_check(cmd, buffer, params,
			 p_req("encrypted_data", param_bin_from_hex, &encdata),
			 p_req("blinding", param_pubkey, &blinding),
			 NULL))
		return command_param_failed();

	/* BOLT #4:
	 *
	 * - MUST compute:
	 *   - $`ss_i = SHA256(k_i * E_i)`$ (standard ECDH)
	 *...
	 * - MUST decrypt the `encrypted_data` field using $`rho_i`$
	 */
	ecdh(blinding, &ss);

	decrypted = decrypt_encmsg_raw(cmd, blinding, &ss, encdata);
	if (!decrypted)
		return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
				    "Decryption failed!");

	if (command_check_only(cmd))
		return command_check_done(cmd);

	/* BOLT #4:
	 *
	 *   - $`E_{i+1} = SHA256(E_i || ss_i) * E_i`$
	 */
	blinding_hash_e_and_ss(blinding, &ss, &h);
	blinding_next_pubkey(blinding, &h, &next_blinding);

	response = json_stream_success(cmd);
	json_object_start(response, "decryptencrypteddata");
	json_add_hex_talarr(response, "decrypted", decrypted);
	json_add_pubkey(response, "next_blinding", &next_blinding);
	json_object_end(response);
	return command_success(cmd, response);
}

static const struct json_command decryptencrypteddata_command = {
	"decryptencrypteddata",
	"utility",
	json_decryptencrypteddata,
	"Decrypt {encrypted_data} using {blinding}, return decryption and next blinding"
};
AUTODATA(json_command, &decryptencrypteddata_command);
