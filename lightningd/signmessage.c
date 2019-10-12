#include <common/json_helpers.h>
#include <common/jsonrpc_errors.h>
#include <common/param.h>
#include <common/type_to_string.h>
#include <common/utils.h>
#include <errno.h>
#include <gossipd/gen_gossip_wire.h>
#include <hsmd/gen_hsm_wire.h>
#include <string.h>
#include <wire/wire_sync.h>

static struct command_result *json_signmessage(struct command *cmd,
					       const char *buffer,
					       const jsmntok_t *obj UNNEEDED,
					       const jsmntok_t *params)
{
	const char *message;
	secp256k1_ecdsa_recoverable_signature rsig;
	struct json_stream *response;
	u8 sig[64], recidu8, *msg;
	int recid;

	if (!param(cmd, buffer, params,
		   p_req("message", param_string, &message),
		   NULL))
		return command_param_failed();

	if (strlen(message) > 65535)
		return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
				    "Message must be < 64k");

	msg = towire_hsm_sign_message(NULL,
				      tal_dup_arr(tmpctx, u8, (u8 *)message,
						  strlen(message), 0));
	if (!wire_sync_write(cmd->ld->hsm_fd, take(msg)))
		fatal("Could not write to HSM: %s", strerror(errno));

	msg = wire_sync_read(tmpctx, cmd->ld->hsm_fd);
	if (!fromwire_hsm_sign_message_reply(msg, &rsig))
		fatal("HSM gave bad hsm_sign_message_reply %s",
		      tal_hex(msg, msg));

	secp256k1_ecdsa_recoverable_signature_serialize_compact(secp256k1_ctx,
								sig, &recid,
								&rsig);
	response = json_stream_success(cmd);
	json_add_hex(response, "signature", sig, sizeof(sig));
	recidu8 = recid;
	json_add_hex(response, "recid", &recidu8, sizeof(recidu8));
	return command_success(cmd, response);
}

static const struct json_command json_signmessage_cmd = {
	"signmessage",
	"utility",
	json_signmessage,
	"Create a digital signature of {message}",
};
AUTODATA(json_command, &json_signmessage_cmd);

