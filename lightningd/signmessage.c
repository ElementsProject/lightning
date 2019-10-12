#include <common/bech32.h>
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

/* These tables copied from zbase32 src:
 * copyright 2002-2007 Zooko "Zooko" Wilcox-O'Hearn
 * mailto:zooko@zooko.com
 *
 * Permission is hereby granted to any person obtaining a copy of this work to
 * deal in this work without restriction (including the rights to use, modify,
 * distribute, sublicense, and/or sell copies).
 */
static const char*const zbase32_chars="ybndrfg8ejkmcpqxot1uwisza345h769";

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

static struct command_result *json_signmessage(struct command *cmd,
					       const char *buffer,
					       const jsmntok_t *obj UNNEEDED,
					       const jsmntok_t *params)
{
	const char *message;
	secp256k1_ecdsa_recoverable_signature rsig;
	struct json_stream *response;
	u8 sig[65], *msg;
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
	"utility",
	json_signmessage,
	"Create a digital signature of {message}",
};
AUTODATA(json_command, &json_signmessage_cmd);

