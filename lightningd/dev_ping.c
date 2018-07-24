#include <channeld/gen_channel_wire.h>
#include <common/sphinx.h>
#include <common/utils.h>
#include <gossipd/gen_gossip_wire.h>
#include <lightningd/htlc_end.h>
#include <lightningd/json.h>
#include <lightningd/jsonrpc.h>
#include <lightningd/jsonrpc_errors.h>
#include <lightningd/lightningd.h>
#include <lightningd/log.h>
#include <lightningd/param.h>
#include <lightningd/peer_control.h>
#include <lightningd/subd.h>

static void ping_reply(struct subd *subd, const u8 *msg, const int *fds UNUSED,
		       struct command *cmd)
{
	u16 totlen;
	bool ok, sent = true;

	log_debug(subd->ld->log, "Got ping reply!");
	ok = fromwire_gossip_ping_reply(msg, &sent, &totlen);

	if (!ok)
		command_fail(cmd, LIGHTNINGD, "Bad reply message");
	else if (!sent)
		command_fail(cmd, LIGHTNINGD, "Unknown peer");
	else {
		struct json_result *response = new_json_result(cmd);

		json_object_start(response, NULL);
		json_add_num(response, "totlen", totlen);
		json_object_end(response);
		command_success(cmd, response);
	}
}

static void json_dev_ping(struct command *cmd,
			  const char *buffer, const jsmntok_t *params)
{
	u8 *msg;
	unsigned int len, pongbytes;
	struct pubkey id;

	if (!param(cmd, buffer, params,
		   p_req("id", json_tok_pubkey, &id),
		   p_req("len", json_tok_number, &len),
		   p_req("pongbytes", json_tok_number, &pongbytes),
		   NULL))
		return;

	/* BOLT #1:
	 *
	 * 1. `type`: a 2-byte big-endian field indicating the type of message
	 * 2. `payload`: ...
	 * The size of the message is required by the transport layer to fit
	 * into a 2-byte unsigned int; therefore, the maximum possible size is
	 * 65535 bytes.
	 *...
	 * 1. type: 18 (`ping`)
	 * 2. data:
	 *    * [`2`:`num_pong_bytes`]
	 *    * [`2`:`byteslen`]
	 *    * [`byteslen`:`ignored`]
	 */
	if (len > 65535 - 2 - 2 - 2) {
		command_fail(cmd, JSONRPC2_INVALID_PARAMS,
			     "%u would result in oversize ping", len);
		return;
	}

	/* Note that > 65531 is valid: it means "no pong reply" */
	if (pongbytes > 65535) {
		command_fail(cmd, JSONRPC2_INVALID_PARAMS,
			     "pongbytes %u > 65535", pongbytes);
		return;
	}

	/* gossipd handles all pinging, even if it's in another daemon. */
	msg = towire_gossip_ping(NULL, &id, pongbytes, len);
	subd_req(cmd->ld->gossip, cmd->ld->gossip,
		 take(msg), -1, 0, ping_reply, cmd);
	command_still_pending(cmd);
}

static const struct json_command dev_ping_command = {
	"dev-ping",
	json_dev_ping,
	"Send {peerid} a ping of length {len} asking for {pongbytes}"
};
AUTODATA(json_command, &dev_ping_command);
