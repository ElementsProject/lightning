#include "config.h"
#include <common/json_command.h>
#include <common/json_param.h>
#include <connectd/connectd_wiregen.h>
#include <lightningd/channel.h>
#include <lightningd/jsonrpc.h>
#include <lightningd/lightningd.h>
#include <lightningd/peer_control.h>
#include <lightningd/subd.h>

static void ping_reply(struct subd *connectd,
		       const u8 *msg, const int *fds,
		       struct command *cmd)
{
	u16 totlen;
	bool sent;

	log_debug(connectd->log, "Got ping reply!");

	if (!fromwire_connectd_ping_reply(msg, &sent, &totlen)) {
		log_broken(connectd->log, "Malformed ping reply %s",
			   tal_hex(tmpctx, msg));
		was_pending(command_fail(cmd, LIGHTNINGD,
					 "Bad reply message"));
		return;
	}

	if (!sent)
		was_pending(command_fail(cmd, LIGHTNINGD,
					 "Ping already pending"));
	else {
		struct json_stream *response = json_stream_success(cmd);

		json_add_num(response, "totlen", totlen);
		was_pending(command_success(cmd, response));
	}
}

static struct command_result *json_ping(struct command *cmd,
					const char *buffer,
					const jsmntok_t *obj UNNEEDED,
					const jsmntok_t *params)
{
	unsigned int *len, *pongbytes;
	struct node_id *id;
	u8 *msg;

	if (!param_check(cmd, buffer, params,
			 p_req("id", param_node_id, &id),
			 p_opt_def("len", param_number, &len, 128),
			 p_opt_def("pongbytes", param_number, &pongbytes, 128),
			 NULL))
		return command_param_failed();

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
	 *    * [`u16`:`num_pong_bytes`]
	 *    * [`u16`:`byteslen`]
	 *    * [`byteslen*byte`:`ignored`]
	 */
	if (*len > 65535 - 2 - 2 - 2) {
		return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
				    "%u would result in oversize ping", *len);
	}

	/* Note that > 65531 is valid: it means "no pong reply" */
	if (*pongbytes > 65535) {
		return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
				    "pongbytes %u > 65535", *pongbytes);
	}

	if (!peer_by_id(cmd->ld, id))
		return command_fail(cmd, LIGHTNINGD, "Peer not connected");

	if (command_check_only(cmd))
		return command_check_done(cmd);

	msg = towire_connectd_ping(NULL, id, *pongbytes, *len);
	subd_req(cmd, cmd->ld->connectd, take(msg), -1, 0, ping_reply, cmd);

	return command_still_pending(cmd);
}

static const struct json_command ping_command = {
	"ping",
	"network",
	json_ping,
	"Send peer {id} a ping of length {len} (default 128) asking for {pongbytes} (default 128)"
};
AUTODATA(json_command, &ping_command);
