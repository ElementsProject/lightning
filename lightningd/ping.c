#include "config.h"
#include <common/json_command.h>
#include <connectd/connectd_wiregen.h>
#include <inttypes.h>
#include <lightningd/jsonrpc.h>
#include <lightningd/lightningd.h>
#include <lightningd/ping.h>
#include <lightningd/subd.h>

struct ping_command {
	struct list_node list;
	u64 reqid;
	struct command *cmd;
};

static void destroy_ping_command(struct ping_command *ping_command,
				 struct lightningd *ld)
{
	list_del_from(&ld->ping_commands, &ping_command->list);
}

static struct ping_command *find_ping_command(struct lightningd *ld,
					      u64 reqid)
{
	struct ping_command *i;
	list_for_each(&ld->ping_commands, i, list) {
		if (i->reqid == reqid)
			return i;
	}
	return NULL;
}

void handle_ping_done(struct subd *connectd, const u8 *msg)
{
	u16 totlen;
	bool sent;
	u64 reqid;
	struct ping_command *ping_command;

	if (!fromwire_connectd_ping_done(msg, &reqid, &sent, &totlen)) {
		log_broken(connectd->log, "Malformed ping reply %s",
			   tal_hex(tmpctx, msg));
		return;
	}

	ping_command = find_ping_command(connectd->ld, reqid);
	if (!ping_command) {
		log_broken(connectd->log, "ping reply for unknown reqid %"PRIu64, reqid);
		return;
	}

	log_debug(connectd->log, "Got ping reply!");
	if (!sent)
		was_pending(command_fail(ping_command->cmd, LIGHTNINGD,
					 "Ping already pending"));
	else {
		struct json_stream *response = json_stream_success(ping_command->cmd);

		json_add_num(response, "totlen", totlen);
		was_pending(command_success(ping_command->cmd, response));
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
	static u64 reqid;
	struct ping_command *ping_command;

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

	ping_command = tal(cmd, struct ping_command);
	ping_command->cmd = cmd;
	ping_command->reqid = ++reqid;
	list_add_tail(&cmd->ld->ping_commands, &ping_command->list);
	tal_add_destructor2(ping_command, destroy_ping_command, cmd->ld);

	msg = towire_connectd_ping(NULL, ping_command->reqid, id, *pongbytes, *len);
	subd_send_msg(cmd->ld->connectd, take(msg));

	return command_still_pending(cmd);
}

static const struct json_command ping_command = {
	"ping",
	json_ping,
};
AUTODATA(json_command, &ping_command);
