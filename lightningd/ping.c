#include "config.h"
#include <channeld/channeld_wiregen.h>
#include <common/json_command.h>
#include <common/json_tok.h>
#include <common/param.h>
#include <lightningd/channel.h>
#include <lightningd/jsonrpc.h>
#include <lightningd/lightningd.h>
#include <lightningd/peer_control.h>
#include <lightningd/ping.h>
#include <lightningd/subd.h>

struct ping_command {
	struct list_node list;
	struct node_id id;
	struct command *cmd;
};

static struct ping_command *find_ping_cmd(struct lightningd *ld,
					  const struct node_id *id)
{
	struct ping_command *i;

	list_for_each(&ld->ping_commands, i, list) {
		if (node_id_eq(id, &i->id))
			return i;
	}
	return NULL;
}

static void destroy_ping_command(struct ping_command *pc)
{
	list_del(&pc->list);
}

static struct ping_command *new_ping_command(const tal_t *ctx,
					     struct lightningd *ld,
					     const struct node_id *peer_id,
					     struct command *cmd)
{
	struct ping_command *pc = tal(ctx, struct ping_command);

	pc->id = *peer_id;
	pc->cmd = cmd;
	list_add_tail(&ld->ping_commands, &pc->list);
	tal_add_destructor(pc, destroy_ping_command);

	return pc;
}

void ping_reply(struct subd *channeld, const u8 *msg)
{
	u16 totlen;
	bool sent;
	struct ping_command *pc;
	struct channel *c = channeld->channel;

	log_debug(channeld->log, "Got ping reply!");
	pc = find_ping_cmd(channeld->ld, &c->peer->id);
	if (!pc) {
		log_broken(channeld->log, "Unexpected ping reply?");
		return;
	}

	if (!fromwire_channeld_ping_reply(msg, &sent, &totlen)) {
		log_broken(channeld->log, "Malformed ping reply %s",
			   tal_hex(tmpctx, msg));
		was_pending(command_fail(pc->cmd, LIGHTNINGD,
					 "Bad reply message"));
		return;
	}

	if (!sent)
		was_pending(command_fail(pc->cmd, LIGHTNINGD,
					 "Ping already pending"));
	else {
		struct json_stream *response = json_stream_success(pc->cmd);

		json_add_num(response, "totlen", totlen);
		was_pending(command_success(pc->cmd, response));
	}
}

static struct command_result *json_ping(struct command *cmd,
					const char *buffer,
					const jsmntok_t *obj UNNEEDED,
					const jsmntok_t *params)
{
	unsigned int *len, *pongbytes;
	struct node_id *id;
	struct peer *peer;
	struct channel *channel;
	u8 *msg;

	if (!param(cmd, buffer, params,
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

	peer = peer_by_id(cmd->ld, id);
	if (!peer)
		return command_fail(cmd, LIGHTNINGD, "Peer not connected");

	channel = peer_active_channel(peer);
	if (!channel || !channel->owner || channel->state != CHANNELD_NORMAL)
		return command_fail(cmd, LIGHTNINGD, "Peer bad state");

	/* parent is cmd, so when we complete cmd, we free this. */
	new_ping_command(cmd, cmd->ld, id, cmd);

	msg = towire_channeld_ping(NULL, *pongbytes, *len);
	subd_send_msg(channel->owner, take(msg));

	return command_still_pending(cmd);
}

static const struct json_command ping_command = {
	"ping",
	"network",
	json_ping,
	"Send peer {id} a ping of length {len} (default 128) asking for {pongbytes} (default 128)"
};
AUTODATA(json_command, &ping_command);
