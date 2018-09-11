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
#include <lightningd/ping.h>
#include <lightningd/subd.h>

struct ping_command {
	struct list_node list;
	struct pubkey id;
	struct command *cmd;
};

static struct ping_command *find_ping_cmd(struct lightningd *ld,
					  const struct pubkey *id)
{
	struct ping_command *i;

	list_for_each(&ld->ping_commands, i, list) {
		if (pubkey_eq(id, &i->id))
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
					     const struct pubkey *peer_id,
					     struct command *cmd)
{
	struct ping_command *pc = tal(ctx, struct ping_command);

	pc->id = *peer_id;
	pc->cmd = cmd;
	list_add_tail(&ld->ping_commands, &pc->list);
	tal_add_destructor(pc, destroy_ping_command);

	return pc;
}

void ping_reply(struct subd *subd, const u8 *msg)
{
	u16 totlen;
	bool ok, sent = true;
	struct pubkey id;
	struct ping_command *pc;

	log_debug(subd->ld->log, "Got ping reply!");
	ok = fromwire_gossip_ping_reply(msg, &id, &sent, &totlen);

	pc = find_ping_cmd(subd->ld, &id);
	assert(pc);

	if (!ok)
		command_fail(pc->cmd, LIGHTNINGD, "Bad reply message");
	else if (!sent)
		command_fail(pc->cmd, LIGHTNINGD, "Unknown peer");
	else {
		struct json_result *response = new_json_result(pc->cmd);

		json_object_start(response, NULL);
		json_add_num(response, "totlen", totlen);
		json_object_end(response);
		command_success(pc->cmd, response);
	}
}

static void json_ping(struct command *cmd,
		      const char *buffer, const jsmntok_t *params)
{
	u8 *msg;
	unsigned int *len, *pongbytes;
	struct pubkey *id;

	if (!param(cmd, buffer, params,
		   p_req("id", json_tok_pubkey, &id),
		   p_opt_def("len", json_tok_number, &len, 128),
		   p_opt_def("pongbytes", json_tok_number, &pongbytes, 128),
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
	if (*len > 65535 - 2 - 2 - 2) {
		command_fail(cmd, JSONRPC2_INVALID_PARAMS,
			     "%u would result in oversize ping", *len);
		return;
	}

	/* Note that > 65531 is valid: it means "no pong reply" */
	if (*pongbytes > 65535) {
		command_fail(cmd, JSONRPC2_INVALID_PARAMS,
			     "pongbytes %u > 65535", *pongbytes);
		return;
	}

	/* parent is cmd, so when we complete cmd, we free this. */
	new_ping_command(cmd, cmd->ld, id, cmd);

	/* gossipd handles all pinging, even if it's in another daemon. */
	msg = towire_gossip_ping(NULL, id, *pongbytes, *len);
	subd_send_msg(cmd->ld->gossip, take(msg));
	command_still_pending(cmd);
}

static const struct json_command ping_command = {
	"ping",
	json_ping,
	"Send peer {id} a ping of length {len} (default 128) asking for {pongbytes} (default 128)"
};
AUTODATA(json_command, &ping_command);
