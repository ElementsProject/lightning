#include <channeld/gen_channel_wire.h>
#include <common/sphinx.h>
#include <common/utils.h>
#include <gossipd/gen_gossip_wire.h>
#include <lightningd/htlc_end.h>
#include <lightningd/json.h>
#include <lightningd/jsonrpc.h>
#include <lightningd/lightningd.h>
#include <lightningd/log.h>
#include <lightningd/peer_control.h>
#include <lightningd/subd.h>

static void ping_reply(struct subd *subd, const u8 *msg, const int *fds UNUSED,
		       struct command *cmd)
{
	u16 totlen;
	bool ok, sent = true;

	log_debug(subd->ld->log, "Got ping reply!");
	if (streq(subd->name, "lightning_channeld"))
		ok = fromwire_channel_ping_reply(msg, &totlen);
	else
		ok = fromwire_gossip_ping_reply(msg, &sent, &totlen);

	if (!ok)
		command_fail(cmd, "Bad reply message");
	else if (!sent)
		command_fail(cmd, "Unknown peer");
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
	struct peer *peer;
	u8 *msg;
	jsmntok_t *idtok, *lentok, *pongbytestok;
	unsigned int len, pongbytes;
	struct pubkey id;
	struct subd *owner;

	if (!json_get_params(cmd, buffer, params,
			     "id", &idtok,
			     "len", &lentok,
			     "pongbytes", &pongbytestok,
			     NULL)) {
		return;
	}

	/* FIXME: These checks are horrible, use a peer flag to say it's
	 * ready to forward! */
	if (!json_tok_number(buffer, lentok, &len)) {
		command_fail(cmd, "'%.*s' is not a valid number",
			     lentok->end - lentok->start,
			     buffer + lentok->start);
		return;
	}

	/* BOLT #1:
	 *
	 * 1. `type`: a 2-byte big-endian field indicating the type of message
	 * 2. `payload`
	 *...
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
		command_fail(cmd, "%u would result in oversize ping", len);
		return;
	}

	if (!json_tok_number(buffer, pongbytestok, &pongbytes)) {
		command_fail(cmd, "'%.*s' is not a valid number",
			     pongbytestok->end - pongbytestok->start,
			     buffer + pongbytestok->start);
		return;
	}

	/* Note that > 65531 is valid: it means "no pong reply" */
	if (pongbytes > 65535) {
		command_fail(cmd, "pongbytes %u > 65535", pongbytes);
		return;
	}

	if (!json_tok_pubkey(buffer, idtok, &id)) {
		command_fail(cmd, "'%.*s' is not a valid pubkey",
			     idtok->end - idtok->start,
			     buffer + idtok->start);
		return;
	}

	/* First, see if it's in channeld. */
	peer = peer_by_id(cmd->ld, &id);
	if (peer) {
		struct channel *channel = peer_active_channel(peer);

		if (!channel
		    || !channel->owner
		    || !streq(channel->owner->name, "lightning_channeld")) {
			command_fail(cmd, "Peer in %s",
				     channel && channel->owner
				     ? channel->owner->name
				     : "unattached");
			return;
		}
		msg = towire_channel_ping(cmd, pongbytes, len);
		owner = channel->owner;
	} else {
		/* We assume it's in gossipd. */
		msg = towire_gossip_ping(cmd, &id, pongbytes, len);
		owner = cmd->ld->gossip;
	}

	subd_req(owner, owner, take(msg), -1, 0, ping_reply, cmd);
	command_still_pending(cmd);
}

static const struct json_command dev_ping_command = {
	"dev-ping",
	json_dev_ping,
	"Send {peerid} a ping of length {len} asking for {pongbytes}"
};
AUTODATA(json_command, &dev_ping_command);
