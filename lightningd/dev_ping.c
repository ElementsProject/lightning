#include <channeld/gen_channel_wire.h>
#include <common/sphinx.h>
#include <common/utils.h>
#include <gossipd/gen_gossip_wire.h>
#include <lightningd/htlc_end.h>
#include <lightningd/jsonrpc.h>
#include <lightningd/lightningd.h>
#include <lightningd/log.h>
#include <lightningd/peer_control.h>
#include <lightningd/subd.h>

static void ping_reply(struct subd *subd, const u8 *msg, const int *fds,
		       struct command *cmd)
{
	u16 totlen;
	bool ok, sent = true;

	log_debug(subd->ld->log, "Got ping reply!");
	if (streq(subd->name, "lightning_channeld"))
		ok = fromwire_channel_ping_reply(msg, NULL, &totlen);
	else
		ok = fromwire_gossip_ping_reply(msg, NULL, &sent, &totlen);

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
	jsmntok_t *peeridtok, *lentok, *pongbytestok;
	unsigned int len, pongbytes;
	struct pubkey id;
	struct subd *owner;

	if (!json_get_params(buffer, params,
			     "peerid", &peeridtok,
			     "len", &lentok,
			     "pongbytes", &pongbytestok,
			     NULL)) {
		command_fail(cmd, "Need peerid, len and pongbytes");
		return;
	}

	/* FIXME: These checks are horrible, use a peer flag to say it's
	 * ready to forward! */
	if (!json_tok_number(buffer, lentok, &len)) {
		command_fail(cmd, "'%.*s' is not a valid number",
			     (int)(lentok->end - lentok->start),
			     buffer + lentok->start);
		return;
	}

	if (!json_tok_number(buffer, pongbytestok, &pongbytes)) {
		command_fail(cmd, "'%.*s' is not a valid number",
			     (int)(pongbytestok->end - pongbytestok->start),
			     buffer + pongbytestok->start);
		return;
	}

	if (!json_tok_pubkey(buffer, peeridtok, &id)) {
		command_fail(cmd, "'%.*s' is not a valid pubkey",
			     (int)(peeridtok->end - peeridtok->start),
			     buffer + peeridtok->start);
		return;
	}

	/* First, see if it's in channeld. */
	peer = peer_by_id(cmd->ld, &id);
	if (peer) {
		if (!peer->owner ||
		    !streq(peer->owner->name, "lightning_channeld")) {
			command_fail(cmd, "Peer in %s",
				     peer->owner
				     ? peer->owner->name : "unattached");
			return;
		}
		msg = towire_channel_ping(cmd, pongbytes, len);
		owner = peer->owner;
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
	"Offer {peerid} a ping of length {len} asking for {pongbytes}",
	"Returns { totlen: u32 } on success"
};
AUTODATA(json_command, &dev_ping_command);
