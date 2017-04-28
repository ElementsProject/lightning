#include <daemon/jsonrpc.h>
#include <daemon/log.h>
#include <lightningd/channel/gen_channel_wire.h>
#include <lightningd/gossip/gen_gossip_wire.h>
#include <lightningd/htlc_end.h>
#include <lightningd/lightningd.h>
#include <lightningd/peer_control.h>
#include <lightningd/sphinx.h>
#include <lightningd/subd.h>
#include <utils.h>

static bool ping_reply(struct subd *subd, const u8 *msg, const int *fds,
		       struct command *cmd)
{
	u16 totlen;
	bool ok;

	log_debug(subd->ld->log, "Got ping reply!");
	if (streq(subd->name, "lightningd_channel"))
		ok = fromwire_channel_ping_reply(msg, NULL, &totlen);
	else
		ok = fromwire_gossip_ping_reply(msg, NULL, &totlen);

	if (!ok)
		command_fail(cmd, "Bad reply message");
	else {
		struct json_result *response = new_json_result(cmd);

		json_object_start(response, NULL);
		json_add_num(response, "totlen", totlen);
		json_object_end(response);
		command_success(cmd, response);
	}
	return true;
}

static void json_dev_ping(struct command *cmd,
			  const char *buffer, const jsmntok_t *params)
{
	struct lightningd *ld = ld_from_dstate(cmd->dstate);
	struct peer *peer;
	u8 *msg;
	jsmntok_t *peeridtok, *lentok, *pongbytestok;
	unsigned int len, pongbytes;

	if (!json_get_params(buffer, params,
			     "peerid", &peeridtok,
			     "len", &lentok,
			     "pongbytes", &pongbytestok,
			     NULL)) {
		command_fail(cmd, "Need peerid, len and pongbytes");
		return;
	}

	peer = peer_from_json(ld, buffer, peeridtok);
	if (!peer) {
		command_fail(cmd, "Could not find peer with that peerid");
		return;
	}

	/* FIXME: These checks are horrible, use a peer flag to say it's
	 * ready to forward! */
	if (peer->owner && !streq(peer->owner->name, "lightningd_channel")
	    && !streq(peer->owner->name, "lightningd_gossip")) {
		command_fail(cmd, "Peer in %s",
			     peer->owner ? peer->owner->name : "unattached");
		return;
	}

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

	if (streq(peer->owner->name, "lightningd_channel"))
		msg = towire_channel_ping(cmd, pongbytes, len);
	else
		msg = towire_gossip_ping(cmd, peer->unique_id, pongbytes, len);

	/* FIXME: If subdaemon dies? */
	subd_req(peer->owner, peer->owner, take(msg), -1, 0, ping_reply, cmd);
}

static const struct json_command dev_ping_command = {
	"dev-ping",
	json_dev_ping,
	"Offer {peerid} a ping of length {len} asking for {pongbytes}",
	"Returns { totlen: u32 } on success"
};
AUTODATA(json_command, &dev_ping_command);
