#include <ccan/str/hex/hex.h>
#include <daemon/jsonrpc.h>
#include <daemon/log.h>
#include <lightningd/channel/gen_channel_wire.h>
#include <lightningd/htlc_end.h>
#include <lightningd/lightningd.h>
#include <lightningd/peer_control.h>
#include <lightningd/sphinx.h>
#include <lightningd/subd.h>
#include <utils.h>

static bool offer_htlc_reply(struct subd *subd, const u8 *msg, const int *fds,
			     struct htlc_end *hend)
{
	u16 failcode;
	u8 *failstr;
	/* We hack this in, since we don't have a real pay_command here. */
	struct command *cmd = (void *)hend->pay_command;

	/* This suppresses normal callback when it's actually paid! */
	hend->pay_command = NULL;

	if (!fromwire_channel_offer_htlc_reply(msg, msg, NULL,
					       &hend->htlc_id,
					       &failcode, &failstr)) {
		command_fail(cmd, "Invalid reply from daemon: %s",
			     tal_hex(msg, msg));
		return true;
	}

	if (failcode != 0) {
		command_fail(cmd, "failure %u: %.*s", failcode,
			     (int)tal_len(failstr), (char *)failstr);
	} else {
		struct json_result *response = new_json_result(cmd);

		/* Peer owns it now (we're about to free cmd) */
		tal_steal(hend->peer, hend);
		connect_htlc_end(&subd->ld->htlc_ends, hend);

		json_object_start(response, NULL);
		json_add_u64(response, "id", hend->htlc_id);
		json_object_end(response);
		command_success(cmd, response);
	}
	return true;
}

static void json_dev_newhtlc(struct command *cmd,
			     const char *buffer, const jsmntok_t *params)
{
	struct lightningd *ld = ld_from_dstate(cmd->dstate);
	struct peer *peer;
	u8 *msg;
	jsmntok_t *peeridtok, *msatoshitok, *expirytok, *rhashtok;
	unsigned int expiry;
	u64 msatoshi;
	struct sha256 rhash;
	u8 sessionkey[32];
	struct onionpacket *packet;
	u8 *onion;
	struct htlc_end *hend;
	struct hop_data *hops_data;
	struct pubkey *path = tal_arrz(cmd, struct pubkey, 1);

	if (!json_get_params(buffer, params,
			     "peerid", &peeridtok,
			     "msatoshi", &msatoshitok,
			     "expiry", &expirytok,
			     "rhash", &rhashtok,
			     NULL)) {
		command_fail(cmd, "Need peerid, msatoshi, expiry and rhash");
		return;
	}

	peer = peer_from_json(ld, buffer, peeridtok);
	if (!peer) {
		command_fail(cmd, "Could not find peer with that peerid");
		return;
	}

	/* FIXME: These checks are horrible, use a peer flag to say it's
	 * ready to forward! */
	if (peer->owner && !streq(peer->owner->name, "lightningd_channel")) {
		command_fail(cmd, "Peer not in lightningd_channel (%s instead)",
			     peer->owner ? peer->owner->name : "unattached");
		return;
	}

	if (!streq(peer->condition, "Normal operation")) {
		command_fail(cmd, "Peer in condition %s", peer->condition);
		return;
	}

	if (!json_tok_u64(buffer, msatoshitok, &msatoshi)) {
		command_fail(cmd, "'%.*s' is not a valid number",
			     (int)(msatoshitok->end - msatoshitok->start),
			     buffer + msatoshitok->start);
		return;
	}
	if (!json_tok_number(buffer, expirytok, &expiry)) {
		command_fail(cmd, "'%.*s' is not a valid number",
			     (int)(expirytok->end - expirytok->start),
			     buffer + expirytok->start);
		return;
	}

	if (!hex_decode(buffer + rhashtok->start,
			rhashtok->end - rhashtok->start,
			&rhash, sizeof(rhash))) {
		command_fail(cmd, "'%.*s' is not a valid sha256 hash",
			     (int)(rhashtok->end - rhashtok->start),
			     buffer + rhashtok->start);
		return;
	}

	hops_data = tal_arrz(cmd, struct hop_data, 1);
	path[0] = *peer->id;
	randombytes_buf(sessionkey, 32);
	packet = create_onionpacket(cmd, path, hops_data, sessionkey,
				    rhash.u.u8, sizeof(rhash));
	onion = serialize_onionpacket(cmd, packet);

	log_debug(peer->log, "JSON command to add new HTLC");

	hend = tal(cmd, struct htlc_end);
	hend->which_end = HTLC_DST;
	hend->peer = peer;
	hend->msatoshis = msatoshi;
	hend->other_end = NULL;
	hend->pay_command = (void *)cmd;

	/* FIXME: If subdaemon dies? */
	msg = towire_channel_offer_htlc(cmd, msatoshi, expiry, &rhash, onion);
	subd_req(hend, peer->owner, take(msg), -1, 0, offer_htlc_reply, hend);
}

static const struct json_command dev_newhtlc_command = {
	"dev-newhtlc",
	json_dev_newhtlc,
	"Offer {peerid} an HTLC worth {msatoshi} in {expiry} (block number) with {rhash}",
	"Returns { id: u64 } result on success"
};
AUTODATA(json_command, &dev_newhtlc_command);
