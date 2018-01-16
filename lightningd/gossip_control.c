#include "bitcoind.h"
#include "chaintopology.h"
#include "gossip_control.h"
#include "lightningd.h"
#include "peer_control.h"
#include "subd.h"
#include <ccan/array_size/array_size.h>
#include <ccan/err/err.h>
#include <ccan/fdpass/fdpass.h>
#include <ccan/take/take.h>
#include <ccan/tal/str/str.h>
#include <common/features.h>
#include <common/type_to_string.h>
#include <common/utils.h>
#include <errno.h>
#include <gossipd/gen_gossip_wire.h>
#include <hsmd/capabilities.h>
#include <hsmd/gen_hsm_client_wire.h>
#include <inttypes.h>
#include <lightningd/gossip_msg.h>
#include <lightningd/hsm_control.h>
#include <lightningd/jsonrpc.h>
#include <lightningd/log.h>
#include <wire/gen_peer_wire.h>
#include <wire/wire_sync.h>

static void peer_nongossip(struct subd *gossip, const u8 *msg,
			   int peer_fd, int gossip_fd)
{
	struct pubkey id;
	struct crypto_state cs;
	struct wireaddr addr;
	u8 *gfeatures, *lfeatures, *in_pkt;
	u64 gossip_index;

	if (!fromwire_gossip_peer_nongossip(msg, msg, NULL,
					    &id, &addr, &cs, &gossip_index,
					    &gfeatures,
					    &lfeatures,
					    &in_pkt))
		fatal("Gossip gave bad GOSSIP_PEER_NONGOSSIP message %s",
		      tal_hex(msg, msg));

	/* We already checked the features when it first connected. */
	if (unsupported_features(gfeatures, lfeatures)) {
		log_unusual(gossip->log,
			    "Gossip gave unsupported features %s/%s",
			    tal_hex(msg, gfeatures),
			    tal_hex(msg, lfeatures));
		close(peer_fd);
		close(gossip_fd);
		return;
	}

	peer_sent_nongossip(gossip->ld, &id, &addr, &cs, gossip_index,
			    gfeatures, lfeatures,
			    peer_fd, gossip_fd, in_pkt);
}

static void got_txout(struct bitcoind *bitcoind,
		      const struct bitcoin_tx_output *output,
		      struct short_channel_id *scid)
{
	const u8 *script;

	/* output will be NULL if it wasn't found */
	if (output)
		script = output->script;
	else
		script = NULL;

	subd_send_msg(bitcoind->ld->gossip,
		      towire_gossip_get_txout_reply(scid, scid, script));
	tal_free(scid);
}

static void get_txout(struct subd *gossip, const u8 *msg)
{
	struct short_channel_id *scid = tal(gossip, struct short_channel_id);

	if (!fromwire_gossip_get_txout(msg, NULL, scid))
		fatal("Gossip gave bad GOSSIP_GET_TXOUT message %s",
		      tal_hex(msg, msg));

	/* FIXME: Block less than 6 deep? */

	bitcoind_getoutput(gossip->ld->topology->bitcoind,
			   scid->blocknum, scid->txnum, scid->outnum,
			   got_txout, scid);
}

static unsigned gossip_msg(struct subd *gossip, const u8 *msg, const int *fds)
{
	enum gossip_wire_type t = fromwire_peektype(msg);

	switch (t) {
	/* These are messages we send, not them. */
	case WIRE_GOSSIPCTL_INIT:
	case WIRE_GOSSIP_GETNODES_REQUEST:
	case WIRE_GOSSIP_GETROUTE_REQUEST:
	case WIRE_GOSSIP_GETCHANNELS_REQUEST:
	case WIRE_GOSSIP_GETPEERS_REQUEST:
	case WIRE_GOSSIP_PING:
	case WIRE_GOSSIP_RESOLVE_CHANNEL_REQUEST:
	case WIRE_GOSSIPCTL_REACH_PEER:
	case WIRE_GOSSIPCTL_HAND_BACK_PEER:
	case WIRE_GOSSIPCTL_RELEASE_PEER:
	case WIRE_GOSSIPCTL_PEER_ADDRHINT:
	case WIRE_GOSSIP_GET_UPDATE:
	case WIRE_GOSSIP_SEND_GOSSIP:
	case WIRE_GOSSIP_GET_TXOUT_REPLY:
	/* This is a reply, so never gets through to here. */
	case WIRE_GOSSIP_GET_UPDATE_REPLY:
	case WIRE_GOSSIP_GETNODES_REPLY:
	case WIRE_GOSSIP_GETROUTE_REPLY:
	case WIRE_GOSSIP_GETCHANNELS_REPLY:
	case WIRE_GOSSIP_GETPEERS_REPLY:
	case WIRE_GOSSIP_PING_REPLY:
	case WIRE_GOSSIP_RESOLVE_CHANNEL_REPLY:
	case WIRE_GOSSIPCTL_RELEASE_PEER_REPLY:
	case WIRE_GOSSIPCTL_RELEASE_PEER_REPLYFAIL:
		break;
	/* These are inter-daemon messages, not received by us */
	case WIRE_GOSSIP_LOCAL_ADD_CHANNEL:
		break;

	case WIRE_GOSSIP_PEER_CONNECTED:
		if (tal_count(fds) != 2)
			return 2;
		peer_connected(gossip->ld, msg, fds[0], fds[1]);
		break;
	case WIRE_GOSSIP_PEER_ALREADY_CONNECTED:
		peer_already_connected(gossip->ld, msg);
		break;
	case WIRE_GOSSIP_PEER_NONGOSSIP:
		if (tal_count(fds) != 2)
			return 2;
		peer_nongossip(gossip, msg, fds[0], fds[1]);
		break;
	case WIRE_GOSSIP_GET_TXOUT:
		get_txout(gossip, msg);
		break;
	}
	return 0;
}

/* Create the `gossipd` subdaemon and send the initialization
 * message */
void gossip_init(struct lightningd *ld)
{
	tal_t *tmpctx = tal_tmpctx(ld);
	u8 *msg;
	int hsmfd;
	u64 capabilities = HSM_CAP_ECDH | HSM_CAP_SIGN_GOSSIP;

	msg = towire_hsm_client_hsmfd(tmpctx, &ld->id, capabilities);
	if (!wire_sync_write(ld->hsm_fd, msg))
		fatal("Could not write to HSM: %s", strerror(errno));

	msg = hsm_sync_read(tmpctx, ld);
	if (!fromwire_hsm_client_hsmfd_reply(msg, NULL))
		fatal("Malformed hsmfd response: %s", tal_hex(msg, msg));

	hsmfd = fdpass_recv(ld->hsm_fd);
	if (hsmfd < 0)
		fatal("Could not read fd from HSM: %s", strerror(errno));

	ld->gossip = new_global_subd(ld, "lightning_gossipd",
				     gossip_wire_type_name, gossip_msg,
				     take(&hsmfd), NULL);
	if (!ld->gossip)
		err(1, "Could not subdaemon gossip");

	msg = towire_gossipctl_init(
	    tmpctx, ld->config.broadcast_interval,
	    &get_chainparams(ld)->genesis_blockhash, &ld->id, ld->portnum,
	    get_supported_global_features(tmpctx),
	    get_supported_local_features(tmpctx), ld->wireaddrs, ld->rgb,
	    ld->alias, ld->config.channel_update_interval);
	subd_send_msg(ld->gossip, msg);
	tal_free(tmpctx);
}

static void json_getnodes_reply(struct subd *gossip, const u8 *reply,
				const int *fds,
				struct command *cmd)
{
	struct gossip_getnodes_entry *nodes;
	struct json_result *response = new_json_result(cmd);
	size_t i, j;

	if (!fromwire_gossip_getnodes_reply(reply, reply, NULL, &nodes)) {
		command_fail(cmd, "Malformed gossip_getnodes response");
		return;
	}

	json_object_start(response, NULL);
	json_array_start(response, "nodes");

	for (i = 0; i < tal_count(nodes); i++) {
		json_object_start(response, NULL);
		json_add_pubkey(response, "nodeid", &nodes[i].nodeid);
		if (nodes[i].last_timestamp < 0) {
			json_object_end(response);
			continue;
		}
		json_add_string(response, "alias",
				tal_strndup(response, (char *)nodes[i].alias,
					    tal_len(nodes[i].alias)));
		json_add_hex(response, "color",
			     nodes[i].color, ARRAY_SIZE(nodes[i].color));
		json_add_u64(response, "last_timestamp",
			     nodes[i].last_timestamp);
		json_array_start(response, "addresses");
		for (j=0; j<tal_count(nodes[i].addresses); j++) {
			json_add_address(response, NULL, &nodes[i].addresses[j]);
		}
		json_array_end(response);
		json_object_end(response);
	}
	json_array_end(response);
	json_object_end(response);
	command_success(cmd, response);
}

static void json_listnodes(struct command *cmd, const char *buffer,
			  const jsmntok_t *params)
{
	u8 *req;
	jsmntok_t *idtok = NULL;
	struct pubkey *id = NULL;

	if (!json_get_params(buffer, params,
			     "?id", &idtok,
			     NULL)) {
		command_fail(cmd, "Invalid arguments");
		return;
	}

	if (idtok) {
		id = tal_arr(cmd, struct pubkey, 1);
		if (!json_tok_pubkey(buffer, idtok, id)) {
			command_fail(cmd, "Invalid id");
			return;
		}
	}

	req = towire_gossip_getnodes_request(cmd, id);
	subd_req(cmd, cmd->ld->gossip, req, -1, 0, json_getnodes_reply, cmd);
	command_still_pending(cmd);
}

static const struct json_command listnodes_command = {
    "listnodes", json_listnodes,
    "List a nodes in our local network view (or all, if no {id})",
    "Returns a list of all nodes that we know about"};
AUTODATA(json_command, &listnodes_command);

static void json_getroute_reply(struct subd *gossip, const u8 *reply, const int *fds,
				struct command *cmd)
{
	struct json_result *response;
	struct route_hop *hops;
	size_t i;

	fromwire_gossip_getroute_reply(reply, reply, NULL, &hops);

	if (tal_count(hops) == 0) {
		command_fail(cmd, "Could not find a route");
		return;
	}

	response = new_json_result(cmd);
	json_object_start(response, NULL);
	json_array_start(response, "route");
	for (i = 0; i < tal_count(hops); i++) {
		json_object_start(response, NULL);
		json_add_pubkey(response, "id", &hops[i].nodeid);
		json_add_short_channel_id(response, "channel",
					  &hops[i].channel_id);
		json_add_u64(response, "msatoshi", hops[i].amount);
		json_add_num(response, "delay", hops[i].delay);
		json_object_end(response);
	}
	json_array_end(response);
	json_object_end(response);
	command_success(cmd, response);
}

static void json_getroute(struct command *cmd, const char *buffer, const jsmntok_t *params)
{
	struct pubkey id;
	jsmntok_t *idtok, *msatoshitok, *riskfactortok, *cltvtok;
	u64 msatoshi;
	unsigned cltv = 9;
	double riskfactor;
	struct lightningd *ld = cmd->ld;

	if (!json_get_params(buffer, params,
			     "id", &idtok,
			     "msatoshi", &msatoshitok,
			     "riskfactor", &riskfactortok,
			     "?cltv", &cltvtok,
			     NULL)) {
		command_fail(cmd, "Need id, msatoshi and riskfactor");
		return;
	}

	if (!json_tok_pubkey(buffer, idtok, &id)) {
		command_fail(cmd, "Invalid id");
		return;
	}

	if (cltvtok && !json_tok_number(buffer, cltvtok, &cltv)) {
		command_fail(cmd, "Invalid cltv");
		return;
	}

	if (!json_tok_u64(buffer, msatoshitok, &msatoshi)) {
		command_fail(cmd, "'%.*s' is not a valid number",
			     (int)(msatoshitok->end - msatoshitok->start),
			     buffer + msatoshitok->start);
		return;
	}

	if (!json_tok_double(buffer, riskfactortok, &riskfactor)) {
		command_fail(cmd, "'%.*s' is not a valid double",
			     (int)(riskfactortok->end - riskfactortok->start),
			     buffer + riskfactortok->start);
		return;
	}
	u8 *req = towire_gossip_getroute_request(cmd, &ld->id, &id, msatoshi, riskfactor*1000, cltv);
	subd_req(ld->gossip, ld->gossip, req, -1, 0, json_getroute_reply, cmd);
	command_still_pending(cmd);
}

static const struct json_command getroute_command = {
	"getroute", json_getroute,
	"Return route to {id} for {msatoshi}, using {riskfactor} and optional {cltv} (default 9)",
	"Returns a {route} array of {id} {msatoshi} {delay}: msatoshi and delay (in blocks) is cumulative."
};
AUTODATA(json_command, &getroute_command);

/* Called upon receiving a getchannels_reply from `gossipd` */
static void json_listchannels_reply(struct subd *gossip, const u8 *reply,
				   const int *fds, struct command *cmd)
{
	size_t i;
	struct gossip_getchannels_entry *entries;
	struct json_result *response = new_json_result(cmd);

	if (!fromwire_gossip_getchannels_reply(reply, reply, NULL, &entries)) {
		command_fail(cmd, "Invalid reply from gossipd");
		return;
	}

	json_object_start(response, NULL);
	json_array_start(response, "channels");
	for (i = 0; i < tal_count(entries); i++) {
		json_object_start(response, NULL);
		json_add_pubkey(response, "source", &entries[i].source);
		json_add_pubkey(response, "destination",
				&entries[i].destination);
		json_add_string(response, "short_channel_id",
				type_to_string(reply, struct short_channel_id,
					       &entries[i].short_channel_id));
		json_add_num(response, "flags", entries[i].flags);
		json_add_bool(response, "active", entries[i].active);
		json_add_bool(response, "public", entries[i].public);
		if (entries[i].last_update_timestamp >= 0) {
			json_add_num(response, "last_update",
				     entries[i].last_update_timestamp);
			json_add_num(response, "base_fee_millisatoshi",
				     entries[i].base_fee_msat);
			json_add_num(response, "fee_per_millionth",
				     entries[i].fee_per_millionth);
			json_add_num(response, "delay", entries[i].delay);
		}
		json_object_end(response);
	}
	json_array_end(response);
	json_object_end(response);
	command_success(cmd, response);
}

static void json_listchannels(struct command *cmd, const char *buffer,
			     const jsmntok_t *params)
{
	u8 *req;
	jsmntok_t *idtok;
	struct short_channel_id *id = NULL;

	if (!json_get_params(buffer, params,
			     "?short_channel_id", &idtok,
			     NULL)) {
		command_fail(cmd, "Invalid arguments");
		return;
	}

	if (idtok) {
		id = tal_arr(cmd, struct short_channel_id, 1);
		if (!json_tok_short_channel_id(buffer, idtok, id)) {
			command_fail(cmd, "Invalid short_channel_id");
			return;
		}
	}

	req = towire_gossip_getchannels_request(cmd, id);
	subd_req(cmd->ld->gossip, cmd->ld->gossip,
		 req, -1, 0, json_listchannels_reply, cmd);
	command_still_pending(cmd);
}

static const struct json_command listchannels_command = {
    "listchannels", json_listchannels, "List all known channels.",
    "Returns a 'channels' array with all known channels including their fees."};
AUTODATA(json_command, &listchannels_command);
