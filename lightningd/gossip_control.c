#include "gossip_control.h"
#include "lightningd.h"
#include "peer_control.h"
#include "subd.h"
#include <ccan/err/err.h>
#include <ccan/take/take.h>
#include <ccan/tal/str/str.h>
#include <daemon/jsonrpc.h>
#include <daemon/log.h>
#include <inttypes.h>
#include <lightningd/cryptomsg.h>
#include <lightningd/gossip/gen_gossip_wire.h>
#include <lightningd/gossip_msg.h>
#include <wire/gen_peer_wire.h>

static void gossip_finished(struct subd *gossip, int status)
{
	if (WIFEXITED(status))
		errx(1, "Gossip failed (exit status %i), exiting.",
		     WEXITSTATUS(status));
	errx(1, "Gossip failed (signal %u), exiting.", WTERMSIG(status));
}

static void peer_bad_message(struct subd *gossip, const u8 *msg)
{
	u64 unique_id;
	struct peer *peer;
	u8 *err;

	if (!fromwire_gossipstatus_peer_bad_msg(msg, msg, NULL,
						&unique_id, &err))
		fatal("Gossip gave bad PEER_BAD message %s", tal_hex(msg, msg));

	peer = peer_by_unique_id(gossip->ld, unique_id);
	if (!peer)
		fatal("Gossip gave bad peerid %"PRIu64, unique_id);

	log_debug(gossip->log, "Peer %s gave bad msg %s",
		  type_to_string(msg, struct pubkey, &peer->id),
		  tal_hex(msg, msg));
	peer_fail_permanent(peer, msg);
}

static void peer_failed(struct subd *gossip, const u8 *msg)
{
	u64 unique_id;
	struct peer *peer;
	u8 *err;

	if (!fromwire_gossipstatus_peer_failed(msg, msg, NULL,
					       &unique_id, &err))
		fatal("Gossip gave bad PEER_FAILED message %s",
		      tal_hex(msg, msg));

	peer = peer_by_unique_id(gossip->ld, unique_id);
	if (!peer)
		fatal("Gossip gave bad peerid %"PRIu64, unique_id);

	peer_fail_permanent(peer, msg);
}

static void peer_nongossip(struct subd *gossip, const u8 *msg,
			   int peer_fd, int gossip_fd)
{
	u64 unique_id;
	struct peer *peer;
	u8 *inner;
	struct crypto_state cs;

	if (!fromwire_gossipstatus_peer_nongossip(msg, msg, NULL,
						  &unique_id, &cs, &inner))
		fatal("Gossip gave bad PEER_NONGOSSIP message %s",
		      tal_hex(msg, msg));

	peer = peer_by_unique_id(gossip->ld, unique_id);
	if (!peer)
		fatal("Gossip gave bad peerid %"PRIu64, unique_id);

	if (peer->owner != gossip)
		fatal("Gossip gave bad peerid %"PRIu64" (owner %s)",
		      unique_id, peer->owner ? peer->owner->name : "(none)");

	log_info(peer->log, "Gossip ended up receipt of %s",
		 wire_type_name(fromwire_peektype(inner)));

	peer_fundee_open(peer, inner, &cs, peer_fd, gossip_fd);
}

static int gossip_msg(struct subd *gossip, const u8 *msg, const int *fds)
{
	enum gossip_wire_type t = fromwire_peektype(msg);

	switch (t) {
	/* subd already logs fatal errors. */
	case WIRE_GOSSIPSTATUS_INIT_FAILED:
	case WIRE_GOSSIPSTATUS_BAD_NEW_PEER_REQUEST:
	case WIRE_GOSSIPSTATUS_BAD_REQUEST:
	case WIRE_GOSSIPSTATUS_FDPASS_FAILED:
	case WIRE_GOSSIPSTATUS_BAD_RELEASE_REQUEST:
	case WIRE_GOSSIPSTATUS_BAD_FAIL_REQUEST:
		break;
	/* These are messages we send, not them. */
	case WIRE_GOSSIPCTL_INIT:
	case WIRE_GOSSIPCTL_NEW_PEER:
	case WIRE_GOSSIPCTL_RELEASE_PEER:
	case WIRE_GOSSIPCTL_FAIL_PEER:
	case WIRE_GOSSIPCTL_GET_PEER_GOSSIPFD:
	case WIRE_GOSSIP_GETNODES_REQUEST:
	case WIRE_GOSSIP_GETROUTE_REQUEST:
	case WIRE_GOSSIP_GETCHANNELS_REQUEST:
	case WIRE_GOSSIP_PING:
	case WIRE_GOSSIP_RESOLVE_CHANNEL_REQUEST:
	case WIRE_GOSSIP_FORWARDED_MSG:
	/* This is a reply, so never gets through to here. */
	case WIRE_GOSSIPCTL_RELEASE_PEER_REPLY:
	case WIRE_GOSSIPCTL_RELEASE_PEER_REPLYFAIL:
	case WIRE_GOSSIPCTL_GET_PEER_GOSSIPFD_REPLY:
	case WIRE_GOSSIPCTL_GET_PEER_GOSSIPFD_REPLYFAIL:
	case WIRE_GOSSIP_GETNODES_REPLY:
	case WIRE_GOSSIP_GETROUTE_REPLY:
	case WIRE_GOSSIP_GETCHANNELS_REPLY:
	case WIRE_GOSSIP_PING_REPLY:
	case WIRE_GOSSIP_RESOLVE_CHANNEL_REPLY:
		break;
	case WIRE_GOSSIPSTATUS_PEER_BAD_MSG:
		peer_bad_message(gossip, msg);
		break;
	case WIRE_GOSSIPSTATUS_PEER_FAILED:
		peer_failed(gossip, msg);
		break;
	case WIRE_GOSSIPSTATUS_PEER_NONGOSSIP:
		if (tal_count(fds) != 2)
			return 2;
		peer_nongossip(gossip, msg, fds[0], fds[1]);
		break;
	}
	return 0;
}

/* Create the `gossipd` subdaemon and send the initialization
 * message */
void gossip_init(struct lightningd *ld)
{
	tal_t *tmpctx = tal_tmpctx(ld);
	u8 *init;
	ld->gossip = new_subd(ld, ld, "lightningd_gossip", NULL,
			      gossip_wire_type_name,
			      gossip_msg, gossip_finished, NULL);
	if (!ld->gossip)
		err(1, "Could not subdaemon gossip");

	init = towire_gossipctl_init(tmpctx, ld->broadcast_interval);
	subd_send_msg(ld->gossip, init);
	tal_free(tmpctx);
}

static bool json_getnodes_reply(struct subd *gossip, const u8 *reply,
				const int *fds,
				struct command *cmd)
{
	struct gossip_getnodes_entry *nodes;
	struct json_result *response = new_json_result(cmd);
	size_t i, j;

	if (!fromwire_gossip_getnodes_reply(reply, reply, NULL, &nodes)) {
		command_fail(cmd, "Malformed gossip_getnodes response");
		return true;
	}

	json_object_start(response, NULL);
	json_array_start(response, "nodes");

	for (i = 0; i < tal_count(nodes); i++) {
		json_object_start(response, NULL);
		json_add_pubkey(response, "nodeid", &nodes[i].nodeid);
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
	return true;
}

static void json_getnodes(struct command *cmd, const char *buffer,
			  const jsmntok_t *params)
{
	struct lightningd *ld = ld_from_dstate(cmd->dstate);
	u8 *req = towire_gossip_getnodes_request(cmd);
	subd_req(cmd, ld->gossip, req, -1, 0, json_getnodes_reply, cmd);
}

static const struct json_command getnodes_command = {
    "getnodes", json_getnodes, "Retrieve all nodes in our local network view",
    "Returns a list of all nodes that we know about"};
AUTODATA(json_command, &getnodes_command);

static bool json_getroute_reply(struct subd *gossip, const u8 *reply, const int *fds,
				struct command *cmd)
{
	struct json_result *response;
	struct route_hop *hops;
	size_t i;

	fromwire_gossip_getroute_reply(reply, reply, NULL, &hops);

	if (tal_count(hops) == 0) {
		command_fail(cmd, "Could not find a route");
		return true;
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
	return true;
}

static void json_getroute(struct command *cmd, const char *buffer, const jsmntok_t *params)
{
	struct pubkey id;
	jsmntok_t *idtok, *msatoshitok, *riskfactortok;
	u64 msatoshi;
	double riskfactor;
	struct lightningd *ld = ld_from_dstate(cmd->dstate);
	if (!json_get_params(buffer, params,
			     "id", &idtok,
			     "msatoshi", &msatoshitok,
			     "riskfactor", &riskfactortok,
			     NULL)) {
		command_fail(cmd, "Need id, msatoshi and riskfactor");
		return;
	}

	if (!pubkey_from_hexstr(buffer + idtok->start,
				idtok->end - idtok->start, &id)) {
		command_fail(cmd, "Invalid id");
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
	u8 *req = towire_gossip_getroute_request(cmd, &cmd->dstate->id, &id, msatoshi, riskfactor*1000);
	subd_req(ld->gossip, ld->gossip, req, -1, 0, json_getroute_reply, cmd);
}

static const struct json_command getroute_command = {
	"getroute", json_getroute,
	"Return route to {id} for {msatoshi}, using {riskfactor}",
	"Returns a {route} array of {id} {msatoshi} {delay}: msatoshi and delay (in blocks) is cumulative."
};
AUTODATA(json_command, &getroute_command);

/* Called upon receiving a getchannels_reply from `gossipd` */
static bool json_getchannels_reply(struct subd *gossip, const u8 *reply,
				   const int *fds, struct command *cmd)
{
	size_t i;
	struct gossip_getchannels_entry *entries;
	struct json_result *response = new_json_result(cmd);
	struct short_channel_id *scid;

	if (!fromwire_gossip_getchannels_reply(reply, reply, NULL, &entries)) {
		command_fail(cmd, "Invalid reply from gossipd");
		return true;
	}

	json_object_start(response, NULL);
	json_array_start(response, "channels");
	for (i = 0; i < tal_count(entries); i++) {
		scid = &entries[i].short_channel_id;
		json_object_start(response, NULL);
		json_add_pubkey(response, "source", &entries[i].source);
		json_add_pubkey(response, "destination",
				&entries[i].destination);
		json_add_bool(response, "active", entries[i].active);
		json_add_num(response, "fee_per_kw", entries[i].fee_per_kw);
		json_add_num(response, "last_update",
			     entries[i].last_update_timestamp);
		json_add_num(response, "flags", entries[i].flags);
		json_add_num(response, "delay", entries[i].delay);
		json_add_string(response, "short_id",
				tal_fmt(reply, "%d:%d:%d/%d", scid->blocknum,
					scid->txnum, scid->outnum,
					entries[i].flags & 0x1));
		json_object_end(response);
	}
	json_array_end(response);
	json_object_end(response);
	command_success(cmd, response);
	return true;
}

static void json_getchannels(struct command *cmd, const char *buffer,
			     const jsmntok_t *params)
{
	struct lightningd *ld = ld_from_dstate(cmd->dstate);
	u8 *req = towire_gossip_getchannels_request(cmd);
	subd_req(ld->gossip, ld->gossip, req, -1, 0, json_getchannels_reply, cmd);
}

static const struct json_command getchannels_command = {
    "getchannels", json_getchannels, "List all known channels.",
    "Returns a 'channels' array with all known channels including their fees."};
AUTODATA(json_command, &getchannels_command);
