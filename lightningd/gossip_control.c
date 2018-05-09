#include "bitcoind.h"
#include "chaintopology.h"
#include "gossip_control.h"
#include "lightningd.h"
#include "peer_control.h"
#include "subd.h"
#include <ccan/array_size/array_size.h>
#include <ccan/crypto/siphash24/siphash24.h>
#include <ccan/err/err.h>
#include <ccan/fdpass/fdpass.h>
#include <ccan/take/take.h>
#include <ccan/tal/str/str.h>
#include <common/features.h>
#include <common/json_escaped.h>
#include <common/type_to_string.h>
#include <common/utils.h>
#include <errno.h>
#include <gossipd/gen_gossip_wire.h>
#include <hsmd/capabilities.h>
#include <hsmd/gen_hsm_client_wire.h>
#include <inttypes.h>
#include <lightningd/connect_control.h>
#include <lightningd/gossip_msg.h>
#include <lightningd/hsm_control.h>
#include <lightningd/json.h>
#include <lightningd/jsonrpc.h>
#include <lightningd/log.h>
#include <sodium/randombytes.h>
#include <string.h>
#include <wire/gen_peer_wire.h>
#include <wire/wire_sync.h>

static void peer_nongossip(struct subd *gossip, const u8 *msg,
			   int peer_fd, int gossip_fd)
{
	struct pubkey id;
	struct crypto_state cs;
	struct wireaddr_internal addr;
	u8 *gfeatures, *lfeatures, *in_pkt;

	if (!fromwire_gossip_peer_nongossip(msg, msg,
					    &id, &addr, &cs,
					    &gfeatures,
					    &lfeatures,
					    &in_pkt))
		fatal("Gossip gave bad GOSSIP_PEER_NONGOSSIP message %s",
		      tal_hex(msg, msg));

	/* We already checked the features when it first connected. */
	if (!features_supported(gfeatures, lfeatures)) {
		log_unusual(gossip->log,
			    "Gossip gave unsupported features %s/%s",
			    tal_hex(msg, gfeatures),
			    tal_hex(msg, lfeatures));
		close(peer_fd);
		close(gossip_fd);
		return;
	}

	peer_sent_nongossip(gossip->ld, &id, &addr, &cs,
			    gfeatures, lfeatures,
			    peer_fd, gossip_fd, in_pkt);
}

static void got_txout(struct bitcoind *bitcoind,
		      const struct bitcoin_tx_output *output,
		      struct short_channel_id *scid)
{
	const u8 *script;
	u64 satoshis;

	/* output will be NULL if it wasn't found */
	if (output) {
		script = output->script;
		satoshis = output->amount;
	} else {
		script = NULL;
		satoshis = 0;
	}

	subd_send_msg(
	    bitcoind->ld->gossip,
	    towire_gossip_get_txout_reply(scid, scid, satoshis, script));
	tal_free(scid);
}

static void get_txout(struct subd *gossip, const u8 *msg)
{
	struct short_channel_id *scid = tal(gossip, struct short_channel_id);
	struct outpoint *op;

	if (!fromwire_gossip_get_txout(msg, scid))
		fatal("Gossip gave bad GOSSIP_GET_TXOUT message %s",
		      tal_hex(msg, msg));

	/* FIXME: Block less than 6 deep? */

	op = wallet_outpoint_for_scid(gossip->ld->wallet, scid, scid);

	if (op) {
		subd_send_msg(gossip,
			      towire_gossip_get_txout_reply(
				  scid, scid, op->satoshis, op->scriptpubkey));
		tal_free(scid);
	} else {
		bitcoind_getoutput(gossip->ld->topology->bitcoind,
				   short_channel_id_blocknum(scid),
				   short_channel_id_txnum(scid),
				   short_channel_id_outnum(scid),
				   got_txout, scid);
	}
}

static unsigned gossip_msg(struct subd *gossip, const u8 *msg, const int *fds)
{
	enum gossip_wire_type t = fromwire_peektype(msg);

	switch (t) {
	/* These are messages we send, not them. */
	case WIRE_GOSSIPCTL_INIT:
	case WIRE_GOSSIPCTL_ACTIVATE:
	case WIRE_GOSSIP_GETNODES_REQUEST:
	case WIRE_GOSSIP_GETROUTE_REQUEST:
	case WIRE_GOSSIP_GETCHANNELS_REQUEST:
	case WIRE_GOSSIP_GETPEERS_REQUEST:
	case WIRE_GOSSIP_PING:
	case WIRE_GOSSIP_RESOLVE_CHANNEL_REQUEST:
	case WIRE_GOSSIPCTL_CONNECT_TO_PEER:
	case WIRE_GOSSIPCTL_HAND_BACK_PEER:
	case WIRE_GOSSIPCTL_RELEASE_PEER:
	case WIRE_GOSSIPCTL_PEER_ADDRHINT:
	case WIRE_GOSSIP_GET_UPDATE:
	case WIRE_GOSSIP_SEND_GOSSIP:
	case WIRE_GOSSIP_GET_TXOUT_REPLY:
	case WIRE_GOSSIP_DISABLE_CHANNEL:
	case WIRE_GOSSIP_OUTPOINT_SPENT:
	case WIRE_GOSSIP_ROUTING_FAILURE:
	case WIRE_GOSSIP_MARK_CHANNEL_UNROUTABLE:
	case WIRE_GOSSIPCTL_PEER_DISCONNECT:
	case WIRE_GOSSIPCTL_PEER_IMPORTANT:
	case WIRE_GOSSIPCTL_PEER_DISCONNECTED:
	/* This is a reply, so never gets through to here. */
	case WIRE_GOSSIPCTL_ACTIVATE_REPLY:
	case WIRE_GOSSIP_GET_UPDATE_REPLY:
	case WIRE_GOSSIP_GETNODES_REPLY:
	case WIRE_GOSSIP_GETROUTE_REPLY:
	case WIRE_GOSSIP_GETCHANNELS_REPLY:
	case WIRE_GOSSIP_GETPEERS_REPLY:
	case WIRE_GOSSIP_PING_REPLY:
	case WIRE_GOSSIP_RESOLVE_CHANNEL_REPLY:
	case WIRE_GOSSIPCTL_RELEASE_PEER_REPLY:
	case WIRE_GOSSIPCTL_RELEASE_PEER_REPLYFAIL:
	case WIRE_GOSSIPCTL_PEER_DISCONNECT_REPLY:
	case WIRE_GOSSIPCTL_PEER_DISCONNECT_REPLYFAIL:
	/* These are inter-daemon messages, not received by us */
	case WIRE_GOSSIP_LOCAL_ADD_CHANNEL:
		break;

	case WIRE_GOSSIP_PEER_CONNECTED:
		if (tal_count(fds) != 2)
			return 2;
		peer_connected(gossip->ld, msg, fds[0], fds[1]);
		break;
	case WIRE_GOSSIP_PEER_NONGOSSIP:
		if (tal_count(fds) != 2)
			return 2;
		peer_nongossip(gossip, msg, fds[0], fds[1]);
		break;
	case WIRE_GOSSIP_GET_TXOUT:
		get_txout(gossip, msg);
		break;
	case WIRE_GOSSIPCTL_CONNECT_TO_PEER_RESULT:
		gossip_connect_result(gossip->ld, msg);
		break;
	}
	return 0;
}

/* Create the `gossipd` subdaemon and send the initialization
 * message */
void gossip_init(struct lightningd *ld)
{
	u8 *msg;
	int hsmfd;
	u64 capabilities = HSM_CAP_ECDH | HSM_CAP_SIGN_GOSSIP;
	struct wireaddr_internal *wireaddrs = ld->proposed_wireaddr;
	enum addr_listen_announce *listen_announce = ld->proposed_listen_announce;
	bool allow_localhost = false;
#if DEVELOPER
	if (ld->dev_allow_localhost)
		allow_localhost = true;
#endif

	msg = towire_hsm_client_hsmfd(tmpctx, &ld->id, capabilities);
	if (!wire_sync_write(ld->hsm_fd, msg))
		fatal("Could not write to HSM: %s", strerror(errno));

	msg = hsm_sync_read(tmpctx, ld);
	if (!fromwire_hsm_client_hsmfd_reply(msg))
		fatal("Malformed hsmfd response: %s", tal_hex(msg, msg));

	hsmfd = fdpass_recv(ld->hsm_fd);
	if (hsmfd < 0)
		fatal("Could not read fd from HSM: %s", strerror(errno));

	ld->gossip = new_global_subd(ld, "lightning_gossipd",
				     gossip_wire_type_name, gossip_msg,
				     take(&hsmfd), NULL);
	if (!ld->gossip)
		err(1, "Could not subdaemon gossip");

	/* If no addr (not even Tor auto) specified, hand wildcard to gossipd */
	if (tal_count(wireaddrs) == 0 && ld->autolisten
	    && !ld->config.tor_enable_auto_hidden_service) {
		wireaddrs = tal_arrz(tmpctx, struct wireaddr_internal, 1);
		listen_announce = tal_arr(tmpctx, enum addr_listen_announce, 1);
		wireaddrs->itype = ADDR_INTERNAL_ALLPROTO;
		wireaddrs->u.port = ld->portnum;
		*listen_announce = ADDR_LISTEN_AND_ANNOUNCE;
	}

	msg = towire_gossipctl_init(
	    tmpctx, ld->config.broadcast_interval,
	    &get_chainparams(ld)->genesis_blockhash, &ld->id,
	    get_offered_global_features(tmpctx),
	    get_offered_local_features(tmpctx), wireaddrs,
	    listen_announce, ld->rgb,
	    ld->alias, ld->config.channel_update_interval, ld->reconnect,
	    ld->proxyaddr, ld->use_proxy_always,
	    allow_localhost);
	subd_send_msg(ld->gossip, msg);
}

static void gossip_activate_done(struct subd *gossip UNUSED,
				 const u8 *reply,
				 const int *fds UNUSED,
				 void *unused UNUSED)
{
	struct lightningd *ld = gossip->ld;

	if (!fromwire_gossipctl_activate_reply(gossip->ld, reply,
					       &ld->binding,
					       &ld->announcable))
		fatal("Bad gossipctl_activate_reply: %s",
		      tal_hex(reply, reply));

	/* Break out of loop, so we can begin */
	io_break(gossip);
}

void gossip_activate(struct lightningd *ld)
{
	const u8 *msg = towire_gossipctl_activate(NULL, ld->listen);
	subd_req(ld->gossip, ld->gossip, take(msg), -1, 0,
		 gossip_activate_done, NULL);

	/* Wait for activate done */
	io_loop(NULL, NULL);
}

void gossipd_notify_spend(struct lightningd *ld,
			  const struct short_channel_id *scid)
{
	u8 *msg = towire_gossip_outpoint_spent(tmpctx, scid);
	subd_send_msg(ld->gossip, msg);
}

static void json_getnodes_reply(struct subd *gossip UNUSED, const u8 *reply,
				const int *fds UNUSED,
				struct command *cmd)
{
	struct gossip_getnodes_entry **nodes;
	struct json_result *response = new_json_result(cmd);
	size_t i, j;

	if (!fromwire_gossip_getnodes_reply(reply, reply, &nodes)) {
		command_fail(cmd, "Malformed gossip_getnodes response");
		return;
	}

	json_object_start(response, NULL);
	json_array_start(response, "nodes");

	for (i = 0; i < tal_count(nodes); i++) {
		struct json_escaped *esc;

		json_object_start(response, NULL);
		json_add_pubkey(response, "nodeid", &nodes[i]->nodeid);
		if (nodes[i]->last_timestamp < 0) {
			json_object_end(response);
			continue;
		}
		esc = json_escape(NULL, (const char *)nodes[i]->alias);
		json_add_escaped_string(response, "alias", take(esc));
		json_add_hex(response, "color",
			     nodes[i]->color, ARRAY_SIZE(nodes[i]->color));
		json_add_u64(response, "last_timestamp",
			     nodes[i]->last_timestamp);
		json_array_start(response, "addresses");
		for (j=0; j<tal_count(nodes[i]->addresses); j++) {
			json_add_address(response, NULL, &nodes[i]->addresses[j]);
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

	if (!json_get_params(cmd, buffer, params,
			     "?id", &idtok,
			     NULL)) {
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
	"listnodes",
	json_listnodes,
	"Show node {id} (or all, if no {id}), in our local network view"
};
AUTODATA(json_command, &listnodes_command);

static void json_getroute_reply(struct subd *gossip UNUSED, const u8 *reply, const int *fds UNUSED,
				struct command *cmd)
{
	struct json_result *response;
	struct route_hop *hops;

	fromwire_gossip_getroute_reply(reply, reply, &hops);

	if (tal_count(hops) == 0) {
		command_fail(cmd, "Could not find a route");
		return;
	}

	response = new_json_result(cmd);
	json_object_start(response, NULL);
	json_add_route(response, "route", hops, tal_count(hops));
	json_object_end(response);
	command_success(cmd, response);
}

static void json_getroute(struct command *cmd, const char *buffer, const jsmntok_t *params)
{
	struct lightningd *ld = cmd->ld;
	struct pubkey source = ld->id, destination;
	jsmntok_t *idtok, *msatoshitok, *riskfactortok, *cltvtok, *fromidtok;
	jsmntok_t *fuzztok;
	jsmntok_t *seedtok;
	u64 msatoshi;
	unsigned cltv = 9;
	double riskfactor;
	/* Higher fuzz means that some high-fee paths can be discounted
	 * for an even larger value, increasing the scope for route
	 * randomization (the higher-fee paths become more likely to
	 * be selected) at the cost of increasing the probability of
	 * selecting the higher-fee paths. */
	double fuzz = 75.0;
	struct siphash_seed seed;

	if (!json_get_params(cmd, buffer, params,
			     "id", &idtok,
			     "msatoshi", &msatoshitok,
			     "riskfactor", &riskfactortok,
			     "?cltv", &cltvtok,
			     "?fromid", &fromidtok,
			     "?fuzzpercent", &fuzztok,
			     "?seed", &seedtok,
			     NULL)) {
		return;
	}

	if (!json_tok_pubkey(buffer, idtok, &destination)) {
		command_fail(cmd, "Invalid id");
		return;
	}

	if (cltvtok && !json_tok_number(buffer, cltvtok, &cltv)) {
		command_fail(cmd, "Invalid cltv");
		return;
	}

	if (!json_tok_u64(buffer, msatoshitok, &msatoshi)) {
		command_fail(cmd, "'%.*s' is not a valid number",
			     msatoshitok->end - msatoshitok->start,
			     buffer + msatoshitok->start);
		return;
	}

	if (!json_tok_double(buffer, riskfactortok, &riskfactor)) {
		command_fail(cmd, "'%.*s' is not a valid double",
			     riskfactortok->end - riskfactortok->start,
			     buffer + riskfactortok->start);
		return;
	}

	if (fromidtok && !json_tok_pubkey(buffer, fromidtok, &source)) {
		command_fail(cmd, "Invalid from id");
		return;
	}

	if (fuzztok &&
	    !json_tok_double(buffer, fuzztok, &fuzz)) {
		command_fail(cmd, "'%.*s' is not a valid double",
			     fuzztok->end - fuzztok->start,
			     buffer + fuzztok->start);
		return;
	}
	if (!(0.0 <= fuzz && fuzz <= 100.0)) {
		command_fail(cmd,
			     "fuzz must be in range 0.0 <= %f <= 100.0",
			     fuzz);
		return;
	}
	/* Convert from percentage */
	fuzz = fuzz / 100.0;

	if (seedtok) {
		if (seedtok->end - seedtok->start > sizeof(seed))
			command_fail(cmd,
				     "seed must be < %zu bytes", sizeof(seed));

		memset(&seed, 0, sizeof(seed));
		memcpy(&seed, buffer + seedtok->start,
		       seedtok->end - seedtok->start);
	} else
		randombytes_buf(&seed, sizeof(seed));

	u8 *req = towire_gossip_getroute_request(cmd, &source, &destination, msatoshi, riskfactor*1000, cltv, &fuzz, &seed);
	subd_req(ld->gossip, ld->gossip, req, -1, 0, json_getroute_reply, cmd);
	command_still_pending(cmd);
}

static const struct json_command getroute_command = {
	"getroute",
	json_getroute,
	"Show route to {id} for {msatoshi}, using {riskfactor} and optional {cltv} (default 9). "
	"If specified search from {fromid} otherwise use this node as source. "
	"Randomize the route with up to {fuzzpercent} (0.0 -> 100.0, default 5.0) "
	"using {seed} as an arbitrary-size string seed."
};
AUTODATA(json_command, &getroute_command);

/* Called upon receiving a getchannels_reply from `gossipd` */
static void json_listchannels_reply(struct subd *gossip UNUSED, const u8 *reply,
				   const int *fds UNUSED, struct command *cmd)
{
	size_t i;
	struct gossip_getchannels_entry *entries;
	struct json_result *response = new_json_result(cmd);

	if (!fromwire_gossip_getchannels_reply(reply, reply, &entries)) {
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
		json_add_u64(response, "satoshis", entries[i].satoshis);
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

	if (!json_get_params(cmd, buffer, params,
			     "?short_channel_id", &idtok,
			     NULL)) {
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
	"listchannels",
	json_listchannels,
	"Show channel {short_channel_id} (or all known channels, if no {short_channel_id})"
};
AUTODATA(json_command, &listchannels_command);
