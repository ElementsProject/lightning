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
#include <lightningd/jsonrpc_errors.h>
#include <lightningd/log.h>
#include <lightningd/param.h>
#include <sodium/randombytes.h>
#include <string.h>
#include <wire/gen_peer_wire.h>
#include <wire/wire_sync.h>

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
	u32 blockheight;
	struct chain_topology *topo = gossip->ld->topology;

	if (!fromwire_gossip_get_txout(msg, scid))
		fatal("Gossip gave bad GOSSIP_GET_TXOUT message %s",
		      tal_hex(msg, msg));

	/* FIXME: Block less than 6 deep? */
	blockheight = short_channel_id_blocknum(scid);

	op = wallet_outpoint_for_scid(gossip->ld->wallet, scid, scid);

	if (op) {
		subd_send_msg(gossip,
			      towire_gossip_get_txout_reply(
				  scid, scid, op->satoshis, op->scriptpubkey));
		tal_free(scid);
	} else if (blockheight >= topo->min_blockheight &&
		   blockheight <= topo->max_blockheight) {
		/* We should have known about this outpoint since it is included
		 * in the range in the DB. The fact that we don't means that
		 * this is either a spent outpoint or an invalid one. Return a
		 * failure. */
		subd_send_msg(gossip, take(towire_gossip_get_txout_reply(
					  NULL, scid, 0, NULL)));
		tal_free(scid);
	} else {
		bitcoind_getoutput(topo->bitcoind,
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
	case WIRE_GOSSIP_GETNODES_REQUEST:
	case WIRE_GOSSIP_GETROUTE_REQUEST:
	case WIRE_GOSSIP_GETCHANNELS_REQUEST:
	case WIRE_GOSSIP_PING:
	case WIRE_GOSSIP_RESOLVE_CHANNEL_REQUEST:
	case WIRE_GOSSIP_GET_UPDATE:
	case WIRE_GOSSIP_SEND_GOSSIP:
	case WIRE_GOSSIP_GET_TXOUT_REPLY:
	case WIRE_GOSSIP_OUTPOINT_SPENT:
	case WIRE_GOSSIP_ROUTING_FAILURE:
	case WIRE_GOSSIP_MARK_CHANNEL_UNROUTABLE:
	case WIRE_GOSSIP_QUERY_SCIDS:
	case WIRE_GOSSIP_QUERY_CHANNEL_RANGE:
	case WIRE_GOSSIP_SEND_TIMESTAMP_FILTER:
	case WIRE_GOSSIP_DEV_SET_MAX_SCIDS_ENCODE_SIZE:
	case WIRE_GOSSIP_DEV_SUPPRESS:
	/* This is a reply, so never gets through to here. */
	case WIRE_GOSSIP_GET_UPDATE_REPLY:
	case WIRE_GOSSIP_GETNODES_REPLY:
	case WIRE_GOSSIP_GETROUTE_REPLY:
	case WIRE_GOSSIP_GETCHANNELS_REPLY:
	case WIRE_GOSSIP_PING_REPLY:
	case WIRE_GOSSIP_SCIDS_REPLY:
	case WIRE_GOSSIP_QUERY_CHANNEL_RANGE_REPLY:
	case WIRE_GOSSIP_RESOLVE_CHANNEL_REPLY:
	/* These are inter-daemon messages, not received by us */
	case WIRE_GOSSIP_LOCAL_ADD_CHANNEL:
	case WIRE_GOSSIP_LOCAL_CHANNEL_UPDATE:
	case WIRE_GOSSIP_LOCAL_CHANNEL_CLOSE:
		break;

	case WIRE_GOSSIP_GET_TXOUT:
		get_txout(gossip, msg);
		break;
	}
	return 0;
}

/* Create the `gossipd` subdaemon and send the initialization
 * message */
void gossip_init(struct lightningd *ld, int connectd_fd)
{
	u8 *msg;
	int hsmfd;
	u64 capabilities = HSM_CAP_SIGN_GOSSIP;

	msg = towire_hsm_client_hsmfd(tmpctx, &ld->id, 0, capabilities);
	if (!wire_sync_write(ld->hsm_fd, msg))
		fatal("Could not write to HSM: %s", strerror(errno));

	msg = wire_sync_read(tmpctx, ld->hsm_fd);
	if (!fromwire_hsm_client_hsmfd_reply(msg))
		fatal("Malformed hsmfd response: %s", tal_hex(msg, msg));

	hsmfd = fdpass_recv(ld->hsm_fd);
	if (hsmfd < 0)
		fatal("Could not read fd from HSM: %s", strerror(errno));

	ld->gossip = new_global_subd(ld, "lightning_gossipd",
				     gossip_wire_type_name, gossip_msg,
				     take(&hsmfd), take(&connectd_fd), NULL);
	if (!ld->gossip)
		err(1, "Could not subdaemon gossip");

	msg = towire_gossipctl_init(
	    tmpctx, ld->config.broadcast_interval,
	    &get_chainparams(ld)->genesis_blockhash, &ld->id,
	    get_offered_global_features(tmpctx),
	    ld->rgb,
	    ld->alias, ld->config.channel_update_interval,
	    ld->announcable);
	subd_send_msg(ld->gossip, msg);
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
		command_fail(cmd, LIGHTNINGD, "Malformed gossip_getnodes response");
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
		json_add_hex_talarr(response, "global_features",
				    nodes[i]->global_features);
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
	struct pubkey *id;

	if (!param(cmd, buffer, params,
		   p_opt("id", json_tok_pubkey, &id),
		   NULL))
		return;

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
		command_fail(cmd, LIGHTNINGD, "Could not find a route");
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
	struct pubkey destination;
	struct pubkey source;
	jsmntok_t *seedtok;
	u64 msatoshi;
	unsigned cltv;
	double riskfactor;
	/* Higher fuzz means that some high-fee paths can be discounted
	 * for an even larger value, increasing the scope for route
	 * randomization (the higher-fee paths become more likely to
	 * be selected) at the cost of increasing the probability of
	 * selecting the higher-fee paths. */
	double fuzz;
	struct siphash_seed seed;

	if (!param(cmd, buffer, params,
		   p_req("id", json_tok_pubkey, &destination),
		   p_req("msatoshi", json_tok_u64, &msatoshi),
		   p_req("riskfactor", json_tok_double, &riskfactor),
		   p_opt_def("cltv", json_tok_number, &cltv, 9),
		   p_opt_def("fromid", json_tok_pubkey, &source, ld->id),
		   p_opt_def("fuzzpercent", json_tok_double, &fuzz, 75.0),
		   p_opt_tok("seed", &seedtok),
		   NULL))
		return;

	if (!(0.0 <= fuzz && fuzz <= 100.0)) {
		command_fail(cmd, JSONRPC2_INVALID_PARAMS,
			     "fuzz must be in range 0.0 <= %f <= 100.0",
			     fuzz);
		return;
	}
	/* Convert from percentage */
	fuzz = fuzz / 100.0;

	if (seedtok) {
		if (seedtok->end - seedtok->start > sizeof(seed))
			command_fail(cmd, JSONRPC2_INVALID_PARAMS,
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
		command_fail(cmd, LIGHTNINGD, "Invalid reply from gossipd");
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
		json_add_bool(response, "public", entries[i].public);
		json_add_u64(response, "satoshis", entries[i].satoshis);
		json_add_num(response, "flags", entries[i].flags);
		json_add_bool(response, "active",
			      !(entries[i].flags & ROUTING_FLAGS_DISABLED)
			      && !entries[i].local_disabled);
		json_add_num(response, "last_update",
			     entries[i].last_update_timestamp);
		json_add_num(response, "base_fee_millisatoshi",
			     entries[i].base_fee_msat);
		json_add_num(response, "fee_per_millionth",
			     entries[i].fee_per_millionth);
		json_add_num(response, "delay", entries[i].delay);
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
	struct short_channel_id *id;
	if (!param(cmd, buffer, params,
		   p_opt("short_channel_id", json_tok_short_channel_id, &id),
		   NULL))
		return;

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

#if DEVELOPER
static void json_scids_reply(struct subd *gossip UNUSED, const u8 *reply,
			     const int *fds UNUSED, struct command *cmd)
{
	bool ok, complete;
	struct json_result *response = new_json_result(cmd);

	if (!fromwire_gossip_scids_reply(reply, &ok, &complete)) {
		command_fail(cmd, LIGHTNINGD,
			     "Gossip gave bad gossip_scids_reply");
		return;
	}

	if (!ok) {
		command_fail(cmd, LIGHTNINGD,
			     "Gossip refused to query peer");
		return;
	}

	json_object_start(response, NULL);
	json_add_bool(response, "complete", complete);
	json_object_end(response);
	command_success(cmd, response);
}

static void json_dev_query_scids(struct command *cmd,
				 const char *buffer, const jsmntok_t *params)
{
	u8 *msg;
	const jsmntok_t *scidstok;
	const jsmntok_t *t, *end;
	struct pubkey id;
	struct short_channel_id *scids;
	size_t i;

	if (!param(cmd, buffer, params,
		   p_req("id", json_tok_pubkey, &id),
		   p_req("scids", json_tok_tok, &scidstok),
		   NULL))
		return;

	if (scidstok->type != JSMN_ARRAY) {
		command_fail(cmd, JSONRPC2_INVALID_PARAMS,
			     "'%.*s' is not an array",
			     scidstok->end - scidstok->start,
			     buffer + scidstok->start);
		return;
	}

	scids = tal_arr(cmd, struct short_channel_id, scidstok->size);
	end = json_next(scidstok);
	for (i = 0, t = scidstok + 1; t < end; t = json_next(t), i++) {
		if (!json_tok_short_channel_id(buffer, t, &scids[i])) {
			command_fail(cmd, JSONRPC2_INVALID_PARAMS,
				     "scid %zu '%.*s' is not an scid",
				     i, t->end - t->start,
				     buffer + t->start);
			return;
		}
	}

	/* Tell gossipd, since this is a gossip query. */
	msg = towire_gossip_query_scids(cmd, &id, scids);
	subd_req(cmd->ld->gossip, cmd->ld->gossip,
		 take(msg), -1, 0, json_scids_reply, cmd);
	command_still_pending(cmd);
}

static const struct json_command dev_query_scids_command = {
	"dev-query-scids",
	json_dev_query_scids,
	"Query {peerid} for [scids]"
};
AUTODATA(json_command, &dev_query_scids_command);

static void json_dev_send_timestamp_filter(struct command *cmd,
					   const char *buffer,
					   const jsmntok_t *params)
{
	u8 *msg;
	struct pubkey id;
	u32 first, range;

	if (!param(cmd, buffer, params,
		   p_req("id", json_tok_pubkey, &id),
		   p_req("first", json_tok_number, &first),
		   p_req("range", json_tok_number, &range),
		   NULL))
		return;

	log_debug(cmd->ld->log, "Setting timestamp range %u+%u", first, range);
	/* Tell gossipd, since this is a gossip query. */
	msg = towire_gossip_send_timestamp_filter(NULL, &id, first, range);
	subd_send_msg(cmd->ld->gossip, take(msg));

	command_success(cmd, null_response(cmd));
}

static const struct json_command dev_send_timestamp_filter = {
	"dev-send-timestamp-filter",
	json_dev_send_timestamp_filter,
	"Send {peerid} the timestamp filter {first} {range}"
};
AUTODATA(json_command, &dev_send_timestamp_filter);

static void json_channel_range_reply(struct subd *gossip UNUSED, const u8 *reply,
				     const int *fds UNUSED, struct command *cmd)
{
	struct json_result *response = new_json_result(cmd);
	u32 final_first_block, final_num_blocks;
	bool final_complete;
	struct short_channel_id *scids;

	if (!fromwire_gossip_query_channel_range_reply(tmpctx, reply,
						       &final_first_block,
						       &final_num_blocks,
						       &final_complete,
						       &scids)) {
		command_fail(cmd, LIGHTNINGD,
			     "Gossip gave bad gossip_query_channel_range_reply");
		return;
	}

	if (final_num_blocks == 0 && final_num_blocks == 0 && !final_complete) {
		command_fail(cmd, LIGHTNINGD,
			     "Gossip refused to query peer");
		return;
	}

	json_object_start(response, NULL);
	/* As this is a dev interface, we don't bother saving and
	 * returning all the replies, just the final one. */
	json_add_num(response, "final_first_block", final_first_block);
	json_add_num(response, "final_num_blocks", final_num_blocks);
	json_add_bool(response, "final_complete", final_complete);
	json_array_start(response, "short_channel_ids");
	for (size_t i = 0; i < tal_count(scids); i++)
		json_add_short_channel_id(response, NULL, &scids[i]);
	json_array_end(response);
	json_object_end(response);
	command_success(cmd, response);
}

static void json_dev_query_channel_range(struct command *cmd,
					 const char *buffer,
					 const jsmntok_t *params)
{
	u8 *msg;
	struct pubkey id;
	u32 first, num;

	if (!param(cmd, buffer, params,
		   p_req("id", json_tok_pubkey, &id),
		   p_req("first", json_tok_number, &first),
		   p_req("num", json_tok_number, &num),
		   NULL))
		return;

	/* Tell gossipd, since this is a gossip query. */
	msg = towire_gossip_query_channel_range(cmd, &id, first, num);
	subd_req(cmd->ld->gossip, cmd->ld->gossip,
		 take(msg), -1, 0, json_channel_range_reply, cmd);
	command_still_pending(cmd);
}

static const struct json_command dev_query_channel_range_command = {
	"dev-query-channel-range",
	json_dev_query_channel_range,
	"Query {peerid} for short_channel_ids for {first} block + {num} blocks"
};
AUTODATA(json_command, &dev_query_channel_range_command);

static void json_dev_set_max_scids_encode_size(struct command *cmd,
					       const char *buffer,
					       const jsmntok_t *params)
{
	u8 *msg;
	u32 max;

	if (!param(cmd, buffer, params,
		   p_req("max", json_tok_number, &max),
		   NULL))
		return;

	msg = towire_gossip_dev_set_max_scids_encode_size(NULL, max);
	subd_send_msg(cmd->ld->gossip, take(msg));

	command_success(cmd, null_response(cmd));
}

static const struct json_command dev_set_max_scids_encode_size = {
	"dev-set-max-scids-encode-size",
	json_dev_set_max_scids_encode_size,
	"Set {max} bytes of short_channel_ids per reply_channel_range"
};
AUTODATA(json_command, &dev_set_max_scids_encode_size);

static void json_dev_suppress_gossip(struct command *cmd,
				     const char *buffer,
				     const jsmntok_t *params)
{
	if (!param(cmd, buffer, params, NULL))
		return;

	subd_send_msg(cmd->ld->gossip, take(towire_gossip_dev_suppress(NULL)));

	command_success(cmd, null_response(cmd));
}

static const struct json_command dev_suppress_gossip = {
	"dev-suppress-gossip",
	json_dev_suppress_gossip,
	"Stop this node from sending any more gossip."
};
AUTODATA(json_command, &dev_suppress_gossip);
#endif /* DEVELOPER */
