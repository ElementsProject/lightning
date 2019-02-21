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
#include <common/amount.h>
#include <common/features.h>
#include <common/json_command.h>
#include <common/json_escaped.h>
#include <common/json_helpers.h>
#include <common/jsonrpc_errors.h>
#include <common/param.h>
#include <common/type_to_string.h>
#include <common/utils.h>
#include <errno.h>
#include <gossipd/gen_gossip_wire.h>
#include <hsmd/capabilities.h>
#include <hsmd/gen_hsm_wire.h>
#include <inttypes.h>
#include <lightningd/connect_control.h>
#include <lightningd/gossip_msg.h>
#include <lightningd/hsm_control.h>
#include <lightningd/json.h>
#include <lightningd/jsonrpc.h>
#include <lightningd/log.h>
#include <lightningd/options.h>
#include <lightningd/ping.h>
#include <sodium/randombytes.h>
#include <string.h>
#include <wire/gen_peer_wire.h>
#include <wire/wire_sync.h>

static void got_txout(struct bitcoind *bitcoind,
		      const struct bitcoin_tx_output *output,
		      struct short_channel_id *scid)
{
	const u8 *script;
	struct amount_sat sat;

	/* output will be NULL if it wasn't found */
	if (output) {
		script = output->script;
		sat = output->amount;
	} else {
		script = NULL;
		sat = AMOUNT_SAT(0);
	}

	subd_send_msg(
	    bitcoind->ld->gossip,
	    towire_gossip_get_txout_reply(scid, scid, sat, script));
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
				  scid, scid, op->sat, op->scriptpubkey));
		tal_free(scid);
	} else if (blockheight >= topo->min_blockheight &&
		   blockheight <= topo->max_blockheight) {
		/* We should have known about this outpoint since it is included
		 * in the range in the DB. The fact that we don't means that
		 * this is either a spent outpoint or an invalid one. Return a
		 * failure. */
		subd_send_msg(gossip, take(towire_gossip_get_txout_reply(
						   NULL, scid, AMOUNT_SAT(0), NULL)));
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
	case WIRE_GOSSIP_GET_CHANNEL_PEER:
	case WIRE_GOSSIP_GET_TXOUT_REPLY:
	case WIRE_GOSSIP_OUTPOINT_SPENT:
	case WIRE_GOSSIP_PAYMENT_FAILURE:
	case WIRE_GOSSIP_QUERY_SCIDS:
	case WIRE_GOSSIP_QUERY_CHANNEL_RANGE:
	case WIRE_GOSSIP_SEND_TIMESTAMP_FILTER:
	case WIRE_GOSSIP_GET_INCOMING_CHANNELS:
	case WIRE_GOSSIP_DEV_SET_MAX_SCIDS_ENCODE_SIZE:
	case WIRE_GOSSIP_DEV_SUPPRESS:
	case WIRE_GOSSIP_LOCAL_CHANNEL_CLOSE:
	case WIRE_GOSSIP_DEV_MEMLEAK:
	/* This is a reply, so never gets through to here. */
	case WIRE_GOSSIP_GETNODES_REPLY:
	case WIRE_GOSSIP_GETROUTE_REPLY:
	case WIRE_GOSSIP_GETCHANNELS_REPLY:
	case WIRE_GOSSIP_SCIDS_REPLY:
	case WIRE_GOSSIP_QUERY_CHANNEL_RANGE_REPLY:
	case WIRE_GOSSIP_GET_CHANNEL_PEER_REPLY:
	case WIRE_GOSSIP_GET_INCOMING_CHANNELS_REPLY:
	case WIRE_GOSSIP_DEV_MEMLEAK_REPLY:
		break;

	case WIRE_GOSSIP_PING_REPLY:
		ping_reply(gossip, msg);
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

	hsmfd = hsm_get_global_fd(ld, HSM_CAP_SIGN_GOSSIP);

	ld->gossip = new_global_subd(ld, "lightning_gossipd",
				     gossip_wire_type_name, gossip_msg,
				     take(&hsmfd), take(&connectd_fd), NULL);
	if (!ld->gossip)
		err(1, "Could not subdaemon gossip");

	msg = towire_gossipctl_init(
	    tmpctx, ld->config.broadcast_interval_msec,
	    &get_chainparams(ld)->genesis_blockhash, &ld->id,
	    get_offered_globalfeatures(tmpctx),
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

/* Gossipd shouldn't give us bad pubkeys, but don't abort if they do */
static void json_add_raw_pubkey(struct json_stream *response,
			 const char *fieldname,
			 const u8 raw_pubkey[sizeof(struct pubkey)])
{
	secp256k1_pubkey pubkey;
	u8 der[PUBKEY_DER_LEN];
	size_t outlen = PUBKEY_DER_LEN;

	memcpy(&pubkey, raw_pubkey, sizeof(pubkey));
	if (!secp256k1_ec_pubkey_serialize(secp256k1_ctx, der, &outlen,
					   &pubkey,
					   SECP256K1_EC_COMPRESSED))
		json_add_string(response, fieldname, "INVALID PUBKEY");
	else
		json_add_hex(response, fieldname, der, sizeof(der));
}

static void json_getnodes_reply(struct subd *gossip UNUSED, const u8 *reply,
				const int *fds UNUSED,
				struct command *cmd)
{
	struct gossip_getnodes_entry **nodes;
	struct json_stream *response;
	size_t i, j;

	if (!fromwire_gossip_getnodes_reply(reply, reply, &nodes)) {
		was_pending(command_fail(cmd, LIGHTNINGD,
					 "Malformed gossip_getnodes response"));
		return;
	}

	response = json_stream_success(cmd);
	json_object_start(response, NULL);
	json_array_start(response, "nodes");

	for (i = 0; i < tal_count(nodes); i++) {
		struct json_escaped *esc;

		json_object_start(response, NULL);
		json_add_raw_pubkey(response, "nodeid", nodes[i]->nodeid);
		if (nodes[i]->last_timestamp < 0) {
			json_object_end(response);
			continue;
		}
		esc = json_escape(NULL,
				  take(tal_strndup(NULL,
						   (const char *)nodes[i]->alias,
						   ARRAY_SIZE(nodes[i]->alias))));
		json_add_escaped_string(response, "alias", take(esc));
		json_add_hex(response, "color",
			     nodes[i]->color, ARRAY_SIZE(nodes[i]->color));
		json_add_u64(response, "last_timestamp",
			     nodes[i]->last_timestamp);
		json_add_hex_talarr(response, "globalfeatures",
				    nodes[i]->globalfeatures);
		if (deprecated_apis)
			json_add_hex_talarr(response, "global_features",
					    nodes[i]->globalfeatures);
		json_array_start(response, "addresses");
		for (j=0; j<tal_count(nodes[i]->addresses); j++) {
			json_add_address(response, NULL, &nodes[i]->addresses[j]);
		}
		json_array_end(response);
		json_object_end(response);
	}
	json_array_end(response);
	json_object_end(response);
	was_pending(command_success(cmd, response));
}

static struct command_result *json_listnodes(struct command *cmd,
					     const char *buffer,
					     const jsmntok_t *obj UNNEEDED,
					     const jsmntok_t *params)
{
	u8 *req;
	struct pubkey *id;

	if (!param(cmd, buffer, params,
		   p_opt("id", param_pubkey, &id),
		   NULL))
		return command_param_failed();

	req = towire_gossip_getnodes_request(cmd, id);
	subd_req(cmd, cmd->ld->gossip, req, -1, 0, json_getnodes_reply, cmd);
	return command_still_pending(cmd);
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
	struct json_stream *response;
	struct route_hop *hops;

	fromwire_gossip_getroute_reply(reply, reply, &hops);

	if (tal_count(hops) == 0) {
		was_pending(command_fail(cmd, PAY_ROUTE_NOT_FOUND,
					 "Could not find a route"));
		return;
	}

	response = json_stream_success(cmd);
	json_object_start(response, NULL);
	json_add_route(response, "route", hops, tal_count(hops));
	json_object_end(response);
	was_pending(command_success(cmd, response));
}

static struct command_result *json_getroute(struct command *cmd,
					    const char *buffer,
					    const jsmntok_t *obj UNNEEDED,
					    const jsmntok_t *params)
{
	struct lightningd *ld = cmd->ld;
	struct pubkey *destination;
	struct pubkey *source;
	const jsmntok_t *excludetok;
	struct amount_msat *msat;
	unsigned *cltv;
	double *riskfactor;
	struct short_channel_id_dir *excluded;
	u32 *max_hops;

	/* Higher fuzz means that some high-fee paths can be discounted
	 * for an even larger value, increasing the scope for route
	 * randomization (the higher-fee paths become more likely to
	 * be selected) at the cost of increasing the probability of
	 * selecting the higher-fee paths. */
	double *fuzz;

	if (!param(cmd, buffer, params,
		   p_req("id", param_pubkey, &destination),
		   p_req("msatoshi", param_msat, &msat),
		   p_req("riskfactor", param_double, &riskfactor),
		   p_opt_def("cltv", param_number, &cltv, 9),
		   p_opt_def("fromid", param_pubkey, &source, ld->id),
		   p_opt_def("fuzzpercent", param_percent, &fuzz, 5.0),
		   p_opt("exclude", param_array, &excludetok),
		   p_opt_def("maxhops", param_number, &max_hops,
			     ROUTING_MAX_HOPS),
		   NULL))
		return command_param_failed();

	/* Convert from percentage */
	*fuzz = *fuzz / 100.0;

	if (excludetok) {
		const jsmntok_t *t;
		size_t i;

		excluded = tal_arr(cmd, struct short_channel_id_dir,
				   excludetok->size);

		json_for_each_arr(i, t, excludetok) {
			if (!short_channel_id_dir_from_str(buffer + t->start,
							   t->end - t->start,
							   &excluded[i],
							   deprecated_apis)) {
				return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
						    "%.*s is not a valid"
						    " short_channel_id/direction",
						    t->end - t->start,
						    buffer + t->start);
			}
		}
	} else {
		excluded = NULL;
	}

	u8 *req = towire_gossip_getroute_request(cmd, source, destination,
						 *msat,
						 *riskfactor * 1000000.0,
						 *cltv, fuzz,
						 excluded,
						 *max_hops);
	subd_req(ld->gossip, ld->gossip, req, -1, 0, json_getroute_reply, cmd);
	return command_still_pending(cmd);
}

static const struct json_command getroute_command = {
	"getroute",
	json_getroute,
	"Show route to {id} for {msatoshi}, using {riskfactor} and optional {cltv} (default 9). "
	"If specified search from {fromid} otherwise use this node as source. "
	"Randomize the route with up to {fuzzpercent} (default 5.0) "
	"using {seed} as an arbitrary-size string seed."
};
AUTODATA(json_command, &getroute_command);

/* Called upon receiving a getchannels_reply from `gossipd` */
static void json_listchannels_reply(struct subd *gossip UNUSED, const u8 *reply,
				   const int *fds UNUSED, struct command *cmd)
{
	size_t i;
	struct gossip_getchannels_entry *entries;
	struct json_stream *response;

	if (!fromwire_gossip_getchannels_reply(reply, reply, &entries)) {
		was_pending(command_fail(cmd, LIGHTNINGD,
					 "Invalid reply from gossipd"));
		return;
	}

	response = json_stream_success(cmd);
	json_object_start(response, NULL);
	json_array_start(response, "channels");
	for (i = 0; i < tal_count(entries); i++) {
		json_object_start(response, NULL);
		json_add_raw_pubkey(response, "source", entries[i].source);
		json_add_raw_pubkey(response, "destination",
				    entries[i].destination);
		json_add_string(response, "short_channel_id",
				type_to_string(reply, struct short_channel_id,
					       &entries[i].short_channel_id));
		json_add_bool(response, "public", entries[i].public);
		json_add_amount_sat(response, entries[i].sat,
				    "satoshis", "amount_msat");
		json_add_num(response, "message_flags", entries[i].message_flags);
		json_add_num(response, "channel_flags", entries[i].channel_flags);
		/* Prior to spec v0891374d47ddffa64c5a2e6ad151247e3d6b7a59, these two were a single u16 field */
		if (deprecated_apis)
			json_add_num(response, "flags", ((u16)entries[i].message_flags << 8) | entries[i].channel_flags);
		json_add_bool(response, "active",
			      !(entries[i].channel_flags & ROUTING_FLAGS_DISABLED)
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
	was_pending(command_success(cmd, response));
}

static struct command_result *json_listchannels(struct command *cmd,
						const char *buffer,
						const jsmntok_t *obj UNNEEDED,
						const jsmntok_t *params)
{
	u8 *req;
	struct short_channel_id *id;
	struct pubkey *source;

	if (!param(cmd, buffer, params,
		   p_opt("short_channel_id", param_short_channel_id, &id),
		   p_opt("source", param_pubkey, &source),
		   NULL))
		return command_param_failed();

	if (id && source)
		return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
				    "Cannot specify both source and short_channel_id");
	req = towire_gossip_getchannels_request(cmd, id, source);
	subd_req(cmd->ld->gossip, cmd->ld->gossip,
		 req, -1, 0, json_listchannels_reply, cmd);
	return command_still_pending(cmd);
}

static const struct json_command listchannels_command = {
	"listchannels",
	json_listchannels,
	"Show channel {short_channel_id} or {source} (or all known channels, if not specified)"
};
AUTODATA(json_command, &listchannels_command);

#if DEVELOPER
static void json_scids_reply(struct subd *gossip UNUSED, const u8 *reply,
			     const int *fds UNUSED, struct command *cmd)
{
	bool ok, complete;
	struct json_stream *response;

	if (!fromwire_gossip_scids_reply(reply, &ok, &complete)) {
		was_pending(command_fail(cmd, LIGHTNINGD,
					 "Gossip gave bad gossip_scids_reply"));
		return;
	}

	if (!ok) {
		was_pending(command_fail(cmd, LIGHTNINGD,
					 "Gossip refused to query peer"));
		return;
	}

	response = json_stream_success(cmd);
	json_object_start(response, NULL);
	json_add_bool(response, "complete", complete);
	json_object_end(response);
	was_pending(command_success(cmd, response));
}

static struct command_result *json_dev_query_scids(struct command *cmd,
						   const char *buffer,
						   const jsmntok_t *obj UNNEEDED,
						   const jsmntok_t *params)
{
	u8 *msg;
	const jsmntok_t *scidstok;
	const jsmntok_t *t;
	struct pubkey *id;
	struct short_channel_id *scids;
	size_t i;

	if (!param(cmd, buffer, params,
		   p_req("id", param_pubkey, &id),
		   p_req("scids", param_array, &scidstok),
		   NULL))
		return command_param_failed();

	scids = tal_arr(cmd, struct short_channel_id, scidstok->size);
	json_for_each_arr(i, t, scidstok) {
		if (!json_to_short_channel_id(buffer, t, &scids[i],
					      deprecated_apis)) {
			return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
					    "scid %zu '%.*s' is not an scid",
					    i, json_tok_full_len(t),
					    json_tok_full(buffer, t));
		}
	}

	/* Tell gossipd, since this is a gossip query. */
	msg = towire_gossip_query_scids(cmd, id, scids);
	subd_req(cmd->ld->gossip, cmd->ld->gossip,
		 take(msg), -1, 0, json_scids_reply, cmd);
	return command_still_pending(cmd);
}

static const struct json_command dev_query_scids_command = {
	"dev-query-scids",
	json_dev_query_scids,
	"Query peer {id} for [scids]"
};
AUTODATA(json_command, &dev_query_scids_command);

static struct command_result *
json_dev_send_timestamp_filter(struct command *cmd,
			       const char *buffer,
			       const jsmntok_t *obj UNNEEDED,
			       const jsmntok_t *params)
{
	u8 *msg;
	struct pubkey *id;
	u32 *first, *range;

	if (!param(cmd, buffer, params,
		   p_req("id", param_pubkey, &id),
		   p_req("first", param_number, &first),
		   p_req("range", param_number, &range),
		   NULL))
		return command_param_failed();

	log_debug(cmd->ld->log, "Setting timestamp range %u+%u", *first, *range);
	/* Tell gossipd, since this is a gossip query. */
	msg = towire_gossip_send_timestamp_filter(NULL, id, *first, *range);
	subd_send_msg(cmd->ld->gossip, take(msg));

	return command_success(cmd, null_response(cmd));
}

static const struct json_command dev_send_timestamp_filter = {
	"dev-send-timestamp-filter",
	json_dev_send_timestamp_filter,
	"Send peer {id} the timestamp filter {first} {range}"
};
AUTODATA(json_command, &dev_send_timestamp_filter);

static void json_channel_range_reply(struct subd *gossip UNUSED, const u8 *reply,
				     const int *fds UNUSED, struct command *cmd)
{
	struct json_stream *response;
	u32 final_first_block, final_num_blocks;
	bool final_complete;
	struct short_channel_id *scids;

	if (!fromwire_gossip_query_channel_range_reply(tmpctx, reply,
						       &final_first_block,
						       &final_num_blocks,
						       &final_complete,
						       &scids)) {
		was_pending(command_fail(cmd, LIGHTNINGD,
					 "Gossip gave bad gossip_query_channel_range_reply"));
		return;
	}

	if (final_num_blocks == 0 && final_num_blocks == 0 && !final_complete) {
		was_pending(command_fail(cmd, LIGHTNINGD,
					 "Gossip refused to query peer"));
		return;
	}

	response = json_stream_success(cmd);
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
	was_pending(command_success(cmd, response));
}

static struct command_result *json_dev_query_channel_range(struct command *cmd,
					 const char *buffer,
					 const jsmntok_t *obj UNNEEDED,
					 const jsmntok_t *params)
{
	u8 *msg;
	struct pubkey *id;
	u32 *first, *num;

	if (!param(cmd, buffer, params,
		   p_req("id", param_pubkey, &id),
		   p_req("first", param_number, &first),
		   p_req("num", param_number, &num),
		   NULL))
		return command_param_failed();

	/* Tell gossipd, since this is a gossip query. */
	msg = towire_gossip_query_channel_range(cmd, id, *first, *num);
	subd_req(cmd->ld->gossip, cmd->ld->gossip,
		 take(msg), -1, 0, json_channel_range_reply, cmd);
	return command_still_pending(cmd);
}

static const struct json_command dev_query_channel_range_command = {
	"dev-query-channel-range",
	json_dev_query_channel_range,
	"Query peer {id} for short_channel_ids for {first} block + {num} blocks"
};
AUTODATA(json_command, &dev_query_channel_range_command);

static struct command_result *
json_dev_set_max_scids_encode_size(struct command *cmd,
				   const char *buffer,
				   const jsmntok_t *obj UNNEEDED,
				   const jsmntok_t *params)
{
	u8 *msg;
	u32 *max;

	if (!param(cmd, buffer, params,
		   p_req("max", param_number, &max),
		   NULL))
		return command_param_failed();

	msg = towire_gossip_dev_set_max_scids_encode_size(NULL, *max);
	subd_send_msg(cmd->ld->gossip, take(msg));

	return command_success(cmd, null_response(cmd));
}

static const struct json_command dev_set_max_scids_encode_size = {
	"dev-set-max-scids-encode-size",
	json_dev_set_max_scids_encode_size,
	"Set {max} bytes of short_channel_ids per reply_channel_range"
};
AUTODATA(json_command, &dev_set_max_scids_encode_size);

static struct command_result *json_dev_suppress_gossip(struct command *cmd,
						       const char *buffer,
						       const jsmntok_t *obj UNNEEDED,
						       const jsmntok_t *params)
{
	if (!param(cmd, buffer, params, NULL))
		return command_param_failed();

	subd_send_msg(cmd->ld->gossip, take(towire_gossip_dev_suppress(NULL)));

	return command_success(cmd, null_response(cmd));
}

static const struct json_command dev_suppress_gossip = {
	"dev-suppress-gossip",
	json_dev_suppress_gossip,
	"Stop this node from sending any more gossip."
};
AUTODATA(json_command, &dev_suppress_gossip);
#endif /* DEVELOPER */
