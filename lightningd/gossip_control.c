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
#include <ccan/json_escape/json_escape.h>
#include <ccan/take/take.h>
#include <ccan/tal/str/str.h>
#include <common/amount.h>
#include <common/features.h>
#include <common/json_command.h>
#include <common/json_helpers.h>
#include <common/jsonrpc_errors.h>
#include <common/param.h>
#include <common/type_to_string.h>
#include <common/utils.h>
#include <errno.h>
#include <gossipd/gossipd_wiregen.h>
#include <hsmd/capabilities.h>
#include <inttypes.h>
#include <lightningd/connect_control.h>
#include <lightningd/gossip_msg.h>
#include <lightningd/hsm_control.h>
#include <lightningd/json.h>
#include <lightningd/jsonrpc.h>
#include <lightningd/log.h>
#include <lightningd/onion_message.h>
#include <lightningd/options.h>
#include <lightningd/ping.h>
#include <sodium/randombytes.h>
#include <string.h>
#include <wire/peer_wire.h>
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
	    towire_gossipd_get_txout_reply(scid, scid, sat, script));
	tal_free(scid);
}

static void got_filteredblock(struct bitcoind *bitcoind,
		      const struct filteredblock *fb,
		      struct short_channel_id *scid)
{
	struct filteredblock_outpoint *fbo = NULL, *o;
	struct bitcoin_tx_output txo;

	/* If we failed to the filtered block we report the failure to
	 * got_txout. */
	if (fb == NULL)
		return got_txout(bitcoind, NULL, scid);

	/* Only fill in blocks that we are not going to scan later. */
	if (bitcoind->ld->topology->max_blockheight > fb->height)
		wallet_filteredblock_add(bitcoind->ld->wallet, fb);

	u32 outnum = short_channel_id_outnum(scid);
	u32 txindex = short_channel_id_txnum(scid);
	for (size_t i=0; i<tal_count(fb->outpoints); i++) {
		o = fb->outpoints[i];
		if (o->txindex == txindex && o->outnum == outnum) {
			fbo = o;
			break;
		}
	}

	if (fbo) {
		txo.amount = fbo->amount;
		txo.script = (u8 *)fbo->scriptPubKey;
		got_txout(bitcoind, &txo, scid);
	} else
		got_txout(bitcoind, NULL, scid);
}

static void get_txout(struct subd *gossip, const u8 *msg)
{
	struct short_channel_id *scid = tal(gossip, struct short_channel_id);
	struct outpoint *op;
	u32 blockheight;
	struct chain_topology *topo = gossip->ld->topology;

	if (!fromwire_gossipd_get_txout(msg, scid))
		fatal("Gossip gave bad GOSSIP_GET_TXOUT message %s",
		      tal_hex(msg, msg));

	/* FIXME: Block less than 6 deep? */
	blockheight = short_channel_id_blocknum(scid);

	op = wallet_outpoint_for_scid(gossip->ld->wallet, scid, scid);

	if (op) {
		subd_send_msg(gossip,
			      towire_gossipd_get_txout_reply(
				  scid, scid, op->sat, op->scriptpubkey));
		tal_free(scid);
	} else if (wallet_have_block(gossip->ld->wallet, blockheight)) {
		/* We should have known about this outpoint since its header
		 * is in the DB. The fact that we don't means that this is
		 * either a spent outpoint or an invalid one. Return a
		 * failure. */
		subd_send_msg(gossip, take(towire_gossipd_get_txout_reply(
						   NULL, scid, AMOUNT_SAT(0), NULL)));
		tal_free(scid);
	} else {
		bitcoind_getfilteredblock(topo->bitcoind, short_channel_id_blocknum(scid), got_filteredblock, scid);
	}
}

static unsigned gossip_msg(struct subd *gossip, const u8 *msg, const int *fds)
{
	enum gossipd_wire t = fromwire_peektype(msg);

	switch (t) {
	/* These are messages we send, not them. */
	case WIRE_GOSSIPD_INIT:
	case WIRE_GOSSIPD_GETNODES_REQUEST:
	case WIRE_GOSSIPD_GETROUTE_REQUEST:
	case WIRE_GOSSIPD_GETCHANNELS_REQUEST:
	case WIRE_GOSSIPD_PING:
	case WIRE_GOSSIPD_GET_STRIPPED_CUPDATE:
	case WIRE_GOSSIPD_GET_TXOUT_REPLY:
	case WIRE_GOSSIPD_OUTPOINT_SPENT:
	case WIRE_GOSSIPD_PAYMENT_FAILURE:
	case WIRE_GOSSIPD_GET_INCOMING_CHANNELS:
	case WIRE_GOSSIPD_DEV_SET_MAX_SCIDS_ENCODE_SIZE:
	case WIRE_GOSSIPD_DEV_SUPPRESS:
	case WIRE_GOSSIPD_LOCAL_CHANNEL_CLOSE:
	case WIRE_GOSSIPD_DEV_MEMLEAK:
	case WIRE_GOSSIPD_DEV_COMPACT_STORE:
	case WIRE_GOSSIPD_DEV_SET_TIME:
	case WIRE_GOSSIPD_NEW_BLOCKHEIGHT:
	case WIRE_GOSSIPD_SEND_ONIONMSG:
	/* This is a reply, so never gets through to here. */
	case WIRE_GOSSIPD_GETNODES_REPLY:
	case WIRE_GOSSIPD_GETROUTE_REPLY:
	case WIRE_GOSSIPD_GETCHANNELS_REPLY:
	case WIRE_GOSSIPD_GET_INCOMING_CHANNELS_REPLY:
	case WIRE_GOSSIPD_DEV_MEMLEAK_REPLY:
	case WIRE_GOSSIPD_DEV_COMPACT_STORE_REPLY:
	case WIRE_GOSSIPD_GET_STRIPPED_CUPDATE_REPLY:
		break;

#if EXPERIMENTAL_FEATURES
	case WIRE_GOSSIPD_GOT_ONIONMSG_TO_US:
		handle_onionmsg_to_us(gossip->ld, msg);
		break;
	case WIRE_GOSSIPD_GOT_ONIONMSG_FORWARD:
		handle_onionmsg_forward(gossip->ld, msg);
		break;
#else
	case WIRE_GOSSIPD_GOT_ONIONMSG_TO_US:
	case WIRE_GOSSIPD_GOT_ONIONMSG_FORWARD:
		break;
#endif
	case WIRE_GOSSIPD_PING_REPLY:
		ping_reply(gossip, msg);
		break;

	case WIRE_GOSSIPD_GET_TXOUT:
		get_txout(gossip, msg);
		break;
	}
	return 0;
}

void gossip_notify_new_block(struct lightningd *ld, u32 blockheight)
{
	/* Only notify gossipd once we're synced. */
	if (!topology_synced(ld->topology))
		return;

	subd_send_msg(ld->gossip,
		      take(towire_gossipd_new_blockheight(NULL, blockheight)));
}

static void gossip_topology_synced(struct chain_topology *topo, void *unused)
{
	/* Now we start telling gossipd about blocks. */
	gossip_notify_new_block(topo->ld, get_block_height(topo));
}

/* Create the `gossipd` subdaemon and send the initialization
 * message */
void gossip_init(struct lightningd *ld, int connectd_fd)
{
	u8 *msg;
	int hsmfd;

	hsmfd = hsm_get_global_fd(ld, HSM_CAP_ECDH|HSM_CAP_SIGN_GOSSIP);

	ld->gossip = new_global_subd(ld, "lightning_gossipd",
				     gossipd_wire_name, gossip_msg,
				     take(&hsmfd), take(&connectd_fd), NULL);
	if (!ld->gossip)
		err(1, "Could not subdaemon gossip");

	/* We haven't started topology yet, so tell us when we're synced. */
	topology_add_sync_waiter(ld->gossip, ld->topology,
				 gossip_topology_synced, NULL);

	msg = towire_gossipd_init(
	    tmpctx,
	    chainparams,
	    ld->our_features,
	    &ld->id,
	    ld->rgb,
	    ld->alias,
	    ld->announcable,
	    IFDEV(ld->dev_gossip_time ? &ld->dev_gossip_time: NULL, NULL),
	    IFDEV(ld->dev_fast_gossip, false),
	    IFDEV(ld->dev_fast_gossip_prune, false));
	subd_send_msg(ld->gossip, msg);
}

void gossipd_notify_spend(struct lightningd *ld,
			  const struct short_channel_id *scid)
{
	u8 *msg = towire_gossipd_outpoint_spent(tmpctx, scid);
	subd_send_msg(ld->gossip, msg);
}

static void json_getnodes_reply(struct subd *gossip UNUSED, const u8 *reply,
				const int *fds UNUSED,
				struct command *cmd)
{
	struct gossip_getnodes_entry **nodes;
	struct json_stream *response;
	size_t i, j;

	if (!fromwire_gossipd_getnodes_reply(reply, reply, &nodes)) {
		was_pending(command_fail(cmd, LIGHTNINGD,
					 "Malformed gossip_getnodes response"));
		return;
	}

	response = json_stream_success(cmd);
	json_array_start(response, "nodes");

	for (i = 0; i < tal_count(nodes); i++) {
		struct json_escape *esc;

		json_object_start(response, NULL);
		json_add_node_id(response, "nodeid", &nodes[i]->nodeid);
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
		json_add_hex_talarr(response, "features", nodes[i]->features);
		json_array_start(response, "addresses");
		for (j=0; j<tal_count(nodes[i]->addresses); j++) {
			json_add_address(response, NULL, &nodes[i]->addresses[j]);
		}
		json_array_end(response);
		json_object_end(response);
	}
	json_array_end(response);
	was_pending(command_success(cmd, response));
}

static struct command_result *json_listnodes(struct command *cmd,
					     const char *buffer,
					     const jsmntok_t *obj UNNEEDED,
					     const jsmntok_t *params)
{
	u8 *req;
	struct node_id *id;

	if (!param(cmd, buffer, params,
		   p_opt("id", param_node_id, &id),
		   NULL))
		return command_param_failed();

	req = towire_gossipd_getnodes_request(cmd, id);
	subd_req(cmd, cmd->ld->gossip, req, -1, 0, json_getnodes_reply, cmd);
	return command_still_pending(cmd);
}

static const struct json_command listnodes_command = {
	"listnodes",
	"network",
	json_listnodes,
	"Show node {id} (or all, if no {id}), in our local network view"
};
AUTODATA(json_command, &listnodes_command);

static void json_add_route_hop_style(struct json_stream *response,
				     const char *fieldname,
				     enum route_hop_style style)
{
	switch (style) {
	case ROUTE_HOP_LEGACY:
		json_add_string(response, fieldname, "legacy");
		return;
	case ROUTE_HOP_TLV:
		json_add_string(response, fieldname, "tlv");
		return;
	}
	fatal("Unknown route_hop_style %u", style);
}

/* Output a route hop */
static void json_add_route_hop(struct json_stream *r, char const *n,
			       const struct route_hop *h)
{
	/* Imitate what getroute/sendpay use */
	json_object_start(r, n);
	json_add_node_id(r, "id", &h->nodeid);
	json_add_short_channel_id(r, "channel",
				  &h->channel_id);
	json_add_num(r, "direction", h->direction);
	json_add_amount_msat_compat(r, h->amount, "msatoshi", "amount_msat");
	json_add_num(r, "delay", h->delay);
	json_add_route_hop_style(r, "style", h->style);
	json_object_end(r);
}

/* Output a route */
static void json_add_route(struct json_stream *r, char const *n,
			   struct route_hop **hops, size_t hops_len)
{
	size_t i;
	json_array_start(r, n);
	for (i = 0; i < hops_len; ++i) {
		json_add_route_hop(r, NULL, hops[i]);
	}
	json_array_end(r);
}

static void json_getroute_reply(struct subd *gossip UNUSED, const u8 *reply, const int *fds UNUSED,
				struct command *cmd)
{
	struct json_stream *response;
	struct route_hop **hops;

	fromwire_gossipd_getroute_reply(reply, reply, &hops);

	if (tal_count(hops) == 0) {
		was_pending(command_fail(cmd, PAY_ROUTE_NOT_FOUND,
					 "Could not find a route"));
		return;
	}

	response = json_stream_success(cmd);
	json_add_route(response, "route", hops, tal_count(hops));
	was_pending(command_success(cmd, response));
}

static struct command_result *json_getroute(struct command *cmd,
					    const char *buffer,
					    const jsmntok_t *obj UNNEEDED,
					    const jsmntok_t *params)
{
	struct lightningd *ld = cmd->ld;
	struct node_id *destination;
	struct node_id *source;
	const jsmntok_t *excludetok;
	struct amount_msat *msat;
	u32 *cltv;
	/* risk factor 12.345% -> riskfactor_millionths = 12345000 */
	u64 *riskfactor_millionths;
	const struct exclude_entry **excluded;
	u32 *max_hops;

	/* Higher fuzz means that some high-fee paths can be discounted
	 * for an even larger value, increasing the scope for route
	 * randomization (the higher-fee paths become more likely to
	 * be selected) at the cost of increasing the probability of
	 * selecting the higher-fee paths. */
	u64 *fuzz_millionths; /* fuzz 12.345% -> fuzz_millionths = 12345000 */

	if (!param(
		cmd, buffer, params, p_req("id", param_node_id, &destination),
		p_req("msatoshi", param_msat, &msat),
		p_req("riskfactor", param_millionths, &riskfactor_millionths),
		p_opt_def("cltv", param_number, &cltv, 9),
		p_opt("fromid", param_node_id, &source),
		p_opt_def("fuzzpercent", param_millionths, &fuzz_millionths,
			  5000000),
		p_opt("exclude", param_array, &excludetok),
		p_opt_def("maxhops", param_number, &max_hops, ROUTING_MAX_HOPS),
		NULL))
		return command_param_failed();

	/* Convert from percentage */
	*fuzz_millionths /= 100;

	if (excludetok) {
		const jsmntok_t *t;
		size_t i;

		excluded = tal_arr(cmd, const struct exclude_entry *, 0);

		json_for_each_arr(i, t, excludetok) {
			struct exclude_entry *entry = tal(excluded, struct exclude_entry);
			struct short_channel_id_dir *chan_id = tal(tmpctx, struct short_channel_id_dir);
			if (!short_channel_id_dir_from_str(buffer + t->start,
							   t->end - t->start,
							   chan_id)) {
				struct node_id *node_id = tal(tmpctx, struct node_id);

				if (!json_to_node_id(buffer, t, node_id))
					return command_fail_badparam(cmd, "exclude",
								     buffer, t,
								     "should be short_channel_id or node_id");

				entry->type = EXCLUDE_NODE;
				entry->u.node_id = *node_id;
			} else {
				entry->type = EXCLUDE_CHANNEL;
				entry->u.chan_id = *chan_id;
			}

			tal_arr_expand(&excluded, entry);
		}
	} else {
		excluded = NULL;
	}

	u8 *req = towire_gossipd_getroute_request(
	    cmd, source, destination, *msat, *riskfactor_millionths, *cltv,
	    *fuzz_millionths, excluded, *max_hops);
	subd_req(ld->gossip, ld->gossip, req, -1, 0, json_getroute_reply, cmd);
	return command_still_pending(cmd);
}

static const struct json_command getroute_command = {
	"getroute",
	"channels",
	json_getroute,
	"Show route to {id} for {msatoshi}, using {riskfactor} and optional {cltv} (default 9). "
	"If specified search from {fromid} otherwise use this node as source. "
	"Randomize the route with up to {fuzzpercent} (default 5.0). "
	"{exclude} an array of short-channel-id/direction (e.g. [ '564334x877x1/0', '564195x1292x0/1' ]) "
	"or node-id from consideration. "
	"Set the {maxhops} the route can take (default 20)."
};
AUTODATA(json_command, &getroute_command);

static void json_add_halfchan(struct json_stream *response,
			      const struct gossip_getchannels_entry *e,
			      int idx)
{
	const struct gossip_halfchannel_entry *he = e->e[idx];
	if (!he)
		return;

	json_object_start(response, NULL);
	json_add_node_id(response, "source", &e->node[idx]);
	json_add_node_id(response, "destination", &e->node[!idx]);
	json_add_short_channel_id(response, "short_channel_id",
				  &e->short_channel_id);
	json_add_bool(response, "public", e->public);
	json_add_amount_sat_compat(response, e->sat,
				   "satoshis", "amount_msat");
	json_add_num(response, "message_flags", he->message_flags);
	json_add_num(response, "channel_flags", he->channel_flags);
	json_add_bool(response, "active",
		      !(he->channel_flags & ROUTING_FLAGS_DISABLED)
		      && !e->local_disabled);
	json_add_num(response, "last_update", he->last_update_timestamp);
	json_add_num(response, "base_fee_millisatoshi", he->base_fee_msat);
	json_add_num(response, "fee_per_millionth", he->fee_per_millionth);
	json_add_num(response, "delay", he->delay);
	json_add_amount_msat_only(response, "htlc_minimum_msat", he->min);
	json_add_amount_msat_only(response, "htlc_maximum_msat", he->max);
	json_add_hex_talarr(response, "features", e->features);
	json_object_end(response);
}

struct listchannels_info {
	struct command *cmd;
	struct json_stream *response;
	struct short_channel_id *id;
	struct node_id *source;
};

/* Called upon receiving a getchannels_reply from `gossipd` */
static void json_listchannels_reply(struct subd *gossip UNUSED, const u8 *reply,
				    const int *fds UNUSED,
				    struct listchannels_info *linfo)
{
	size_t i;
	struct gossip_getchannels_entry **entries;
	bool complete;

	if (!fromwire_gossipd_getchannels_reply(reply, reply,
					       &complete, &entries)) {
		/* Shouldn't happen: just end json stream. */
		log_broken(linfo->cmd->ld->log, "Invalid reply from gossipd");
		was_pending(command_raw_complete(linfo->cmd, linfo->response));
		return;
	}

	for (i = 0; i < tal_count(entries); i++) {
		json_add_halfchan(linfo->response, entries[i], 0);
		json_add_halfchan(linfo->response, entries[i], 1);
	}

	/* More coming?  Ask from this point on.. */
	if (!complete) {
		u8 *req;
		assert(tal_count(entries) != 0);
		req = towire_gossipd_getchannels_request(linfo->cmd,
							linfo->id,
							linfo->source,
							&entries[i-1]
							->short_channel_id);
		subd_req(linfo->cmd->ld->gossip, linfo->cmd->ld->gossip,
			 req, -1, 0, json_listchannels_reply, linfo);
	} else {
		json_array_end(linfo->response);
		was_pending(command_success(linfo->cmd, linfo->response));
	}
}

static struct command_result *json_listchannels(struct command *cmd,
						const char *buffer,
						const jsmntok_t *obj UNNEEDED,
						const jsmntok_t *params)
{
	u8 *req;
	struct listchannels_info *linfo = tal(cmd, struct listchannels_info);

	linfo->cmd = cmd;
	if (!param(cmd, buffer, params,
		   p_opt("short_channel_id", param_short_channel_id, &linfo->id),
		   p_opt("source", param_node_id, &linfo->source),
		   NULL))
		return command_param_failed();

	if (linfo->id && linfo->source)
		return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
				    "Cannot specify both source and short_channel_id");

	/* Start JSON response, then we stream. */
	linfo->response = json_stream_success(cmd);
	json_array_start(linfo->response, "channels");

	req = towire_gossipd_getchannels_request(cmd, linfo->id, linfo->source,
						NULL);
	subd_req(cmd->ld->gossip, cmd->ld->gossip,
		 req, -1, 0, json_listchannels_reply, linfo);

	return command_still_pending(cmd);
}

static const struct json_command listchannels_command = {
	"listchannels",
	"channels",
	json_listchannels,
	"Show channel {short_channel_id} or {source} (or all known channels, if not specified)"
};
AUTODATA(json_command, &listchannels_command);

#if DEVELOPER
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

	msg = towire_gossipd_dev_set_max_scids_encode_size(NULL, *max);
	subd_send_msg(cmd->ld->gossip, take(msg));

	return command_success(cmd, json_stream_success(cmd));
}

static const struct json_command dev_set_max_scids_encode_size = {
	"dev-set-max-scids-encode-size",
	"developer",
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

	subd_send_msg(cmd->ld->gossip, take(towire_gossipd_dev_suppress(NULL)));

	return command_success(cmd, json_stream_success(cmd));
}

static const struct json_command dev_suppress_gossip = {
	"dev-suppress-gossip",
	"developer",
	json_dev_suppress_gossip,
	"Stop this node from sending any more gossip."
};
AUTODATA(json_command, &dev_suppress_gossip);

static void dev_compact_gossip_store_reply(struct subd *gossip UNUSED,
					   const u8 *reply,
					   const int *fds UNUSED,
					   struct command *cmd)
{
	bool success;

	if (!fromwire_gossipd_dev_compact_store_reply(reply, &success)) {
		was_pending(command_fail(cmd, LIGHTNINGD,
					 "Gossip gave bad dev_gossip_compact_store_reply"));
		return;
	}

	if (!success)
		was_pending(command_fail(cmd, LIGHTNINGD,
					 "gossip_compact_store failed"));
	else
		was_pending(command_success(cmd, json_stream_success(cmd)));
}

static struct command_result *json_dev_compact_gossip_store(struct command *cmd,
							    const char *buffer,
							    const jsmntok_t *obj UNNEEDED,
							    const jsmntok_t *params)
{
	u8 *msg;
	if (!param(cmd, buffer, params, NULL))
		return command_param_failed();

	msg = towire_gossipd_dev_compact_store(NULL);
	subd_req(cmd->ld->gossip, cmd->ld->gossip,
		 take(msg), -1, 0, dev_compact_gossip_store_reply, cmd);
	return command_still_pending(cmd);
}

static const struct json_command dev_compact_gossip_store = {
	"dev-compact-gossip-store",
	"developer",
	json_dev_compact_gossip_store,
	"Ask gossipd to rewrite the gossip store."
};
AUTODATA(json_command, &dev_compact_gossip_store);

static struct command_result *json_dev_gossip_set_time(struct command *cmd,
						       const char *buffer,
						       const jsmntok_t *obj UNNEEDED,
						       const jsmntok_t *params)
{
	u8 *msg;
	u32 *time;

	if (!param(cmd, buffer, params,
		   p_req("time", param_number, &time),
		   NULL))
		return command_param_failed();

	msg = towire_gossipd_dev_set_time(NULL, *time);
	subd_send_msg(cmd->ld->gossip, take(msg));

	return command_success(cmd, json_stream_success(cmd));
}

static const struct json_command dev_gossip_set_time = {
	"dev-gossip-set-time",
	"developer",
	json_dev_gossip_set_time,
	"Ask gossipd to update the current time."
};
AUTODATA(json_command, &dev_gossip_set_time);
#endif /* DEVELOPER */
