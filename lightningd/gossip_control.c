#include "config.h"
#include <ccan/err/err.h>
#include <ccan/ptrint/ptrint.h>
#include <channeld/channeld_wiregen.h>
#include <common/json_command.h>
#include <common/json_param.h>
#include <common/json_stream.h>
#include <common/node_id.h>
#include <common/type_to_string.h>
#include <gossipd/gossipd_wiregen.h>
#include <hsmd/permissions.h>
#include <lightningd/bitcoind.h>
#include <lightningd/chaintopology.h>
#include <lightningd/channel.h>
#include <lightningd/channel_control.h>
#include <lightningd/gossip_control.h>
#include <lightningd/hsm_control.h>
#include <lightningd/jsonrpc.h>
#include <lightningd/lightningd.h>
#include <lightningd/peer_control.h>
#include <lightningd/subd.h>

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
		if (o->txindex == txindex && o->outpoint.n == outnum) {
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

static void handle_init_cupdate(struct lightningd *ld, const u8 *msg)
{
	struct short_channel_id scid;
	u8 *update;
	struct channel *channel;

	if (!fromwire_gossipd_init_cupdate(msg, msg, &scid, &update)) {
		fatal("Gossip gave bad GOSSIPD_INIT_CUPDATE %s",
		      tal_hex(msg, msg));
	}

	/* In theory this could vanish before gossipd gets around to telling
	 * us. */
	channel = any_channel_by_scid(ld, &scid, true);
	if (!channel) {
		log_unusual(ld->log, "init_cupdate for bad scid %s",
			    type_to_string(tmpctx, struct short_channel_id,
					   &scid));
		return;
	}

	/* This should only happen on initialization, *but* gossipd also
	 * disabled channels on startup, so that can set this first. */
	if (!channel->channel_update)
		channel->channel_update = tal_steal(channel, update);
}

static void handle_local_channel_update(struct lightningd *ld, const u8 *msg)
{
	struct short_channel_id scid;
	u8 *update;
	struct channel *channel;

	if (!fromwire_gossipd_got_local_channel_update(msg, msg,
						       &scid, &update)) {
		fatal("Gossip gave bad GOSSIP_GOT_LOCAL_CHANNEL_UPDATE %s",
		      tal_hex(msg, msg));
	}

	/* In theory this could vanish before gossipd gets around to telling
	 * us. */
	channel = any_channel_by_scid(ld, &scid, true);
	if (!channel) {
		log_unusual(ld->log, "Local update for bad scid %s",
			    type_to_string(tmpctx, struct short_channel_id,
					   &scid));
		return;
	}

	channel_replace_update(channel, take(update));
}

const u8 *get_channel_update(struct channel *channel)
{
	/* Tell gossipd we're using it (if shutting down, might be NULL) */
	if (channel->channel_update && channel->peer->ld->gossip) {
		subd_send_msg(channel->peer->ld->gossip,
			      take(towire_gossipd_used_local_channel_update
				   (NULL, channel->scid)));
	}
	return channel->channel_update;
}

static void set_channel_remote_update(struct lightningd *ld,
				      struct channel *channel,
				      struct remote_priv_update* update TAKES)
{
	if (!node_id_eq(&update->source_node, &channel->peer->id)) {
		log_unusual(ld->log, "%s sent us a channel update for a "
			    "channel they don't own (%s)",
			    type_to_string(tmpctx, struct node_id,
					   &update->source_node),
			    type_to_string(tmpctx, struct short_channel_id,
					   channel->scid));
		if (taken(update))
			tal_free(update);
		return;
	}
	struct short_channel_id *scid;
	scid = channel->scid;
	if (!scid)
		scid = channel->alias[LOCAL];
	log_debug(ld->log, "updating channel %s with private inbound settings",
		  type_to_string(tmpctx, struct short_channel_id, scid));
	tal_free(channel->private_update);
	channel->private_update = tal_dup(channel,
					  struct remote_priv_update, update);
	if (taken(update))
		tal_free(update);
	wallet_channel_save(ld->wallet, channel);
}

static void handle_private_update_data(struct lightningd *ld, const u8 *msg)
{
	struct channel *channel;
	struct remote_priv_update *update;

	update = tal(tmpctx, struct remote_priv_update);
	if (!fromwire_gossipd_remote_channel_update(msg, update))
		fatal("Gossip gave bad GOSSIPD_REMOTE_CHANNEL_UPDATE %s",
		      tal_hex(msg, msg));
	channel = any_channel_by_scid(ld, &update->scid, true);
	if (!channel) {
		log_unusual(ld->log, "could not find channel for peer's "
			    "private channel update");
		return;
	}

	set_channel_remote_update(ld, channel, update);
}

static unsigned gossip_msg(struct subd *gossip, const u8 *msg, const int *fds)
{
	enum gossipd_wire t = fromwire_peektype(msg);

	switch (t) {
	/* These are messages we send, not them. */
	case WIRE_GOSSIPD_INIT:
	case WIRE_GOSSIPD_GET_TXOUT_REPLY:
	case WIRE_GOSSIPD_OUTPOINTS_SPENT:
	case WIRE_GOSSIPD_NEW_LEASE_RATES:
	case WIRE_GOSSIPD_DEV_SET_MAX_SCIDS_ENCODE_SIZE:
	case WIRE_GOSSIPD_LOCAL_CHANNEL_CLOSE:
	case WIRE_GOSSIPD_DEV_MEMLEAK:
	case WIRE_GOSSIPD_DEV_COMPACT_STORE:
	case WIRE_GOSSIPD_DEV_SET_TIME:
	case WIRE_GOSSIPD_NEW_BLOCKHEIGHT:
	case WIRE_GOSSIPD_ADDGOSSIP:
	case WIRE_GOSSIPD_GET_ADDRS:
	case WIRE_GOSSIPD_USED_LOCAL_CHANNEL_UPDATE:
	case WIRE_GOSSIPD_LOCAL_CHANNEL_UPDATE:
	case WIRE_GOSSIPD_LOCAL_CHANNEL_ANNOUNCEMENT:
	case WIRE_GOSSIPD_LOCAL_PRIVATE_CHANNEL:
	/* This is a reply, so never gets through to here. */
	case WIRE_GOSSIPD_INIT_REPLY:
	case WIRE_GOSSIPD_DEV_MEMLEAK_REPLY:
	case WIRE_GOSSIPD_DEV_COMPACT_STORE_REPLY:
	case WIRE_GOSSIPD_ADDGOSSIP_REPLY:
	case WIRE_GOSSIPD_NEW_BLOCKHEIGHT_REPLY:
	case WIRE_GOSSIPD_GET_ADDRS_REPLY:
	case WIRE_GOSSIPD_DISCOVERED_IP:
		break;

	case WIRE_GOSSIPD_INIT_CUPDATE:
		handle_init_cupdate(gossip->ld, msg);
		break;
	case WIRE_GOSSIPD_GET_TXOUT:
		get_txout(gossip, msg);
		break;
	case WIRE_GOSSIPD_GOT_LOCAL_CHANNEL_UPDATE:
		handle_local_channel_update(gossip->ld, msg);
		break;
	case WIRE_GOSSIPD_REMOTE_CHANNEL_UPDATE:
		/* Please stash in database for us! */
		handle_private_update_data(gossip->ld, msg);
		tal_free(msg);
		break;
	}
	return 0;
}

static void gossipd_new_blockheight_reply(struct subd *gossipd,
					  const u8 *reply,
					  const int *fds UNUSED,
					  void *blockheight)
{
	if (!fromwire_gossipd_new_blockheight_reply(reply)) {
		/* Shouldn't happen! */
		log_broken(gossipd->ld->log,
			   "Invalid new_blockheight_reply from gossipd: %s",
			   tal_hex(tmpctx, reply));
		return;
	}

	/* Now, finally update getinfo's blockheight */
	gossipd->ld->gossip_blockheight = ptr2int(blockheight);
}

void gossip_notify_new_block(struct lightningd *ld, u32 blockheight)
{
	/* Only notify gossipd once we're synced. */
	if (!topology_synced(ld->topology))
		return;

	subd_req(ld->gossip, ld->gossip,
		 take(towire_gossipd_new_blockheight(NULL, blockheight)),
		 -1, 0, gossipd_new_blockheight_reply, int2ptr(blockheight));
}

static void gossip_topology_synced(struct chain_topology *topo, void *unused)
{
	/* Now we start telling gossipd about blocks. */
	gossip_notify_new_block(topo->ld, get_block_height(topo));
}

/* We make sure gossipd is started before plugins (which may want gossip_map) */
static void gossipd_init_done(struct subd *gossipd,
			      const u8 *msg,
			      const int *fds,
			      void *unused)
{
	/* Break out of loop, so we can begin */
	log_debug(gossipd->ld->log, "io_break: %s", __func__);
	io_break(gossipd);
}

/* Create the `gossipd` subdaemon and send the initialization
 * message */
void gossip_init(struct lightningd *ld, int connectd_fd)
{
	u8 *msg;
	int hsmfd;
	void *ret;

	hsmfd = hsm_get_global_fd(ld, HSM_PERM_ECDH|HSM_PERM_SIGN_GOSSIP);

	ld->gossip = new_global_subd(ld, "lightning_gossipd",
				     gossipd_wire_name, gossip_msg,
				     take(&hsmfd), take(&connectd_fd), NULL);
	if (!ld->gossip)
		err(1, "Could not subdaemon gossip");

	/* We haven't started topology yet, so tell us when we're synced. */
	topology_add_sync_waiter(ld->gossip, ld->topology,
				 gossip_topology_synced, NULL);

	msg = towire_gossipd_init(
	    NULL,
	    chainparams,
	    ld->our_features,
	    &ld->id,
	    ld->rgb,
	    ld->alias,
	    ld->announceable,
	    ld->dev_gossip_time ? &ld->dev_gossip_time: NULL,
	    ld->dev_fast_gossip,
	    ld->dev_fast_gossip_prune,
	    ld->config.ip_discovery);

	subd_req(ld->gossip, ld->gossip, take(msg), -1, 0,
		 gossipd_init_done, NULL);

	/* Wait for gossipd_init_reply */
	ret = io_loop(NULL, NULL);
	log_debug(ld->log, "io_loop: %s", __func__);
	assert(ret == ld->gossip);
}

/* We save these so we always tell gossipd about new blockheight first. */
void gossipd_notify_spends(struct lightningd *ld,
			   u32 blockheight,
			   const struct short_channel_id *scids)
{
	subd_send_msg(ld->gossip,
		      take(towire_gossipd_outpoints_spent(NULL,
							  blockheight,
							  scids)));
}

/* We unwrap, add the peer id, and send to gossipd. */
void tell_gossipd_local_channel_update(struct lightningd *ld,
				       struct channel *channel,
				       const u8 *msg)
{
	struct short_channel_id scid;
	bool disable, public;
	u16 cltv_expiry_delta;
	struct amount_msat htlc_minimum_msat;
	u32 fee_base_msat, fee_proportional_millionths;
	struct amount_msat htlc_maximum_msat;

	if (!fromwire_channeld_local_channel_update(msg, &scid, &disable,
						    &cltv_expiry_delta,
						    &htlc_minimum_msat,
						    &fee_base_msat,
						    &fee_proportional_millionths,
						    &htlc_maximum_msat, &public)) {
		channel_internal_error(channel,
				       "bad channeld_local_channel_update %s",
				       tal_hex(channel, msg));
		return;
	}

	/* As we're shutting down, ignore */
	if (!ld->gossip)
		return;

	subd_send_msg(ld->gossip,
		      take(towire_gossipd_local_channel_update
			   (NULL,
			    &channel->peer->id,
			    &scid,
			    disable,
			    cltv_expiry_delta,
			    htlc_minimum_msat,
			    fee_base_msat,
			    fee_proportional_millionths,
			    htlc_maximum_msat,
			    public)));
}

void tell_gossipd_local_channel_announce(struct lightningd *ld,
					 struct channel *channel,
					 const u8 *msg)
{
	u8 *ann;
	if (!fromwire_channeld_local_channel_announcement(msg, msg, &ann)) {
		channel_internal_error(channel,
				       "bad channeld_local_channel_announcement"
				       " %s",
				       tal_hex(channel, msg));
		return;
	}

	/* As we're shutting down, ignore */
	if (!ld->gossip)
		return;

	subd_send_msg(ld->gossip,
		      take(towire_gossipd_local_channel_announcement
			   (NULL, &channel->peer->id, ann)));
}

void tell_gossipd_local_private_channel(struct lightningd *ld,
					struct channel *channel,
					struct amount_sat capacity,
					const u8 *features)
{
	/* Which short_channel_id should we use to refer to this channel when
	 * creating invoices? */
	const struct short_channel_id *scid;

	/* As we're shutting down, ignore */
	if (!ld->gossip)
		return;

	if (channel->scid != NULL) {
		scid = channel->scid;
	} else {
		scid = channel->alias[REMOTE];
	}

	assert(scid != NULL);
	subd_send_msg(ld->gossip,
		      take(towire_gossipd_local_private_channel
			   (NULL, &channel->peer->id,
			    capacity,
			    scid,
			    features)));

	/* If we have no real scid, and there are two different
	 * aliases, then we need to add both as single direction
	 * channels to the local gossip_store. */
	if ((!channel->scid && channel->alias[LOCAL]) &&
	    !short_channel_id_eq(channel->alias[REMOTE],
				 channel->alias[LOCAL])) {
		subd_send_msg(ld->gossip,
			      take(towire_gossipd_local_private_channel(
				  NULL, &channel->peer->id, capacity,
				  channel->alias[LOCAL], features)));
	}
}

static struct command_result *json_setleaserates(struct command *cmd,
						  const char *buffer,
						  const jsmntok_t *obj UNNEEDED,
						  const jsmntok_t *params)
{
	struct json_stream *res;
	struct lease_rates *rates;
	struct amount_msat *channel_fee_base_msat, *lease_base_msat;
	u32 *lease_basis, *channel_fee_max_ppt, *funding_weight;

	if (!param(cmd, buffer, params,
		   p_req("lease_fee_base_msat", param_msat, &lease_base_msat),
		   p_req("lease_fee_basis", param_number, &lease_basis),
		   p_req("funding_weight", param_number, &funding_weight),
		   p_req("channel_fee_max_base_msat", param_msat,
			 &channel_fee_base_msat),
		   p_req("channel_fee_max_proportional_thousandths",
			 param_number, &channel_fee_max_ppt),
		   NULL))
		return command_param_failed();

	rates = tal(tmpctx, struct lease_rates);
	rates->lease_fee_basis = *lease_basis;
	rates->lease_fee_base_sat = lease_base_msat->millisatoshis / 1000; /* Raw: conversion */
	rates->channel_fee_max_base_msat = channel_fee_base_msat->millisatoshis; /* Raw: conversion */

	rates->funding_weight = *funding_weight;
	rates->channel_fee_max_proportional_thousandths
		= *channel_fee_max_ppt;

	/* Gotta check that we didn't overflow */
	if (lease_base_msat->millisatoshis != rates->lease_fee_base_sat * (u64)1000) /* Raw: comparison */
		return command_fail_badparam(cmd, "lease_fee_base_msat",
					     buffer, params, "Overflow");

	if (channel_fee_base_msat->millisatoshis > rates->channel_fee_max_base_msat) /* Raw: comparison */
		return command_fail_badparam(cmd, "channel_fee_max_base_msat",
					     buffer, params, "Overflow");

	/* Call gossipd, let them know we've got new rates */
	subd_send_msg(cmd->ld->gossip,
		      take(towire_gossipd_new_lease_rates(NULL, rates)));

	res = json_stream_success(cmd);
	json_add_amount_sat_msat(res, "lease_fee_base_msat",
				 amount_sat(rates->lease_fee_base_sat));
	json_add_num(res, "lease_fee_basis", rates->lease_fee_basis);
	json_add_num(res, "funding_weight", rates->funding_weight);
	json_add_amount_msat(res, "channel_fee_max_base_msat",
			     amount_msat(rates->channel_fee_max_base_msat));
	json_add_num(res, "channel_fee_max_proportional_thousandths",
		     rates->channel_fee_max_proportional_thousandths);

	return command_success(cmd, res);
}

static const struct json_command setleaserates_command = {
	"setleaserates",
	"channels",
	json_setleaserates,
	"Called by plugin to set the node's present channel lease rates."
	" Not to be set without having a plugin which can handle"
	" `openchannel2` hooks.",
};

AUTODATA(json_command, &setleaserates_command);

/* Called upon receiving a addgossip_reply from `gossipd` */
static void json_addgossip_reply(struct subd *gossip UNUSED, const u8 *reply,
				 const int *fds UNUSED,
				 struct command *cmd)
{
	char *err;

	if (!fromwire_gossipd_addgossip_reply(reply, reply, &err)) {
		/* Shouldn't happen: just end json stream. */
		log_broken(cmd->ld->log,
			   "Invalid addgossip_reply from gossipd: %s",
			   tal_hex(tmpctx, reply));
		was_pending(command_fail(cmd, LIGHTNINGD,
					 "Invalid reply from gossipd"));
		return;
	}

	if (strlen(err))
		was_pending(command_fail(cmd, LIGHTNINGD, "%s", err));
	else
		was_pending(command_success(cmd, json_stream_success(cmd)));
}

static struct command_result *json_addgossip(struct command *cmd,
					     const char *buffer,
					     const jsmntok_t *obj UNNEEDED,
					     const jsmntok_t *params)
{
	u8 *req, *gossip_msg;
	if (!param(cmd, buffer, params,
		   p_req("message", param_bin_from_hex, &gossip_msg),
		   NULL))
		return command_param_failed();

	req = towire_gossipd_addgossip(cmd, gossip_msg);
	subd_req(cmd->ld->gossip, cmd->ld->gossip,
		 req, -1, 0, json_addgossip_reply, cmd);

	return command_still_pending(cmd);
}

static const struct json_command addgossip_command = {
	"addgossip",
	"utility",
	json_addgossip,
	"Inject gossip {message} into gossipd"
};
AUTODATA(json_command, &addgossip_command);

static struct command_result *json_listprivateinbound(struct command *cmd,
						      const char *buffer,
						      const jsmntok_t *obj UNNEEDED,
						      const jsmntok_t *params)
{
	/* struct node_id *peer_id; */
	struct peer *peer;
	/* struct channel *c, **channels; */
	struct channel *c;
	struct json_stream *response;

	if (!param(cmd, buffer, params, NULL))
		return command_param_failed();

	response = json_stream_success(cmd);
	json_array_start(response, "private_channels");

	/* channels = tal_arr(tmpctx, struct channel *, 0); */
	struct peer_node_id_map_iter it;

	for (peer = peer_node_id_map_first(cmd->ld->peers, &it);
	     peer;
	     peer = peer_node_id_map_next(cmd->ld->peers, &it)) {
		/* json_add_peerchannels(cmd->ld, response, peer); */
		list_for_each(&peer->channels, c, list) {
			if (c->state != CHANNELD_NORMAL &&
			    c->state != CHANNELD_AWAITING_SPLICE)
				continue;

			if (c->private_update) {
				json_object_start(response, NULL);
				json_add_node_id(response, "id", &peer->id);
				/* Zeroconf channels will use the local alias here */
				json_add_short_channel_id(response,
							  "short_channel_id",
							  &c->private_update->scid);
				if (c->alias[REMOTE])
					json_add_short_channel_id(response,
								  "remote_alias",
								  c->alias[REMOTE]);
				json_add_u32(response, "fee_base",
					     c->private_update->fee_base);
				json_add_u32(response, "fee_ppm",
					     c->private_update->fee_ppm);
				json_add_u32(response, "cltv_delta",
					     c->private_update->cltv_delta);
				json_add_amount_msat(response, "htlc_minimum_msat",
						     c->private_update->htlc_minimum_msat);
				json_add_amount_msat(response, "htlc_maximum_msat",
						     c->private_update->htlc_maximum_msat);
				json_add_hex_talarr(response, "features", peer->their_features);
				json_object_end(response);
			}
		}
	}
	json_array_end(response);
	return command_success(cmd, response);
}

static const struct json_command listprivateinbound_command = {
	"listprivateinbound",
	"channels",
	json_listprivateinbound,
	"Called by plugin to create route hints from incoming private channels",
	false,
	NULL
};

AUTODATA(json_command, &listprivateinbound_command);

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
	"Set {max} bytes of short_channel_ids per reply_channel_range",
	.dev_only = true,
};
AUTODATA(json_command, &dev_set_max_scids_encode_size);

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
	"Ask gossipd to rewrite the gossip store.",
	.dev_only = true,
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
	"Ask gossipd to update the current time.",
	.dev_only = true,
};
AUTODATA(json_command, &dev_gossip_set_time);
