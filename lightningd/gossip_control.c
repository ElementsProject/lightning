#include "config.h"
#include <ccan/err/err.h>
#include <ccan/mem/mem.h>
#include <ccan/ptrint/ptrint.h>
#include <channeld/channeld_wiregen.h>
#include <common/daemon.h>
#include <common/json_command.h>
#include <common/json_param.h>
#include <common/json_stream.h>
#include <common/node_id.h>
#include <common/timeout.h>
#include <common/type_to_string.h>
#include <connectd/connectd_wiregen.h>
#include <gossipd/gossipd_wiregen.h>
#include <hsmd/hsmd_wiregen.h>
#include <hsmd/permissions.h>
#include <lightningd/bitcoind.h>
#include <lightningd/chaintopology.h>
#include <lightningd/channel.h>
#include <lightningd/channel_control.h>
#include <lightningd/channel_gossip.h>
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

	channel = any_channel_by_scid(ld, &scid, true);
	if (!channel) {
		log_broken(ld->log, "init_cupdate for unknown scid %s",
			   type_to_string(tmpctx, struct short_channel_id,
					  &scid));
		return;
	}

	channel_gossip_update_from_gossipd(channel, take(update));
}

static void handle_peer_update_data(struct lightningd *ld, const u8 *msg)
{
	struct peer_update update;
	struct node_id *source;

	if (!fromwire_gossipd_remote_channel_update(msg, msg, &source, &update))
		fatal("Gossip gave bad GOSSIPD_REMOTE_CHANNEL_UPDATE %s",
		      tal_hex(msg, msg));

	channel_gossip_set_remote_update(ld, &update, source);
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
	case WIRE_GOSSIPD_LOCAL_CHANNEL_ANNOUNCEMENT:
	case WIRE_GOSSIPD_USED_LOCAL_CHANNEL_UPDATE:
	case WIRE_GOSSIPD_LOCAL_CHANNEL_UPDATE:
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
	/* FIXME: remove from gossipd_wire.csv */
	case WIRE_GOSSIPD_GOT_LOCAL_CHANNEL_UPDATE:
		break;
	case WIRE_GOSSIPD_GET_TXOUT:
		get_txout(gossip, msg);
		break;
	case WIRE_GOSSIPD_REMOTE_CHANNEL_UPDATE:
		/* Please stash in database for us! */
		handle_peer_update_data(gossip->ld, msg);
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
	/* Any channels without channel_updates, we populate now: gossipd
	 * might have lost its gossip_store. */
	channel_gossip_init_done(gossipd->ld);

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

static struct command_result *json_setleaserates(struct command *cmd,
						  const char *buffer,
						  const jsmntok_t *obj UNNEEDED,
						  const jsmntok_t *params)
{
	struct json_stream *res;
	struct lease_rates *rates;
	struct amount_msat *channel_fee_base_msat, *lease_base_msat;
	u32 *lease_basis, *channel_fee_max_ppt, *funding_weight;

	if (!param_check(cmd, buffer, params,
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

	if (command_check_only(cmd))
		return command_check_done(cmd);

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
