#include "config.h"
#include <ccan/err/err.h>
#include <ccan/io/io.h>
#include <ccan/ptrint/ptrint.h>
#include <common/json_command.h>
#include <connectd/connectd_wiregen.h>
#include <hsmd/permissions.h>
#include <lightningd/chaintopology.h>
#include <lightningd/channel.h>
#include <lightningd/channel_gossip.h>
#include <lightningd/gossip_control.h>
#include <lightningd/hsm_control.h>
#include <lightningd/jsonrpc.h>
#include <lightningd/lightningd.h>
#include <lightningd/subd.h>
#include <lightningd/watchman.h>

/* Handler for gossipd's WIRE_GOSSIPD_GET_TXOUT request: gossipd has seen a
 * channel announcement and wants to verify the funding output exists.  We
 * register a SCID watch with bwatch; the reply is sent later from
 * gossip_scid_watch_found once bwatch confirms (or denies) the output. */
static void get_txout(struct subd *gossip, const u8 *msg)
{
	struct short_channel_id scid;
	u32 blockheight, start_block;

	if (!fromwire_gossipd_get_txout(msg, &scid))
		fatal("Gossip gave bad GOSSIP_GET_TXOUT message %s",
		      tal_hex(msg, msg));

	if (gossip->ld->state == LD_STATE_SHUTDOWN)
		return;

	/* The SCID tells us which block the channel was confirmed in.  Pick
	 * the lower of (that block, our current tip) as the rescan start: if
	 * the channel's block is already in the past we want bwatch to rescan
	 * back to it, but if it's in the future (we're still syncing, or the
	 * SCID is bogus) we shouldn't ask bwatch to scan a height it hasn't
	 * reached. */
	blockheight = short_channel_id_blocknum(scid);
	start_block = get_block_height(gossip->ld->topology);
	if (blockheight < start_block)
		start_block = blockheight;
	watchman_watch_scid(gossip->ld,
			    owner_gossip_scid(tmpctx, scid),
			    &scid, start_block);
}

/* bwatch has resolved the SCID: either tx!=NULL (funding output confirmed —
 * reply to gossipd, then arm the funding-spent watch) or tx==NULL (the SCID's
 * block/tx/output position is empty — tell gossipd the channel is invalid). */
void gossip_scid_watch_found(struct lightningd *ld,
			     const char *suffix,
			     const struct bitcoin_tx *tx,
			     size_t index,
			     u32 blockheight,
			     u32 txindex UNUSED)
{
	struct short_channel_id scid;
	struct amount_sat sat;
	const u8 *script;
	struct bitcoin_outpoint outpoint;

	if (!short_channel_id_from_str(suffix, strlen(suffix), &scid)) {
		log_broken(ld->log,
			   "gossip/: invalid scid suffix '%s'", suffix);
		return;
	}

	if (!tx) {
		/* SCID's expected position absent — tell gossipd it's invalid. */
		log_unusual(ld->log,
			    "gossip: SCID %s not found at expected"
			    " block/txindex/outnum — telling gossipd it's invalid",
			    fmt_short_channel_id(tmpctx, scid));
		if (ld->gossip) {
			const u8 *empty = tal_arr(tmpctx, u8, 0);
			subd_send_msg(ld->gossip,
				      take(towire_gossipd_get_txout_reply(
						NULL, scid, AMOUNT_SAT(0), empty)));
		}
		watchman_unwatch_scid(ld, owner_gossip_scid(tmpctx, scid), &scid);
		return;
	}

	if (!ld->gossip)
		return;

	sat = bitcoin_tx_output_get_amount_sat(tx, index);
	script = tal_dup_arr(tmpctx, u8,
			     tx->wtx->outputs[index].script,
			     tx->wtx->outputs[index].script_len, 0);

	subd_send_msg(ld->gossip,
		      take(towire_gossipd_get_txout_reply(NULL, scid, sat, script)));

	watchman_unwatch_scid(ld, owner_gossip_scid(tmpctx, scid), &scid);
	bitcoin_txid(tx, &outpoint.txid);
	outpoint.n = index;
	watchman_watch_outpoint(ld,
				owner_gossip_funding_spent(tmpctx, scid),
				&outpoint, blockheight);
}

/* Revert for "gossip/<scid>" (WATCH_SCID).  The watch is only alive between
 * gossipd's get_txout request and SCID confirmation; a revert means the block
 * we were waiting for was reorged before the watch fired — nothing was sent
 * to gossipd, so just re-arm the watch for when the block returns. */
void gossip_scid_watch_revert(struct lightningd *ld,
			      const char *suffix,
			      u32 blockheight UNUSED)
{
	struct short_channel_id scid;

	if (!short_channel_id_from_str(suffix, strlen(suffix), &scid)) {
		log_broken(ld->log,
			   "gossip/ revert: invalid scid suffix '%s'", suffix);
		return;
	}

	log_unusual(ld->log,
		    "gossip: SCID %s block reorged before confirmation"
		    " — re-watching",
		    fmt_short_channel_id(tmpctx, scid));

	watchman_watch_scid(ld,
			    owner_gossip_scid(tmpctx, scid),
			    &scid,
			    short_channel_id_blocknum(scid));
}

void gossip_funding_spent_watch_found(struct lightningd *ld,
				      const char *suffix,
				      const struct bitcoin_tx *tx UNUSED,
				      size_t index UNUSED,
				      u32 blockheight,
				      u32 txindex UNUSED)
{
	struct short_channel_id scid;

	if (!short_channel_id_from_str(suffix, strlen(suffix), &scid)) {
		log_broken(ld->log,
			   "gossip/funding_spent/: invalid scid suffix '%s'",
			   suffix);
		return;
	}

	if (!ld->gossip)
		return;

	gossipd_notify_spends(ld, blockheight,
			      tal_dup(tmpctx, struct short_channel_id, &scid));
}

/* Revert for "gossip/funding_spent/<scid>".  bwatch reverts in two cases,
 * distinguished by blockheight:
 *
 *   funding-block revert (blockheight == scid's block): the SCID's confirming
 *     block was reorged away, taking the funding output with it.  We
 *     previously sent get_txout_reply so gossipd believes the channel exists
 *     — undo that.
 *
 *   spend-block revert (blockheight != scid's block): the spending tx was
 *     reorged; the funding output is unspent again.  We previously told
 *     gossipd the channel was closed — re-arm the SCID watch so gossipd
 *     re-learns the channel is still open once the funding output
 *     re-confirms. */
void gossip_funding_spent_watch_revert(struct lightningd *ld,
				       const char *suffix,
				       u32 blockheight)
{
	struct short_channel_id scid;

	if (!short_channel_id_from_str(suffix, strlen(suffix), &scid)) {
		log_broken(ld->log,
			   "gossip/funding_spent/ revert: invalid scid suffix '%s'",
			   suffix);
		return;
	}

	if (blockheight == short_channel_id_blocknum(scid)) {
		log_unusual(ld->log,
			    "gossip: SCID %s funding block reorged out"
			    " — notifying gossipd and re-watching",
			    fmt_short_channel_id(tmpctx, scid));
		if (ld->gossip)
			gossipd_notify_spends(ld, blockheight,
					      tal_dup(tmpctx,
						      struct short_channel_id,
						      &scid));
	} else {
		log_unusual(ld->log,
			    "gossip: SCID %s spend reorged out"
			    " — re-watching for re-confirmation to gossipd",
			    fmt_short_channel_id(tmpctx, scid));
	}

	watchman_watch_scid(ld,
			    owner_gossip_scid(tmpctx, scid),
			    &scid,
			    short_channel_id_blocknum(scid));
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

	channel = any_channel_by_scid(ld, scid, true);
	if (!channel) {
		log_broken(ld->log, "init_cupdate for unknown scid %s: telling gossipd it's spent",
			   fmt_short_channel_id(tmpctx, scid));
		/* Presumably gossipd missed that it was already spent, so
		 * tell it now! (We need a tal object for this, hence
		 * tal_dup) */
		gossipd_notify_spends(ld, ld->gossip_blockheight,
				      tal_dup(tmpctx, struct short_channel_id, &scid));
		return;
	}

	channel_gossip_update_from_gossipd(channel, take(update));
}

static void handle_init_nannounce(struct lightningd *ld, const u8 *msg)
{
	u8 *nannounce;

	if (!fromwire_gossipd_init_nannounce(ld, msg, &nannounce)) {
		fatal("Gossip gave bad GOSSIPD_INIT_NANNOUNCE %s",
		      tal_hex(msg, msg));
	}

	assert(!ld->node_announcement);
	ld->node_announcement = nannounce;
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

/* gossipd would like a connection to this peer for more gossiping. */
static void handle_connect_to_peer(struct subd *gossip, const u8 *msg)
{
	struct node_id id;

	if (!fromwire_gossipd_connect_to_peer(msg, &id)) {
		log_broken(gossip->ld->log, "malformed peer connect request"
			   " from gossipd %s", tal_hex(msg, msg));
		return;
	}
	log_debug(gossip->ld->log, "attempting connection to %s "
		  "for additional gossip", fmt_node_id(tmpctx, &id));
	u8 *connectmsg;
	connectmsg = towire_connectd_connect_to_peer(NULL,
						     &id,
						     NULL,	//addrhint,
						     true,	//transient
						     "gossipd");
	subd_send_msg(gossip->ld->connectd, take(connectmsg));
}

static unsigned gossip_msg(struct subd *gossip, const u8 *msg, const int *fds)
{
	enum gossipd_wire t = fromwire_peektype(msg);

	switch (t) {
	/* These are messages we send, not them. */
	case WIRE_GOSSIPD_INIT:
	case WIRE_GOSSIPD_GET_TXOUT_REPLY:
	case WIRE_GOSSIPD_OUTPOINTS_SPENT:
	case WIRE_GOSSIPD_DEV_MEMLEAK:
	case WIRE_GOSSIPD_DEV_COMPACT_STORE:
	case WIRE_GOSSIPD_NEW_BLOCKHEIGHT:
	case WIRE_GOSSIPD_ADDGOSSIP:
	/* This is a reply, so never gets through to here. */
	case WIRE_GOSSIPD_INIT_REPLY:
	case WIRE_GOSSIPD_DEV_MEMLEAK_REPLY:
	case WIRE_GOSSIPD_DEV_COMPACT_STORE_REPLY:
	case WIRE_GOSSIPD_ADDGOSSIP_REPLY:
	case WIRE_GOSSIPD_NEW_BLOCKHEIGHT_REPLY:
		break;

	case WIRE_GOSSIPD_INIT_CUPDATE:
		handle_init_cupdate(gossip->ld, msg);
		break;
	case WIRE_GOSSIPD_INIT_NANNOUNCE:
		handle_init_nannounce(gossip->ld, msg);
		break;
	case WIRE_GOSSIPD_GET_TXOUT:
		get_txout(gossip, msg);
		break;
	case WIRE_GOSSIPD_REMOTE_CHANNEL_UPDATE:
		/* Please stash in database for us! */
		handle_peer_update_data(gossip->ld, msg);
		tal_free(msg);
		break;
	case WIRE_GOSSIPD_CONNECT_TO_PEER:
		/* Please try connecting to this peer for more gossip. */
		handle_connect_to_peer(gossip, msg);
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

	/* And use that to trim old entries in the UTXO set */
	wallet_utxoset_prune(gossipd->ld->wallet,
			     gossipd->ld->gossip_blockheight);
}

void gossip_notify_new_block(struct lightningd *ld)
{
	u32 blockheight = get_block_height(ld->topology);

	/* Only notify gossipd once bitcoind is synced. */
	if (!ld->bitcoind->synced)
		return;

	subd_req(ld->gossip, ld->gossip,
		 take(towire_gossipd_new_blockheight(NULL, blockheight)),
		 -1, 0, gossipd_new_blockheight_reply, int2ptr(blockheight));
}

/* We make sure gossipd is started before plugins (which may want gossip_map) */
static void gossipd_init_done(struct subd *gossipd,
			      const u8 *msg,
			      const int *fds,
			      void *unused)
{
	struct lightningd *ld = gossipd->ld;
	u32 oldspends;

	/* Any channels without channel_updates, we populate now: gossipd
	 * might have lost its gossip_store. */
	channel_gossip_init_done(ld);

	/* Tell it about any closures it might have missed! */
	oldspends = wallet_utxoset_oldest_spentheight(tmpctx, ld->wallet);
	if (oldspends) {
		while (oldspends <= get_block_height(ld->topology)) {
			const struct short_channel_id *scids;

			scids = wallet_utxoset_get_spent(tmpctx, ld->wallet,
							 oldspends);
			gossipd_notify_spends(ld, oldspends, scids);
			oldspends++;
		}
	}

	/* Break out of loop, so we can begin */
	log_debug(gossipd->ld->log, "io_break: %s", __func__);
	io_break(gossipd);
}

/* Create the `gossipd` subdaemon and send the initialization
 * message */
void gossip_init(struct lightningd *ld, int connectd_fd)
{
	u8 *msg;
	void *ret;

	ld->gossip = new_global_subd(ld, "lightning_gossipd",
				     gossipd_wire_name, gossip_msg,
				     take(&connectd_fd), NULL);
	if (!ld->gossip)
		err(1, "Could not subdaemon gossip");

	msg = towire_gossipd_init(
	    NULL,
	    chainparams,
	    ld->our_features,
	    &ld->our_nodeid,
	    ld->autoconnect_seeker_peers,
	    subdaemon_path(tmpctx, ld, "lightning_gossip_compactd"),
	    ld->dev_fast_gossip,
	    ld->dev_fast_gossip_prune);

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

	/* Save them for node_announcement generation */
	cmd->ld->lease_rates = tal_free(cmd->ld->lease_rates);
	if (!lease_rates_empty(rates))
		cmd->ld->lease_rates = tal_steal(cmd->ld, rates);

	/* This may generate a new node_announcement */
	channel_gossip_node_announce(cmd->ld);

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
	json_setleaserates,
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

	req = towire_gossipd_addgossip(cmd, gossip_msg, NULL);
	subd_req(cmd->ld->gossip, cmd->ld->gossip,
		 req, -1, 0, json_addgossip_reply, cmd);

	return command_still_pending(cmd);
}

static const struct json_command addgossip_command = {
	"addgossip",
	json_addgossip,
};
AUTODATA(json_command, &addgossip_command);

/* FIXME: move to connect_control.c! */
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

	msg = towire_connectd_dev_set_max_scids_encode_size(NULL, *max);
	subd_send_msg(cmd->ld->connectd, take(msg));

	return command_success(cmd, json_stream_success(cmd));
}

static const struct json_command dev_set_max_scids_encode_size = {
	"dev-set-max-scids-encode-size",
	json_dev_set_max_scids_encode_size,
	.dev_only = true,
};
AUTODATA(json_command, &dev_set_max_scids_encode_size);

static void dev_compact_gossip_store_reply(struct subd *gossip UNUSED,
					   const u8 *reply,
					   const int *fds UNUSED,
					   struct command *cmd)
{
	char *result;

	if (!fromwire_gossipd_dev_compact_store_reply(cmd, reply, &result)) {
		was_pending(command_fail(cmd, LIGHTNINGD,
					 "Gossip gave bad dev_gossip_compact_store_reply"));
		return;
	}

	if (streq(result, ""))
		was_pending(command_success(cmd, json_stream_success(cmd)));
	else
		was_pending(command_fail(cmd, LIGHTNINGD,
					 "gossip_compact_store failed: %s", result));
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
	json_dev_compact_gossip_store,
	.dev_only = true,
};
AUTODATA(json_command, &dev_compact_gossip_store);
