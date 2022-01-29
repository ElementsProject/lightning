#include "config.h"
#include <ccan/cast/cast.h>
#include <channeld/channeld_wiregen.h>
#include <common/json_command.h>
#include <common/json_helpers.h>
#include <common/json_tok.h>
#include <common/memleak.h>
#include <common/param.h>
#include <common/shutdown_scriptpubkey.h>
#include <common/type_to_string.h>
#include <common/wire_error.h>
#include <errno.h>
#include <hsmd/capabilities.h>
#include <lightningd/chaintopology.h>
#include <lightningd/channel.h>
#include <lightningd/channel_control.h>
#include <lightningd/closing_control.h>
#include <lightningd/coin_mvts.h>
#include <lightningd/dual_open_control.h>
#include <lightningd/gossip_control.h>
#include <lightningd/hsm_control.h>
#include <lightningd/notification.h>
#include <lightningd/peer_control.h>
#include <lightningd/peer_fd.h>

static void update_feerates(struct lightningd *ld, struct channel *channel)
{
	u8 *msg;
	u32 feerate = unilateral_feerate(ld->topology);

	/* Nothing to do if we don't know feerate. */
	if (!feerate)
		return;

	log_debug(ld->log,
		  "update_feerates: feerate = %u, min=%u, max=%u, penalty=%u",
		  feerate,
		  feerate_min(ld, NULL),
		  feerate_max(ld, NULL),
		  try_get_feerate(ld->topology, FEERATE_PENALTY));

	msg = towire_channeld_feerates(NULL, feerate,
				       feerate_min(ld, NULL),
				       feerate_max(ld, NULL),
				       try_get_feerate(ld->topology, FEERATE_PENALTY));
	subd_send_msg(channel->owner, take(msg));
}

static void try_update_feerates(struct lightningd *ld, struct channel *channel)
{
	/* No point until funding locked in */
	if (!channel_fees_can_change(channel))
		return;

	/* Can't if no daemon listening. */
	if (!channel->owner)
		return;

	update_feerates(ld, channel);
}

static void try_update_blockheight(struct lightningd *ld,
				   struct channel *channel,
				   u32 blockheight)
{
	u8 *msg;

	log_debug(channel->log, "attempting update blockheight %s",
		  type_to_string(tmpctx, struct channel_id, &channel->cid));

	/* If they're offline, check that we're not too far behind anyway */
	if (!channel->owner) {
		if (channel->opener == REMOTE
		    && channel->lease_expiry > 0) {
			u32 peer_height
				= get_blockheight(channel->blockheight_states,
						  channel->opener, REMOTE);

			/* Lease no longer active, we don't (really) care */
			if (peer_height >= channel->lease_expiry)
				return;

			assert(peer_height + 1008 > peer_height);
			if (peer_height + 1008 < blockheight)
				channel_fail_permanent(channel,
						       REASON_PROTOCOL,
						       "Offline peer is too"
						       " far behind,"
						       " terminating leased"
						       " channel. Our current"
						       " %u, theirs %u",
						       blockheight,
						       peer_height);
		}
		return;
	}

	/* If we're not opened/locked in yet, don't send update */
	if (!channel_fees_can_change(channel))
		return;

	/* We don't update the blockheight for non-leased chans */
	if (channel->lease_expiry == 0)
		return;

	log_debug(ld->log, "update_blockheight: height = %u", blockheight);

	msg = towire_channeld_blockheight(NULL, blockheight);
	subd_send_msg(channel->owner, take(msg));
}

void notify_feerate_change(struct lightningd *ld)
{
	struct peer *peer;

	/* FIXME: We should notify onchaind about NORMAL fee change in case
	 * it's going to generate more txs. */
	list_for_each(&ld->peers, peer, list) {
		struct channel *channel = peer_active_channel(peer);

		if (!channel)
			continue;

		/* FIXME: We choose not to drop to chain if we can't contact
		 * peer.  We *could* do so, however. */
		try_update_feerates(ld, channel);
	}
}

void channel_record_open(struct channel *channel)
{
	struct chain_coin_mvt *mvt;
	u32 blockheight;
	struct amount_msat start_balance;
	bool is_pushed = !amount_msat_zero(channel->push);
	bool is_leased = channel->lease_expiry > 0;

	blockheight = short_channel_id_blocknum(channel->scid);

	/* If funds were pushed, add/sub them from the starting balance */
	if (is_pushed) {
		if (channel->opener == LOCAL) {
			if (!amount_msat_add(&start_balance,
					    channel->our_msat, channel->push))
				fatal("Unable to add push_msat (%s) + our_msat (%s)",
				      type_to_string(tmpctx, struct amount_msat,
						     &channel->push),
				      type_to_string(tmpctx, struct amount_msat,
						     &channel->our_msat));
		} else {
			if (!amount_msat_sub(&start_balance,
					    channel->our_msat, channel->push))
				fatal("Unable to sub our_msat (%s) - push (%s)",
				      type_to_string(tmpctx, struct amount_msat,
						     &channel->our_msat),
				      type_to_string(tmpctx, struct amount_msat,
						     &channel->push));
		}
	} else
		start_balance = channel->our_msat;

	mvt = new_coin_channel_open(tmpctx,
				    &channel->cid,
				    &channel->funding,
				    blockheight,
				    start_balance,
				    channel->funding_sats,
				    channel->opener == LOCAL,
				    is_leased);

	notify_chain_mvt(channel->peer->ld, mvt);

	/* If we pushed sats, *now* record them */
	if (is_pushed)
		notify_channel_mvt(channel->peer->ld,
				   new_coin_channel_push(tmpctx, &channel->cid,
							 channel->push,
							 is_leased ? LEASE_FEE : PUSHED,
							 channel->opener == REMOTE));
}

static void lockin_complete(struct channel *channel)
{
	/* We set this once we're locked in. */
	assert(channel->scid);
	/* We set this once they're locked in. */
	assert(channel->remote_funding_locked);

	/* We might have already started shutting down */
	if (channel->state != CHANNELD_AWAITING_LOCKIN) {
		log_debug(channel->log, "Lockin complete, but state %s",
			  channel_state_name(channel));
		return;
	}

	channel_set_state(channel,
			  CHANNELD_AWAITING_LOCKIN,
			  CHANNELD_NORMAL,
			  REASON_UNKNOWN,
			  "Lockin complete");

	/* Fees might have changed (and we use IMMEDIATE once we're funded),
	 * so update now. */
	try_update_feerates(channel->peer->ld, channel);

	try_update_blockheight(channel->peer->ld, channel,
			       get_block_height(channel->peer->ld->topology));
	channel_record_open(channel);
}

bool channel_on_funding_locked(struct channel *channel,
			       struct pubkey *next_per_commitment_point)
{
	if (channel->remote_funding_locked) {
		channel_internal_error(channel,
				       "channel_got_funding_locked twice");
		return false;
	}
	update_per_commit_point(channel, next_per_commitment_point);

	log_debug(channel->log, "Got funding_locked");
	channel->remote_funding_locked = true;

	return true;
}

/* We were informed by channeld that it announced the channel and sent
 * an update, so we can now start sending a node_announcement. The
 * first step is to build the provisional announcement and ask the HSM
 * to sign it. */

static void peer_got_funding_locked(struct channel *channel, const u8 *msg)
{
	struct pubkey next_per_commitment_point;

	if (!fromwire_channeld_got_funding_locked(msg,
						 &next_per_commitment_point)) {
		channel_internal_error(channel,
				       "bad channel_got_funding_locked %s",
				       tal_hex(channel, msg));
		return;
	}

	if (!channel_on_funding_locked(channel, &next_per_commitment_point))
		return;

	if (channel->scid)
		lockin_complete(channel);
	else
		/* Remember that we got the lockin */
		wallet_channel_save(channel->peer->ld->wallet, channel);
}

static void peer_got_announcement(struct channel *channel, const u8 *msg)
{
	secp256k1_ecdsa_signature remote_ann_node_sig;
	secp256k1_ecdsa_signature remote_ann_bitcoin_sig;

	if (!fromwire_channeld_got_announcement(msg,
					       &remote_ann_node_sig,
					       &remote_ann_bitcoin_sig)) {
		channel_internal_error(channel,
				       "bad channel_got_announcement %s",
				       tal_hex(tmpctx, msg));
		return;
	}

	wallet_announcement_save(channel->peer->ld->wallet, channel->dbid,
				 &remote_ann_node_sig,
				 &remote_ann_bitcoin_sig);
}

static void peer_got_shutdown(struct channel *channel, const u8 *msg)
{
	u8 *scriptpubkey;
	struct lightningd *ld = channel->peer->ld;
	struct bitcoin_outpoint *wrong_funding;
	bool anysegwit = feature_negotiated(ld->our_features,
					    channel->peer->their_features,
					    OPT_SHUTDOWN_ANYSEGWIT);

	if (!fromwire_channeld_got_shutdown(channel, msg, &scriptpubkey,
					    &wrong_funding)) {
		channel_internal_error(channel, "bad channel_got_shutdown %s",
				       tal_hex(msg, msg));
		return;
	}

	/* FIXME: Add to spec that we must allow repeated shutdown! */
	tal_free(channel->shutdown_scriptpubkey[REMOTE]);
	channel->shutdown_scriptpubkey[REMOTE] = scriptpubkey;

	if (!valid_shutdown_scriptpubkey(scriptpubkey, anysegwit)) {
		channel_fail_permanent(channel,
				       REASON_PROTOCOL,
				       "Bad shutdown scriptpubkey %s",
				       tal_hex(tmpctx, scriptpubkey));
		return;
	}

	/* If we weren't already shutting down, we are now */
	if (channel->state != CHANNELD_SHUTTING_DOWN)
		channel_set_state(channel,
				  channel->state,
				  CHANNELD_SHUTTING_DOWN,
				  REASON_REMOTE,
				  "Peer closes channel");

	/* If we set it, that's what we want.  Otherwise use their preference.
	 * We can't have both, since only opener can set this! */
	if (!channel->shutdown_wrong_funding)
		channel->shutdown_wrong_funding = wrong_funding;

	/* We now watch the "wrong" funding, in case we spend it. */
	channel_watch_wrong_funding(ld, channel);

	/* TODO(cdecker) Selectively save updated fields to DB */
	wallet_channel_save(ld->wallet, channel);
}

void channel_fallen_behind(struct channel *channel, const u8 *msg)
{

	/* per_commitment_point is NULL if option_static_remotekey, but we
	 * use its presence as a flag so set it any valid key in that case. */
	if (!channel->future_per_commitment_point) {
		struct pubkey *any = tal(channel, struct pubkey);
		if (!pubkey_from_node_id(any, &channel->peer->ld->id))
			fatal("Our own id invalid?");
		channel->future_per_commitment_point = any;
	}

	/* Peer sees this, so send a generic msg about unilateral close. */
	channel_fail_permanent(channel,
			       REASON_LOCAL,
			       "Awaiting unilateral close");
}

static void
channel_fail_fallen_behind(struct channel *channel, const u8 *msg)
{
	if (!fromwire_channeld_fail_fallen_behind(channel, msg,
						 cast_const2(struct pubkey **,
							    &channel->future_per_commitment_point))) {
		channel_internal_error(channel,
				       "bad channel_fail_fallen_behind %s",
				       tal_hex(tmpctx, msg));
		return;
	}

        channel_fallen_behind(channel, msg);
}

static void peer_start_closingd_after_shutdown(struct channel *channel,
					       const u8 *msg,
					       const int *fds)
{
	struct peer_fd *peer_fd;

	if (!fromwire_channeld_shutdown_complete(msg)) {
		channel_internal_error(channel, "bad shutdown_complete: %s",
				       tal_hex(msg, msg));
		return;
	}
	peer_fd = new_peer_fd_arr(msg, fds);

	/* This sets channel->owner, closes down channeld. */
	peer_start_closingd(channel, peer_fd);

	/* We might have reconnected, so already be here. */
	if (!channel_closed(channel)
	    && channel->state != CLOSINGD_SIGEXCHANGE)
		channel_set_state(channel,
				  CHANNELD_SHUTTING_DOWN,
				  CLOSINGD_SIGEXCHANGE,
				  REASON_UNKNOWN,
				  "Start closingd");
}

static void forget(struct channel *channel)
{
	struct command **forgets = tal_steal(tmpctx, channel->forgets);
	channel->forgets = tal_arr(channel, struct command *, 0);

	/* Forget the channel. */
	delete_channel(channel);

	for (size_t i = 0; i < tal_count(forgets); i++) {
		assert(!forgets[i]->json_stream);

		struct json_stream *response;
		response = json_stream_success(forgets[i]);
		json_add_string(response, "cancelled",
				"Channel open canceled by RPC(after"
				" fundchannel_complete)");
		was_pending(command_success(forgets[i], response));
	}

	tal_free(forgets);
}

static void handle_error_channel(struct channel *channel,
				 const u8 *msg)
{
	if (!fromwire_channeld_send_error_reply(msg)) {
		channel_internal_error(channel, "bad send_error_reply: %s",
				       tal_hex(tmpctx, msg));
		return;
	}

	forget(channel);
}

static void handle_local_private_channel(struct channel *channel, const u8 *msg)
{
	struct amount_sat capacity;
	u8 *features;

	if (!fromwire_channeld_local_private_channel(msg, msg, &capacity,
						     &features)) {
		channel_internal_error(channel,
				       "bad channeld_local_private_channel %s",
				       tal_hex(channel, msg));
		return;
	}

	tell_gossipd_local_private_channel(channel->peer->ld, channel,
					   capacity, features);
}

static void forget_channel(struct channel *channel, const char *why)
{
	channel->error = towire_errorfmt(channel, &channel->cid, "%s", why);

	/* If the peer is connected, we let them know. Otherwise
	 * we just directly remove the channel */
	if (channel->owner)
		subd_send_msg(channel->owner,
			      take(towire_channeld_send_error(NULL, why)));
	else
		forget(channel);
}

#if EXPERIMENTAL_FEATURES
static void handle_channel_upgrade(struct channel *channel,
				   const u8 *msg)
{
	struct channel_type *newtype;

	if (!fromwire_channeld_upgraded(msg, msg, &newtype)) {
		channel_internal_error(channel, "bad handle_channel_upgrade: %s",
				       tal_hex(tmpctx, msg));
		return;
	}

	/* You can currently only upgrade to turn on option_static_remotekey:
	 * if they somehow thought anything else we need to close channel! */
	if (channel->static_remotekey_start[LOCAL] != 0x7FFFFFFFFFFFFFFFULL) {
		channel_internal_error(channel,
				       "channel_upgrade already static_remotekey? %s",
				       tal_hex(tmpctx, msg));
		return;
	}

	if (!channel_type_eq(newtype, channel_type_static_remotekey(tmpctx))) {
		channel_internal_error(channel,
				       "channel_upgrade must be static_remotekey, not %s",
				       fmt_featurebits(tmpctx, newtype->features));
		return;
	}

	tal_free(channel->type);
	channel->type = channel_type_dup(channel, newtype);
	channel->static_remotekey_start[LOCAL] = channel->next_index[LOCAL];
	channel->static_remotekey_start[REMOTE] = channel->next_index[REMOTE];
	log_debug(channel->log,
		  "option_static_remotekey enabled at %"PRIu64"/%"PRIu64,
		  channel->static_remotekey_start[LOCAL],
		  channel->static_remotekey_start[REMOTE]);

	wallet_channel_save(channel->peer->ld->wallet, channel);
}
#endif /* EXPERIMENTAL_FEATURES */

static unsigned channel_msg(struct subd *sd, const u8 *msg, const int *fds)
{
	enum channeld_wire t = fromwire_peektype(msg);

	switch (t) {
	case WIRE_CHANNELD_SENDING_COMMITSIG:
		peer_sending_commitsig(sd->channel, msg);
		break;
	case WIRE_CHANNELD_GOT_COMMITSIG:
		peer_got_commitsig(sd->channel, msg);
		break;
	case WIRE_CHANNELD_GOT_REVOKE:
		peer_got_revoke(sd->channel, msg);
		break;
	case WIRE_CHANNELD_GOT_FUNDING_LOCKED:
		peer_got_funding_locked(sd->channel, msg);
		break;
	case WIRE_CHANNELD_GOT_ANNOUNCEMENT:
		peer_got_announcement(sd->channel, msg);
		break;
	case WIRE_CHANNELD_GOT_SHUTDOWN:
		peer_got_shutdown(sd->channel, msg);
		break;
	case WIRE_CHANNELD_SHUTDOWN_COMPLETE:
		/* We expect 1 fd. */
		if (!fds)
			return 1;
		peer_start_closingd_after_shutdown(sd->channel, msg, fds);
		break;
	case WIRE_CHANNELD_FAIL_FALLEN_BEHIND:
		channel_fail_fallen_behind(sd->channel, msg);
		break;
	case WIRE_CHANNELD_SEND_ERROR_REPLY:
		handle_error_channel(sd->channel, msg);
		break;
	case WIRE_CHANNELD_USED_CHANNEL_UPDATE:
		/* This tells gossipd we used it. */
		get_channel_update(sd->channel);
		break;
	case WIRE_CHANNELD_LOCAL_CHANNEL_UPDATE:
		tell_gossipd_local_channel_update(sd->ld, sd->channel, msg);
		break;
	case WIRE_CHANNELD_LOCAL_CHANNEL_ANNOUNCEMENT:
		tell_gossipd_local_channel_announce(sd->ld, sd->channel, msg);
		break;
	case WIRE_CHANNELD_LOCAL_PRIVATE_CHANNEL:
		handle_local_private_channel(sd->channel, msg);
		break;
#if EXPERIMENTAL_FEATURES
	case WIRE_CHANNELD_UPGRADED:
		handle_channel_upgrade(sd->channel, msg);
		break;
#else
	case WIRE_CHANNELD_UPGRADED:
#endif
	/* And we never get these from channeld. */
	case WIRE_CHANNELD_INIT:
	case WIRE_CHANNELD_FUNDING_DEPTH:
	case WIRE_CHANNELD_OFFER_HTLC:
	case WIRE_CHANNELD_FULFILL_HTLC:
	case WIRE_CHANNELD_FAIL_HTLC:
	case WIRE_CHANNELD_GOT_COMMITSIG_REPLY:
	case WIRE_CHANNELD_GOT_REVOKE_REPLY:
	case WIRE_CHANNELD_SENDING_COMMITSIG_REPLY:
	case WIRE_CHANNELD_SEND_SHUTDOWN:
	case WIRE_CHANNELD_DEV_REENABLE_COMMIT:
	case WIRE_CHANNELD_FEERATES:
	case WIRE_CHANNELD_BLOCKHEIGHT:
	case WIRE_CHANNELD_SPECIFIC_FEERATES:
	case WIRE_CHANNELD_CHANNEL_UPDATE:
	case WIRE_CHANNELD_DEV_MEMLEAK:
	case WIRE_CHANNELD_DEV_QUIESCE:
		/* Replies go to requests. */
	case WIRE_CHANNELD_OFFER_HTLC_REPLY:
	case WIRE_CHANNELD_DEV_REENABLE_COMMIT_REPLY:
	case WIRE_CHANNELD_DEV_MEMLEAK_REPLY:
	case WIRE_CHANNELD_SEND_ERROR:
	case WIRE_CHANNELD_DEV_QUIESCE_REPLY:
		break;
	}

	return 0;
}

void peer_start_channeld(struct channel *channel,
			 struct peer_fd *peer_fd,
			 const u8 *fwd_msg,
			 bool reconnected,
			 const u8 *reestablish_only)
{
	u8 *initmsg;
	int hsmfd;
	const struct existing_htlc **htlcs;
	struct short_channel_id scid;
	u64 num_revocations;
	struct lightningd *ld = channel->peer->ld;
	const struct config *cfg = &ld->config;
	bool reached_announce_depth;
	struct secret last_remote_per_commit_secret;
	secp256k1_ecdsa_signature *remote_ann_node_sig, *remote_ann_bitcoin_sig;
	struct penalty_base *pbases;

	hsmfd = hsm_get_client_fd(ld, &channel->peer->id,
				  channel->dbid,
				  HSM_CAP_SIGN_GOSSIP
				  | HSM_CAP_ECDH
				  | HSM_CAP_COMMITMENT_POINT
				  | HSM_CAP_SIGN_REMOTE_TX
				  | HSM_CAP_SIGN_ONCHAIN_TX);

	channel_set_owner(channel,
			  new_channel_subd(ld,
					   "lightning_channeld",
					   channel,
					   &channel->peer->id,
					   channel->log, true,
					   channeld_wire_name,
					   channel_msg,
					   channel_errmsg,
					   channel_set_billboard,
					   take(&peer_fd->fd),
					   take(&hsmfd), NULL));

	if (!channel->owner) {
		log_broken(channel->log, "Could not subdaemon channel: %s",
			   strerror(errno));
		channel_fail_reconnect_later(channel,
					     "Failed to subdaemon channel");
		return;
	}

	htlcs = peer_htlcs(tmpctx, channel);

	if (channel->scid) {
		scid = *channel->scid;
		reached_announce_depth
			= is_scid_depth_announceable(&scid,
						     get_block_height(ld->topology));
		log_debug(channel->log, "Already have funding locked in%s",
			  reached_announce_depth
			  ? " (and ready to announce)" : "");
	} else {
		log_debug(channel->log, "Waiting for funding confirmations");
		memset(&scid, 0, sizeof(scid));
		reached_announce_depth = false;
	}

	num_revocations = revocations_received(&channel->their_shachain.chain);

	/* BOLT #2:
	 *     - if `next_revocation_number` equals 0:
	 *       - MUST set `your_last_per_commitment_secret` to all zeroes
	 *     - otherwise:
	 *       - MUST set `your_last_per_commitment_secret` to the last
	 *         `per_commitment_secret` it received
	 */
	if (num_revocations == 0)
		memset(&last_remote_per_commit_secret, 0,
		       sizeof(last_remote_per_commit_secret));
	else if (!shachain_get_secret(&channel->their_shachain.chain,
				      num_revocations-1,
				      &last_remote_per_commit_secret)) {
		channel_fail_permanent(channel,
				       REASON_LOCAL,
				       "Could not get revocation secret %"PRIu64,
				       num_revocations-1);
		return;
	}

	/* Warn once. */
	if (ld->config.ignore_fee_limits)
		log_debug(channel->log, "Ignoring fee limits!");

	if (!wallet_remote_ann_sigs_load(tmpctx, channel->peer->ld->wallet,
					 channel->dbid,
					 &remote_ann_node_sig,
					 &remote_ann_bitcoin_sig)) {
		channel_internal_error(channel,
				       "Could not load remote announcement"
				       " signatures");
		return;
	}

	pbases = wallet_penalty_base_load_for_channel(
	    tmpctx, channel->peer->ld->wallet, channel->dbid);

	initmsg = towire_channeld_init(tmpctx,
				       chainparams,
				       ld->our_features,
				       &channel->cid,
				       &channel->funding,
				       channel->funding_sats,
				       channel->minimum_depth,
				       get_block_height(ld->topology),
				       channel->blockheight_states,
				       channel->lease_expiry,
				       &channel->our_config,
				       &channel->channel_info.their_config,
				       channel->fee_states,
				       feerate_min(ld, NULL),
				       feerate_max(ld, NULL),
				       try_get_feerate(ld->topology, FEERATE_PENALTY),
				       &channel->last_sig,
				       &channel->channel_info.remote_fundingkey,
				       &channel->channel_info.theirbase,
				       &channel->channel_info.remote_per_commit,
				       &channel->channel_info.old_remote_per_commit,
				       channel->opener,
				       channel->feerate_base,
				       channel->feerate_ppm,
				       channel->our_msat,
				       &channel->local_basepoints,
				       &channel->local_funding_pubkey,
				       &ld->id,
				       &channel->peer->id,
				       cfg->commit_time_ms,
				       cfg->cltv_expiry_delta,
				       channel->last_was_revoke,
				       channel->last_sent_commit,
				       channel->next_index[LOCAL],
				       channel->next_index[REMOTE],
				       num_revocations,
				       channel->next_htlc_id,
				       htlcs,
				       channel->scid != NULL,
				       channel->remote_funding_locked,
				       &scid,
				       reconnected,
				       /* Anything that indicates we are or have
					* shut down */
				       channel->state == CHANNELD_SHUTTING_DOWN
				       || channel->state == CLOSINGD_SIGEXCHANGE
				       || channel_closed(channel),
				       channel->shutdown_scriptpubkey[REMOTE] != NULL,
				       channel->shutdown_scriptpubkey[LOCAL],
				       channel->channel_flags,
				       fwd_msg,
				       reached_announce_depth,
				       &last_remote_per_commit_secret,
				       channel->peer->their_features,
				       channel->remote_upfront_shutdown_script,
				       remote_ann_node_sig,
				       remote_ann_bitcoin_sig,
				       channel->type,
				       IFDEV(ld->dev_fast_gossip, false),
				       IFDEV(dev_fail_process_onionpacket, false),
				       IFDEV(ld->dev_disable_commit == -1
					     ? NULL
					     : (u32 *)&ld->dev_disable_commit,
					     NULL),
				       pbases,
				       reestablish_only,
				       channel->channel_update);

	/* We don't expect a response: we are triggered by funding_depth_cb. */
	subd_send_msg(channel->owner, take(initmsg));

	/* On restart, feerate and blockheight
	 * might not be what we expect: adjust now. */
	if (channel->opener == LOCAL) {
		try_update_feerates(ld, channel);
		try_update_blockheight(ld, channel,
				       get_block_height(ld->topology));
	}
}

bool channel_tell_depth(struct lightningd *ld,
			struct channel *channel,
			const struct bitcoin_txid *txid,
			u32 depth)
{
	const char *txidstr;

	txidstr = type_to_string(tmpctx, struct bitcoin_txid, txid);

	if (!channel->owner) {
		log_debug(channel->log,
			  "Funding tx %s confirmed, but peer disconnected",
			  txidstr);
		return false;
	}

	if (streq(channel->owner->name, "dualopend")) {
		if (channel->state != DUALOPEND_AWAITING_LOCKIN) {
			log_debug(channel->log,
				  "Funding tx %s confirmed, but peer in"
				  " state %s",
				  txidstr, channel_state_name(channel));
			return true;
		}

		log_debug(channel->log,
			  "Funding tx %s confirmed, telling peer", txidstr);
		dualopen_tell_depth(channel->owner, channel,
				    txid, depth);
		return true;
	} else if (channel->state != CHANNELD_AWAITING_LOCKIN
	    && channel->state != CHANNELD_NORMAL) {
		/* If not awaiting lockin/announce, it doesn't
		 * care any more */
		log_debug(channel->log,
			  "Funding tx %s confirmed, but peer in state %s",
			  txidstr, channel_state_name(channel));
		return true;
	}

	subd_send_msg(channel->owner,
		      take(towire_channeld_funding_depth(NULL, channel->scid,
							 depth)));

	if (channel->remote_funding_locked
	    && channel->state == CHANNELD_AWAITING_LOCKIN
	    && depth >= channel->minimum_depth)
		lockin_complete(channel);

	return true;
}

/* Check if we are the fundee of this channel, the channel
 * funding transaction is still not yet seen onchain, and
 * it has been too long since the channel was first opened.
 * If so, we should forget the channel. */
static bool
is_fundee_should_forget(struct lightningd *ld,
			struct channel *channel,
			u32 block_height)
{
	/* BOLT #2:
	 *
	 * A non-funding node (fundee):
	 *   - SHOULD forget the channel if it does not see the
	 * correct funding transaction after a timeout of 2016 blocks.
	 */
	u32 max_funding_unconfirmed = IFDEV(ld->dev_max_funding_unconfirmed, 2016);

	/* Only applies if we are fundee. */
	if (channel->opener == LOCAL)
		return false;

	/* Does not apply if we already saw the funding tx. */
	if (channel->scid)
		return false;

	/* Not even reached previous starting blocknum.
	 * (e.g. if --rescan option is used) */
	if (block_height < channel->first_blocknum)
		return false;

	/* Timeout in blocks not yet reached. */
	if (block_height - channel->first_blocknum < max_funding_unconfirmed)
		return false;

	/* If we've got funds in the channel, don't forget it */
	if (!amount_sat_zero(channel->our_funds))
		return false;

	/* Ah forget it! */
	return true;
}

/* Notify all channels of new blocks. */
void channel_notify_new_block(struct lightningd *ld,
			      u32 block_height)
{
	struct peer *peer;
	struct channel *channel;
	struct channel **to_forget = tal_arr(NULL, struct channel *, 0);
	size_t i;

	list_for_each (&ld->peers, peer, list) {
		list_for_each (&peer->channels, channel, list) {
			if (channel_unsaved(channel))
				continue;
			if (is_fundee_should_forget(ld, channel, block_height)) {
				tal_arr_expand(&to_forget, channel);
			} else
				/* Let channels know about new blocks,
				 * required for lease updates */
				try_update_blockheight(ld, channel,
						       block_height);
		}
	}

	/* Need to forget in a separate loop, else the above
	 * nested loops may crash due to the last channel of
	 * a peer also deleting the peer, making the inner
	 * loop crash.
	 * list_for_each_safe does not work because it is not
	 * just the freeing of the channel that occurs, but the
	 * potential destruction of the peer that invalidates
	 * memory the inner loop is accessing. */
	for (i = 0; i < tal_count(to_forget); ++i) {
		channel = to_forget[i];
		/* Report it first. */
		log_unusual(channel->log,
			    "Forgetting channel: "
			    "It has been %"PRIu32" blocks without the "
			    "funding transaction %s getting deeply "
			    "confirmed. "
			    "We are fundee and can forget channel without "
			    "loss of funds.",
			    block_height - channel->first_blocknum,
			    type_to_string(tmpctx, struct bitcoin_txid,
					   &channel->funding.txid));
		/* FIXME: Send an error packet for this case! */
		/* And forget it. */
		delete_channel(channel);
	}

	tal_free(to_forget);
}

struct channel *find_channel_by_id(const struct peer *peer,
				   const struct channel_id *cid)
{
	struct channel *c;

	list_for_each(&peer->channels, c, list) {
		if (channel_id_eq(&c->cid, cid))
			return c;
	}
	return NULL;
}

/* Since this could vanish while we're checking with bitcoind, we need to save
 * the details and re-lookup.
 *
 * channel_id *should* be unique, but it can be set by the counterparty, so
 * we cannot rely on that! */
struct channel_to_cancel {
	struct node_id peer;
	struct channel_id cid;
};

static void process_check_funding_broadcast(struct bitcoind *bitcoind,
					    const struct bitcoin_tx_output *txout,
					    void *arg)
{
	struct channel_to_cancel *cc = arg;
	struct peer *peer;
	struct channel *cancel;

	/* Peer could have errored out while we were waiting */
	peer = peer_by_id(bitcoind->ld, &cc->peer);
	if (!peer)
		goto cleanup;
	cancel = find_channel_by_id(peer, &cc->cid);
	if (!cancel)
		goto cleanup;

	if (txout != NULL) {
		for (size_t i = 0; i < tal_count(cancel->forgets); i++)
			was_pending(command_fail(cancel->forgets[i],
				    FUNDING_CANCEL_NOT_SAFE,
				    "The funding transaction has been broadcast, "
				    "please consider `close` or `dev-fail`! "));
		tal_free(cancel->forgets);
		cancel->forgets = tal_arr(cancel, struct command *, 0);
		goto cleanup;
	}

	char *error_reason = "Cancel channel by our RPC "
			     "command before funding "
			     "transaction broadcast.";
	forget_channel(cancel, error_reason);

cleanup:
	tal_free(cc);
	return;
}

struct command_result *cancel_channel_before_broadcast(struct command *cmd,
						       struct peer *peer)
{
	struct channel *cancel_channel;
	struct channel_to_cancel *cc = tal(cmd, struct channel_to_cancel);
	struct channel *channel;

	cc->peer = peer->id;
	cancel_channel = NULL;
	list_for_each(&peer->channels, channel, list) {
		/* After `fundchannel_complete`, channel is in
		 * `CHANNELD_AWAITING_LOCKIN` state.
		 *
		 * TODO: This assumes only one channel at a time
		 * can be in this state, which is true at the
		 * time of this writing, but may change *if* we
		 * ever implement multiple channels per peer.
		 */
		if (channel->state != CHANNELD_AWAITING_LOCKIN)
			continue;
		cancel_channel = channel;
		break;
	}
	if (!cancel_channel)
		return command_fail(cmd, FUNDING_NOTHING_TO_CANCEL,
				    "No channels being opened or "
				    "awaiting lock-in for "
				    "peer_id %s",
				    type_to_string(tmpctx, struct node_id,
						   &peer->id));
	cc->cid = cancel_channel->cid;

	if (cancel_channel->opener == REMOTE)
		return command_fail(cmd, FUNDING_CANCEL_NOT_SAFE,
				    "Cannot cancel channel that was "
				    "initiated by peer");

	/* Check if we broadcast the transaction. (We store the transaction
	 * type into DB before broadcast). */
	enum wallet_tx_type type;
	if (wallet_transaction_type(cmd->ld->wallet,
				   &cancel_channel->funding.txid,
				   &type))
		return command_fail(cmd, FUNDING_CANCEL_NOT_SAFE,
				    "Has the funding transaction been"
				    " broadcast? Please use `close` or"
				    " `dev-fail` instead.");

	if (channel_has_htlc_out(cancel_channel) ||
	    channel_has_htlc_in(cancel_channel)) {
		return command_fail(cmd, FUNDING_CANCEL_NOT_SAFE,
				    "This channel has HTLCs attached and it"
				    " is not safe to cancel. Has the funding"
				    " transaction been broadcast? Please use"
				    " `close` or `dev-fail` instead.");
	}

	tal_arr_expand(&cancel_channel->forgets, cmd);

	/* Check if the transaction is onchain. */
	/* Note: The above check and this check can't completely ensure that
	 * the funding transaction isn't broadcast. We can't know if the funding
	 * is broadcast by external wallet and the transaction hasn't
	 * been onchain. */
	bitcoind_getutxout(cmd->ld->topology->bitcoind,
			   &cancel_channel->funding,
			   process_check_funding_broadcast,
			   /* Freed by callback */
			   tal_steal(NULL, cc));
	return command_still_pending(cmd);
}

void channel_replace_update(struct channel *channel, u8 *update TAKES)
{
	tal_free(channel->channel_update);
	channel->channel_update = tal_dup_talarr(channel, u8, update);

	/* Keep channeld up-to-date */
	if (!channel->owner || !streq(channel->owner->name, "channeld"))
		return;

	subd_send_msg(channel->owner,
		      take(towire_channeld_channel_update(NULL,
							  channel->channel_update)));
}

#if DEVELOPER
static struct command_result *json_dev_feerate(struct command *cmd,
					       const char *buffer,
					       const jsmntok_t *obj UNNEEDED,
					       const jsmntok_t *params)
{
	u32 *feerate;
	struct node_id *id;
	struct peer *peer;
	struct json_stream *response;
	struct channel *channel;
	const u8 *msg;

	if (!param(cmd, buffer, params,
		   p_req("id", param_node_id, &id),
		   p_req("feerate", param_number, &feerate),
		   NULL))
		return command_param_failed();

	peer = peer_by_id(cmd->ld, id);
	if (!peer)
		return command_fail(cmd, LIGHTNINGD, "Peer not connected");

	channel = peer_active_channel(peer);
	if (!channel || !channel->owner || channel->state != CHANNELD_NORMAL)
		return command_fail(cmd, LIGHTNINGD, "Peer bad state");

	msg = towire_channeld_feerates(NULL, *feerate,
				       feerate_min(cmd->ld, NULL),
				       feerate_max(cmd->ld, NULL),
				       try_get_feerate(cmd->ld->topology,
						       FEERATE_PENALTY));
	subd_send_msg(channel->owner, take(msg));

	response = json_stream_success(cmd);
	json_add_node_id(response, "id", id);
	json_add_u32(response, "feerate", *feerate);

	return command_success(cmd, response);
}

static const struct json_command dev_feerate_command = {
	"dev-feerate",
	"developer",
	json_dev_feerate,
	"Set feerate for {id} to {feerate}"
};
AUTODATA(json_command, &dev_feerate_command);

#if EXPERIMENTAL_FEATURES
static void quiesce_reply(struct subd *channeld UNUSED,
			  const u8 *reply,
			  const int *fds UNUSED,
			  struct command *cmd)
{
	struct json_stream *response;

	response = json_stream_success(cmd);
	was_pending(command_success(cmd, response));
}

static struct command_result *json_dev_quiesce(struct command *cmd,
					       const char *buffer,
					       const jsmntok_t *obj UNNEEDED,
					       const jsmntok_t *params)
{
	struct node_id *id;
	struct peer *peer;
	struct channel *channel;
	const u8 *msg;

	if (!param(cmd, buffer, params,
		   p_req("id", param_node_id, &id),
		   NULL))
		return command_param_failed();

	peer = peer_by_id(cmd->ld, id);
	if (!peer)
		return command_fail(cmd, LIGHTNINGD, "Peer not connected");

	channel = peer_active_channel(peer);
	if (!channel || !channel->owner || channel->state != CHANNELD_NORMAL)
		return command_fail(cmd, LIGHTNINGD, "Peer bad state");

	msg = towire_channeld_dev_quiesce(NULL);
	subd_req(channel->owner, channel->owner, take(msg), -1, 0,
		 quiesce_reply, cmd);
	return command_still_pending(cmd);
}

static const struct json_command dev_quiesce_command = {
	"dev-quiesce",
	"developer",
	json_dev_quiesce,
	"Initiate quiscence protocol with peer"
};
AUTODATA(json_command, &dev_quiesce_command);
#endif /* EXPERIMENTAL_FEATURES */
#endif /* DEVELOPER */
