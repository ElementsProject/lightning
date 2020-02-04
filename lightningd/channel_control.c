#include <bitcoin/pubkey.h>
#include <bitcoin/script.h>
#include <ccan/cast/cast.h>
#include <channeld/gen_channel_wire.h>
#include <common/features.h>
#include <common/gossip_constants.h>
#include <common/json_command.h>
#include <common/jsonrpc_errors.h>
#include <common/memleak.h>
#include <common/per_peer_state.h>
#include <common/timeout.h>
#include <common/utils.h>
#include <common/wallet_tx.h>
#include <common/wire_error.h>
#include <errno.h>
#include <hsmd/gen_hsm_wire.h>
#include <inttypes.h>
#include <lightningd/channel_control.h>
#include <lightningd/closing_control.h>
#include <lightningd/hsm_control.h>
#include <lightningd/jsonrpc.h>
#include <lightningd/lightningd.h>
#include <lightningd/log.h>
#include <lightningd/onion_message.h>
#include <lightningd/peer_control.h>
#include <lightningd/subd.h>
#include <wire/gen_common_wire.h>
#include <wire/wire_sync.h>

static void update_feerates(struct lightningd *ld, struct channel *channel)
{
	u8 *msg;
	u32 feerate = unilateral_feerate(ld->topology);

	/* Nothing to do if we don't know feerate. */
	if (!feerate)
		return;

	msg = towire_channel_feerates(NULL, feerate,
				      feerate_min(ld, NULL),
				      feerate_max(ld, NULL));
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

	channel_set_state(channel, CHANNELD_AWAITING_LOCKIN, CHANNELD_NORMAL);

	/* Fees might have changed (and we use IMMEDIATE once we're funded),
	 * so update now. */
	try_update_feerates(channel->peer->ld, channel);
}

/* We were informed by channeld that it announced the channel and sent
 * an update, so we can now start sending a node_announcement. The
 * first step is to build the provisional announcement and ask the HSM
 * to sign it. */

static void peer_got_funding_locked(struct channel *channel, const u8 *msg)
{
	struct pubkey next_per_commitment_point;

	if (!fromwire_channel_got_funding_locked(msg,
						 &next_per_commitment_point)) {
		channel_internal_error(channel,
				       "bad channel_got_funding_locked %s",
				       tal_hex(channel, msg));
		return;
	}

	if (channel->remote_funding_locked) {
		channel_internal_error(channel,
				       "channel_got_funding_locked twice");
		return;
	}
	update_per_commit_point(channel, &next_per_commitment_point);

	log_debug(channel->log, "Got funding_locked");
	channel->remote_funding_locked = true;

	if (channel->scid)
		lockin_complete(channel);
}

static void peer_got_announcement(struct channel *channel, const u8 *msg)
{
	secp256k1_ecdsa_signature remote_ann_node_sig;
	secp256k1_ecdsa_signature remote_ann_bitcoin_sig;

	if (!fromwire_channel_got_announcement(msg,
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

	if (!fromwire_channel_got_shutdown(channel, msg, &scriptpubkey)) {
		channel_internal_error(channel, "bad channel_got_shutdown %s",
				       tal_hex(msg, msg));
		return;
	}

	/* FIXME: Add to spec that we must allow repeated shutdown! */
	tal_free(channel->shutdown_scriptpubkey[REMOTE]);
	channel->shutdown_scriptpubkey[REMOTE] = scriptpubkey;

	/* BOLT #2:
	 *
	 * 1. `OP_DUP` `OP_HASH160` `20` 20-bytes `OP_EQUALVERIFY` `OP_CHECKSIG`
	 *   (pay to pubkey hash), OR
	 * 2. `OP_HASH160` `20` 20-bytes `OP_EQUAL` (pay to script hash), OR
	 * 3. `OP_0` `20` 20-bytes (version 0 pay to witness pubkey), OR
	 * 4. `OP_0` `32` 32-bytes (version 0 pay to witness script hash)
	 *
	 * A receiving node:
	 *...
	 *  - if the `scriptpubkey` is not in one of the above forms:
	 *    - SHOULD fail the connection.
	 */
	if (!is_p2pkh(scriptpubkey, NULL) && !is_p2sh(scriptpubkey, NULL)
	    && !is_p2wpkh(scriptpubkey, NULL) && !is_p2wsh(scriptpubkey, NULL)) {
		channel_fail_permanent(channel, "Bad shutdown scriptpubkey %s",
				       tal_hex(tmpctx, scriptpubkey));
		return;
	}

	/* If we weren't already shutting down, we are now */
	if (channel->state != CHANNELD_SHUTTING_DOWN)
		channel_set_state(channel,
				  channel->state, CHANNELD_SHUTTING_DOWN);

	/* TODO(cdecker) Selectively save updated fields to DB */
	wallet_channel_save(ld->wallet, channel);
}

static void channel_fail_fallen_behind(struct channel *channel, const u8 *msg)
{
	if (!fromwire_channel_fail_fallen_behind(channel, msg,
						 cast_const2(struct pubkey **,
							    &channel->future_per_commitment_point))) {
		channel_internal_error(channel,
				       "bad channel_fail_fallen_behind %s",
				       tal_hex(tmpctx, msg));
		return;
	}

	/* per_commitment_point is NULL if option_static_remotekey, but we
	 * use its presence as a flag so set it any valid key in that case. */
	if (!channel->future_per_commitment_point) {
		struct pubkey *any = tal(channel, struct pubkey);
		if (!channel->option_static_remotekey) {
			channel_internal_error(channel,
					       "bad channel_fail_fallen_behind %s",
					       tal_hex(tmpctx, msg));
			return;
		}
		if (!pubkey_from_node_id(any, &channel->peer->ld->id))
			fatal("Our own id invalid?");
		channel->future_per_commitment_point = any;
	}

	/* Peer sees this, so send a generic msg about unilateral close. */
	channel_fail_permanent(channel,	"Awaiting unilateral close");
}

static void peer_start_closingd_after_shutdown(struct channel *channel,
					       const u8 *msg,
					       const int *fds)
{
	struct per_peer_state *pps;

	if (!fromwire_channel_shutdown_complete(tmpctx, msg, &pps)) {
		channel_internal_error(channel, "bad shutdown_complete: %s",
				       tal_hex(msg, msg));
		return;
	}
	per_peer_state_set_fds_arr(pps, fds);

	/* This sets channel->owner, closes down channeld. */
	peer_start_closingd(channel, pps, false, NULL);
	channel_set_state(channel, CHANNELD_SHUTTING_DOWN, CLOSINGD_SIGEXCHANGE);
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
		json_add_string(response, "cancelled", "Channel open canceled by RPC(after fundchannel_complete)");
		was_pending(command_success(forgets[i], response));
	}

	tal_free(forgets);
}

static void handle_error_channel(struct channel *channel,
				 const u8 *msg)
{
	if (!fromwire_channel_send_error_reply(msg)) {
		channel_internal_error(channel, "bad send_error_reply: %s",
				       tal_hex(tmpctx, msg));
		return;
	}

	forget(channel);
}

void forget_channel(struct channel *channel, bool notify, const char *why)
{
	struct channel_id cid;

	derive_channel_id(&cid, &channel->funding_txid,
			  channel->funding_outnum);
	channel->error = towire_errorfmt(channel, &cid, "%s", why);

	/* If the peer is connected, we let them know. Otherwise
	 * we just directly remove the channel */
	if (channel->owner && notify) {
		subd_send_msg(channel->owner,
			      take(towire_channel_send_error(NULL, why)));
	} else
		forget(channel);
}

bool maybe_bork_channel(struct channel *channel, struct bitcoin_txid *txid,
			struct bitcoin_txid *input_txid, u32 input_outpoint)
{
	/* If there's no RBF alternative, we move this channel into the 'borked' state */
	/* Returns true if borked */
	// TODO: only update to borked if there's no other eligible 'rbf'
	// txids outstanding

	/* The channel may already be in a borked state, if this is a replay from start */
	if (!channel_is_borked(channel))
		channel_set_state(channel, CHANNELD_AWAITING_LOCKIN, CHANNELD_BORKED);
	return true;
}

bool maybe_cleanup_channel(struct channel *channel, const struct bitcoin_txid *txid)
{
	/* in theory, returns false if the channel isn't ready to be cleaned up */
	/* but since we don't do RBF accounting yet... */
	//FIXME: handle removal of txid for an RBF'd tx
	return true;
}

static unsigned channel_msg(struct subd *sd, const u8 *msg, const int *fds)
{
	enum channel_wire_type t = fromwire_peektype(msg);

	switch (t) {
	case WIRE_CHANNEL_SENDING_COMMITSIG:
		peer_sending_commitsig(sd->channel, msg);
		break;
	case WIRE_CHANNEL_GOT_COMMITSIG:
		peer_got_commitsig(sd->channel, msg);
		break;
	case WIRE_CHANNEL_GOT_REVOKE:
		peer_got_revoke(sd->channel, msg);
		break;
	case WIRE_CHANNEL_GOT_FUNDING_LOCKED:
		peer_got_funding_locked(sd->channel, msg);
		break;
	case WIRE_CHANNEL_GOT_ANNOUNCEMENT:
		peer_got_announcement(sd->channel, msg);
		break;
	case WIRE_CHANNEL_GOT_SHUTDOWN:
		peer_got_shutdown(sd->channel, msg);
		break;
	case WIRE_CHANNEL_SHUTDOWN_COMPLETE:
		/* We expect 3 fds. */
		if (!fds)
			return 3;
		peer_start_closingd_after_shutdown(sd->channel, msg, fds);
		break;
	case WIRE_CHANNEL_FAIL_FALLEN_BEHIND:
		channel_fail_fallen_behind(sd->channel, msg);
		break;
	case WIRE_CHANNEL_SEND_ERROR_REPLY:
		handle_error_channel(sd->channel, msg);
		break;
#if EXPERIMENTAL_FEATURES
	case WIRE_GOT_ONIONMSG_TO_US:
		handle_onionmsg_to_us(sd->channel, msg);
		break;
	case WIRE_GOT_ONIONMSG_FORWARD:
		handle_onionmsg_forward(sd->channel, msg);
		break;
#else
	case WIRE_GOT_ONIONMSG_TO_US:
	case WIRE_GOT_ONIONMSG_FORWARD:
#endif
	/* And we never get these from channeld. */
	case WIRE_CHANNEL_INIT:
	case WIRE_CHANNEL_FUNDING_DEPTH:
	case WIRE_CHANNEL_OFFER_HTLC:
	case WIRE_CHANNEL_FULFILL_HTLC:
	case WIRE_CHANNEL_FAIL_HTLC:
	case WIRE_CHANNEL_GOT_COMMITSIG_REPLY:
	case WIRE_CHANNEL_GOT_REVOKE_REPLY:
	case WIRE_CHANNEL_SENDING_COMMITSIG_REPLY:
	case WIRE_CHANNEL_SEND_SHUTDOWN:
	case WIRE_CHANNEL_DEV_REENABLE_COMMIT:
	case WIRE_CHANNEL_FEERATES:
	case WIRE_CHANNEL_SPECIFIC_FEERATES:
	case WIRE_CHANNEL_DEV_MEMLEAK:
	case WIRE_SEND_ONIONMSG:
		/* Replies go to requests. */
	case WIRE_CHANNEL_OFFER_HTLC_REPLY:
	case WIRE_CHANNEL_DEV_REENABLE_COMMIT_REPLY:
	case WIRE_CHANNEL_DEV_MEMLEAK_REPLY:
	case WIRE_CHANNEL_SEND_ERROR:
		break;
	}

	switch ((enum common_wire_type)t) {
#if DEVELOPER
	case WIRE_CUSTOMMSG_IN:
		handle_custommsg_in(sd->ld, sd->node_id, msg);
		break;
#else
	case WIRE_CUSTOMMSG_IN:
#endif
	/* We send these. */
	case WIRE_CUSTOMMSG_OUT:
		break;
	}

	return 0;
}

void peer_start_channeld(struct channel *channel,
			 struct per_peer_state *pps,
			 const u8 *sigs_msg,
			 bool reconnected)
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

	hsmfd = hsm_get_client_fd(ld, &channel->peer->id,
				  channel->dbid,
				  HSM_CAP_SIGN_GOSSIP
				  | HSM_CAP_ECDH
				  | HSM_CAP_COMMITMENT_POINT
				  | HSM_CAP_SIGN_REMOTE_TX);

	channel_set_owner(channel,
			  new_channel_subd(ld,
					   "lightning_channeld", channel,
					   &channel->peer->id,
					   channel->log, true,
					   channel_wire_type_name,
					   channel_msg,
					   channel_errmsg,
					   channel_set_billboard,
					   take(&pps->peer_fd),
					   take(&pps->gossip_fd),
					   take(&pps->gossip_store_fd),
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
				       "Could not get revocation secret %"PRIu64,
				       num_revocations-1);
		return;
	}

	/* Warn once. */
	if (ld->config.ignore_fee_limits)
		log_debug(channel->log, "Ignoring fee limits!");

	if (!wallet_remote_ann_sigs_load(tmpctx, channel->peer->ld->wallet, channel->dbid,
				       &remote_ann_node_sig, &remote_ann_bitcoin_sig)) {
		channel_internal_error(channel,
				       "Could not load remote announcement signatures");
		return;
	}

	initmsg = towire_channel_init(tmpctx,
				      chainparams,
 				      ld->our_features,
				      &channel->funding_txid,
				      channel->funding_outnum,
				      channel->funding,
				      channel->minimum_depth,
				      &channel->our_config,
				      &channel->channel_info.their_config,
				      channel->channel_info.fee_states,
				      feerate_min(ld, NULL),
				      feerate_max(ld, NULL),
				      &channel->last_sig,
				      pps,
				      &channel->channel_info.remote_fundingkey,
				      &channel->channel_info.theirbase,
				      &channel->channel_info.remote_per_commit,
				      &channel->channel_info.old_remote_per_commit,
				      channel->opener,
				      !amount_sat_eq(channel->our_funds, AMOUNT_SAT(0)),
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
				      channel->state == CHANNELD_SHUTTING_DOWN,
				      channel->shutdown_scriptpubkey[REMOTE] != NULL,
				      channel->shutdown_scriptpubkey[LOCAL],
				      channel->channel_flags,
				      sigs_msg,
				      reached_announce_depth,
				      &last_remote_per_commit_secret,
				      channel->peer->their_features,
				      channel->remote_upfront_shutdown_script,
				      remote_ann_node_sig,
				      remote_ann_bitcoin_sig,
				      /* Set at channel open, even if not
				       * negotiated now! */
				      channel->option_static_remotekey,
				      IFDEV(ld->dev_fast_gossip, false),
				      IFDEV(dev_fail_process_onionpacket, false));

	/* We don't expect a response: we are triggered by funding_depth_cb. */
	subd_send_msg(channel->owner, take(initmsg));

	/* On restart, feerate might not be what we expect: adjust now. */
	if (channel->opener == LOCAL)
		try_update_feerates(ld, channel);
}

bool channel_tell_depth(struct lightningd *ld,
				 struct channel *channel,
				 const struct bitcoin_txid *txid,
				 u32 depth)
{
	const char *txidstr;

	txidstr = type_to_string(tmpctx, struct bitcoin_txid, txid);

	/* If not awaiting lockin/announce, it doesn't care any more */
	if (channel->state != CHANNELD_AWAITING_LOCKIN
	    && channel->state != CHANNELD_NORMAL) {
		log_debug(channel->log,
			  "Funding tx %s confirmed, but peer in state %s",
			  txidstr, channel_state_name(channel));
		return true;
	}

	if (!channel->owner) {
		log_debug(channel->log,
			  "Funding tx %s confirmed, but peer disconnected",
			  txidstr);
		return false;
	}

	subd_send_msg(channel->owner,
		      take(towire_channel_funding_depth(NULL, channel->scid,
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
	u32 max_funding_unconfirmed = ld->max_funding_unconfirmed;

	/* BOLT #2:
	 *
	 * A non-funding node (fundee):
	 *   - SHOULD forget the channel if it does not see the
	 * correct funding transaction after a reasonable timeout.
	 */

	/* Only applies if we are fundee. */
	if (channel->opener == LOCAL)
		return false;

	/* Does not apply if we already saw the funding tx. */
	if (channel->scid)
		return false;

	/* Does not apply if we contributed funds.
	 * These will get cleaned up when the
	 * utxo we used to fund them gets spent elsewhere
	 */
	if (!amount_sat_eq(channel->our_funds, AMOUNT_SAT(0)))
		return false;

	/* Not even reached previous starting blocknum.
	 * (e.g. if --rescan option is used) */
	if (block_height < channel->first_blocknum)
		return false;

	/* Timeout in blocks not yet reached. */
	if (block_height - channel->first_blocknum < max_funding_unconfirmed)
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
		list_for_each (&peer->channels, channel, list)
			if (is_fundee_should_forget(ld, channel, block_height)) {
				tal_arr_expand(&to_forget, channel);
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
					   &channel->funding_txid));
		/* FIXME: Send an error packet for this case! */
		/* And forget it. */
		delete_channel(channel);
	}

	tal_free(to_forget);
}

static struct channel *find_channel_by_id(const struct peer *peer,
					  const struct channel_id *cid)
{
	struct channel *c;

	list_for_each(&peer->channels, c, list) {
		struct channel_id this_cid;

		derive_channel_id(&this_cid,
				  &c->funding_txid, c->funding_outnum);
		if (channel_id_eq(&this_cid, cid))
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
		return;
	cancel = find_channel_by_id(peer, &cc->cid);
	if (!cancel)
		return;

	if (txout != NULL) {
		for (size_t i = 0; i < tal_count(cancel->forgets); i++)
			was_pending(command_fail(cancel->forgets[i], LIGHTNINGD,
				    "The funding transaction has been broadcast, "
				    "please consider `close` or `dev-fail`! "));
		tal_free(cancel->forgets);
		cancel->forgets = tal_arr(cancel, struct command *, 0);
		return;
	}

	char *error_reason = "Cancel channel by our RPC "
			     "command before funding "
			     "transaction broadcast.";
	forget_channel(cancel, true, error_reason);
}

struct command_result *cancel_channel_before_broadcast(struct command *cmd,
						       const char *buffer,
						       struct peer *peer,
						       const jsmntok_t *cidtok)
{
	struct channel *cancel_channel;
	struct channel_to_cancel *cc = tal(cmd, struct channel_to_cancel);

	cc->peer = peer->id;
	if (!cidtok) {
		struct channel *channel;

		cancel_channel = NULL;
		list_for_each(&peer->channels, channel, list) {
			if (cancel_channel) {
				return command_fail(cmd, LIGHTNINGD,
						    "Multiple channels:"
						    " please specify channel_id");
			}
			cancel_channel = channel;
		}
		if (!cancel_channel)
			return command_fail(cmd, LIGHTNINGD,
					    "No channels matching that peer_id");
		derive_channel_id(&cc->cid,
				  &cancel_channel->funding_txid,
				  cancel_channel->funding_outnum);
	} else {
		if (!json_tok_channel_id(buffer, cidtok, &cc->cid))
			return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
					    "Invalid channel_id parameter.");

		cancel_channel = find_channel_by_id(peer, &cc->cid);
		if (!cancel_channel)
			return command_fail(cmd, LIGHTNINGD,
					    "Channel ID not found: '%.*s'",
					    cidtok->end - cidtok->start,
					    buffer + cidtok->start);
	}

	if (cancel_channel->opener == REMOTE)
		return command_fail(cmd, LIGHTNINGD,
				    "Cannot cancel channel that was "
				    "initiated by peer");

	if (channel_is_borked(cancel_channel))
		return command_fail(cmd, LIGHTNINGD,
				    "Channel is considered 'borked' and is uncloseable. "
				    "A 'borked' channel is one where a funding_tx input"
				    " has been spent in a different transaction, making"
				    " it unlikely that this channel will open.");

	/* Check if we broadcast the transaction. (We store the transaction type into DB
	 * before broadcast). */
	enum wallet_tx_type type;
	if (wallet_transaction_type(cmd->ld->wallet,
				   &cancel_channel->funding_txid,
				   &type))
		return command_fail(cmd, LIGHTNINGD,
				    "Has the funding transaction been broadcast? "
				    "Please use `close` or `dev-fail` instead.");

	if (channel_has_htlc_out(cancel_channel) ||
	    channel_has_htlc_in(cancel_channel)) {
		return command_fail(cmd, LIGHTNINGD,
				    "This channel has HTLCs attached and it is "
				    "not safe to cancel. Has the funding transaction "
				    "been broadcast? Please use `close` or `dev-fail` "
				    "instead.");
	}

	tal_arr_expand(&cancel_channel->forgets, cmd);

	/* Check if the transaction is onchain. */
	/* Note: The above check and this check can't completely ensure that
	 * the funding transaction isn't broadcast. We can't know if the funding
	 * is broadcast by external wallet and the transaction hasn't been onchain. */
	bitcoind_getutxout(cmd->ld->topology->bitcoind,
			   &cancel_channel->funding_txid,
			   cancel_channel->funding_outnum,
			   process_check_funding_broadcast,
			   notleak(cc));
	return command_still_pending(cmd);
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

	msg = towire_channel_feerates(NULL, *feerate,
				      feerate_min(cmd->ld, NULL),
				      feerate_max(cmd->ld, NULL));
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
#endif /* DEVELOPER */
