#include <bitcoin/script.h>
#include <ccan/fdpass/fdpass.h>
#include <channeld/gen_channel_wire.h>
#include <errno.h>
#include <hsmd/capabilities.h>
#include <hsmd/gen_hsm_client_wire.h>
#include <inttypes.h>
#include <lightningd/channel_control.h>
#include <lightningd/closing_control.h>
#include <lightningd/hsm_control.h>
#include <lightningd/lightningd.h>
#include <lightningd/log.h>
#include <lightningd/peer_control.h>
#include <lightningd/subd.h>
#include <wire/wire_sync.h>

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
	tal_free(channel->remote_shutdown_scriptpubkey);
	channel->remote_shutdown_scriptpubkey = scriptpubkey;

	/* BOLT #2:
	 *
	 * A sending node MUST set `scriptpubkey` to one of the following forms:
	 *
	 * 1. `OP_DUP` `OP_HASH160` `20` 20-bytes `OP_EQUALVERIFY` `OP_CHECKSIG`
	 *   (pay to pubkey hash), OR
	 * 2. `OP_HASH160` `20` 20-bytes `OP_EQUAL` (pay to script hash), OR
	 * 3. `OP_0` `20` 20-bytes (version 0 pay to witness pubkey), OR
	 * 4. `OP_0` `32` 32-bytes (version 0 pay to witness script hash)
	 *
	 * A receiving node SHOULD fail the connection if the `scriptpubkey`
	 * is not one of those forms. */
	if (!is_p2pkh(scriptpubkey, NULL) && !is_p2sh(scriptpubkey, NULL)
	    && !is_p2wpkh(scriptpubkey, NULL) && !is_p2wsh(scriptpubkey, NULL)) {
		channel_fail_permanent(channel, "Bad shutdown scriptpubkey %s",
				       tal_hex(channel, scriptpubkey));
		return;
	}

	if (channel->local_shutdown_idx == -1) {
		u8 *scriptpubkey;

		channel->local_shutdown_idx = wallet_get_newindex(ld);
		if (channel->local_shutdown_idx == -1) {
			channel_internal_error(channel,
					    "Can't get local shutdown index");
			return;
		}

		channel_set_state(channel,
				  CHANNELD_NORMAL, CHANNELD_SHUTTING_DOWN);

		/* BOLT #2:
		 *
		 * A sending node MUST set `scriptpubkey` to one of the
		 * following forms:
		 *
		 * ...3. `OP_0` `20` 20-bytes (version 0 pay to witness pubkey),
		 */
		scriptpubkey = p2wpkh_for_keyidx(msg, ld,
						 channel->local_shutdown_idx);
		if (!scriptpubkey) {
			channel_internal_error(channel,
					    "Can't get shutdown script %"PRIu64,
					    channel->local_shutdown_idx);
			return;
		}

		txfilter_add_scriptpubkey(ld->owned_txfilter, scriptpubkey);

		/* BOLT #2:
		 *
		 * A receiving node MUST reply to a `shutdown` message with a
		 * `shutdown` once there are no outstanding updates on the
		 * peer, unless it has already sent a `shutdown`.
		 */
		subd_send_msg(channel->owner,
			      take(towire_channel_send_shutdown(channel,
								scriptpubkey)));
	}

	/* TODO(cdecker) Selectively save updated fields to DB */
	wallet_channel_save(ld->wallet, channel);
}

static void peer_start_closingd_after_shutdown(struct channel *channel,
					       const u8 *msg,
					       const int *fds)
{
	struct crypto_state cs;
	u64 gossip_index;

	/* We expect 2 fds. */
	assert(tal_count(fds) == 2);

	if (!fromwire_channel_shutdown_complete(msg, &cs, &gossip_index)) {
		channel_internal_error(channel, "bad shutdown_complete: %s",
				       tal_hex(msg, msg));
		return;
	}

	/* This sets channel->owner, closes down channeld. */
	peer_start_closingd(channel, &cs, gossip_index, fds[0], fds[1], false);
	channel_set_state(channel, CHANNELD_SHUTTING_DOWN, CLOSINGD_SIGEXCHANGE);
}

static unsigned channel_msg(struct subd *sd, const u8 *msg, const int *fds)
{
	enum channel_wire_type t = fromwire_peektype(msg);

	switch (t) {
	case WIRE_CHANNEL_NORMAL_OPERATION:
		channel_set_state(sd->channel,
				  CHANNELD_AWAITING_LOCKIN, CHANNELD_NORMAL);
		break;
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
	case WIRE_CHANNEL_GOT_SHUTDOWN:
		peer_got_shutdown(sd->channel, msg);
		break;
	case WIRE_CHANNEL_SHUTDOWN_COMPLETE:
		/* We expect 2 fds. */
		if (!fds)
			return 2;
		peer_start_closingd_after_shutdown(sd->channel, msg, fds);
		break;

	/* And we never get these from channeld. */
	case WIRE_CHANNEL_INIT:
	case WIRE_CHANNEL_FUNDING_LOCKED:
	case WIRE_CHANNEL_FUNDING_ANNOUNCE_DEPTH:
	case WIRE_CHANNEL_OFFER_HTLC:
	case WIRE_CHANNEL_FULFILL_HTLC:
	case WIRE_CHANNEL_FAIL_HTLC:
	case WIRE_CHANNEL_PING:
	case WIRE_CHANNEL_GOT_COMMITSIG_REPLY:
	case WIRE_CHANNEL_GOT_REVOKE_REPLY:
	case WIRE_CHANNEL_SENDING_COMMITSIG_REPLY:
	case WIRE_CHANNEL_SEND_SHUTDOWN:
	case WIRE_CHANNEL_DEV_REENABLE_COMMIT:
	case WIRE_CHANNEL_FEERATES:
	/* Replies go to requests. */
	case WIRE_CHANNEL_OFFER_HTLC_REPLY:
	case WIRE_CHANNEL_PING_REPLY:
	case WIRE_CHANNEL_DEV_REENABLE_COMMIT_REPLY:
		break;
	}

	return 0;
}

bool peer_start_channeld(struct channel *channel,
			 const struct crypto_state *cs,
			 u64 gossip_index,
			 int peer_fd, int gossip_fd,
			 const u8 *funding_signed,
			 bool reconnected)
{
	const tal_t *tmpctx = tal_tmpctx(channel);
	u8 *msg, *initmsg;
	int hsmfd;
	struct added_htlc *htlcs;
	enum htlc_state *htlc_states;
	struct fulfilled_htlc *fulfilled_htlcs;
	enum side *fulfilled_sides;
	const struct failed_htlc **failed_htlcs;
	enum side *failed_sides;
	struct short_channel_id funding_channel_id;
	const u8 *shutdown_scriptpubkey;
	u64 num_revocations;
	struct lightningd *ld = channel->peer->ld;
	const struct config *cfg = &ld->config;

	msg = towire_hsm_client_hsmfd(tmpctx, &channel->peer->id, HSM_CAP_SIGN_GOSSIP | HSM_CAP_ECDH);
	if (!wire_sync_write(ld->hsm_fd, take(msg)))
		fatal("Could not write to HSM: %s", strerror(errno));

	msg = hsm_sync_read(tmpctx, ld);
	if (!fromwire_hsm_client_hsmfd_reply(msg))
		fatal("Bad reply from HSM: %s", tal_hex(tmpctx, msg));

	hsmfd = fdpass_recv(ld->hsm_fd);
	if (hsmfd < 0)
		fatal("Could not read fd from HSM: %s", strerror(errno));

	channel_set_owner(channel, new_channel_subd(ld,
					   "lightning_channeld", channel,
					   channel->log,
					   channel_wire_type_name,
					   channel_msg,
					   channel_errmsg,
					   take(&peer_fd),
					   take(&gossip_fd),
					   take(&hsmfd), NULL));

	if (!channel->owner) {
		log_unusual(channel->log, "Could not subdaemon channel: %s",
			    strerror(errno));
		channel_fail_transient(channel, "Failed to subdaemon channel");
		tal_free(tmpctx);
		return true;
	}

	peer_htlcs(tmpctx, channel, &htlcs, &htlc_states, &fulfilled_htlcs,
		   &fulfilled_sides, &failed_htlcs, &failed_sides);

	if (channel->scid) {
		funding_channel_id = *channel->scid;
		log_debug(channel->log, "Already have funding locked in");
	} else {
		log_debug(channel->log, "Waiting for funding confirmations");
		memset(&funding_channel_id, 0, sizeof(funding_channel_id));
	}

	if (channel->local_shutdown_idx != -1) {
		shutdown_scriptpubkey
			= p2wpkh_for_keyidx(tmpctx, ld,
					    channel->local_shutdown_idx);
	} else
		shutdown_scriptpubkey = NULL;

	num_revocations = revocations_received(&channel->their_shachain.chain);

	/* Warn once. */
	if (ld->config.ignore_fee_limits)
		log_debug(channel->log, "Ignoring fee limits!");

	initmsg = towire_channel_init(tmpctx,
				      &get_chainparams(ld)->genesis_blockhash,
				      &channel->funding_txid,
				      channel->funding_outnum,
				      channel->funding_satoshi,
				      &channel->our_config,
				      &channel->channel_info.their_config,
				      channel->channel_info.feerate_per_kw,
				      feerate_min(ld),
				      feerate_max(ld),
				      &channel->last_sig,
				      cs, gossip_index,
				      &channel->channel_info.remote_fundingkey,
				      &channel->channel_info.theirbase.revocation,
				      &channel->channel_info.theirbase.payment,
				      &channel->channel_info.theirbase.htlc,
				      &channel->channel_info.theirbase.delayed_payment,
				      &channel->channel_info.remote_per_commit,
				      &channel->channel_info.old_remote_per_commit,
				      channel->funder,
				      cfg->fee_base,
				      cfg->fee_per_satoshi,
				      channel->our_msatoshi,
				      &channel->seed,
				      &ld->id,
				      &channel->peer->id,
				      time_to_msec(cfg->commit_time),
				      cfg->cltv_expiry_delta,
				      channel->last_was_revoke,
				      channel->last_sent_commit,
				      channel->next_index[LOCAL],
				      channel->next_index[REMOTE],
				      num_revocations,
				      channel->next_htlc_id,
				      htlcs, htlc_states,
				      fulfilled_htlcs, fulfilled_sides,
				      failed_htlcs, failed_sides,
				      channel->scid != NULL,
				      channel->remote_funding_locked,
				      &funding_channel_id,
				      reconnected,
				      shutdown_scriptpubkey,
				      channel->remote_shutdown_scriptpubkey != NULL,
				      channel->channel_flags,
				      funding_signed);

	/* We don't expect a response: we are triggered by funding_depth_cb. */
	subd_send_msg(channel->owner, take(initmsg));

	tal_free(tmpctx);
	return true;
}
