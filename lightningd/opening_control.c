#include "config.h"
#include <bitcoin/feerate.h>
#include <bitcoin/psbt.h>
#include <ccan/cast/cast.h>
#include <ccan/mem/mem.h>
#include <ccan/tal/str/str.h>
#include <common/addr.h>
#include <common/blockheight_states.h>
#include <common/configdir.h>
#include <common/fee_states.h>
#include <common/json_channel_type.h>
#include <common/json_command.h>
#include <common/json_param.h>
#include <common/memleak.h>
#include <common/scb_wiregen.h>
#include <connectd/connectd_wiregen.h>
#include <errno.h>
#include <hsmd/permissions.h>
#include <lightningd/chaintopology.h>
#include <lightningd/channel.h>
#include <lightningd/channel_control.h>
#include <lightningd/connect_control.h>
#include <lightningd/hsm_control.h>
#include <lightningd/notification.h>
#include <lightningd/opening_common.h>
#include <lightningd/opening_control.h>
#include <lightningd/peer_fd.h>
#include <lightningd/plugin_hook.h>
#include <lightningd/subd.h>
#include <openingd/openingd_wiregen.h>
#include <sodium/randombytes.h>
#include <wally_psbt.h>

void json_add_uncommitted_channel(struct json_stream *response,
				  const struct uncommitted_channel *uc,
				  const struct peer *peer)
{
	struct amount_msat total, ours;

	if (!uc)
		return;

	/* If we're chatting but no channel, that's shown by connected: True */
	if (!uc->fc)
		return;

	json_object_start(response, NULL);
	json_add_node_id(response, "peer_id", &peer->id);
	json_add_bool(response, "peer_connected", peer->connected == PEER_CONNECTED);
	if (uc->fc->channel_type)
			json_add_channel_type(response, "channel_type", uc->fc->channel_type);
	json_add_string(response, "state", "OPENINGD");
	json_add_string(response, "owner", "lightning_openingd");
	json_add_string(response, "opener", "local");
	if (uc->transient_billboard) {
		json_array_start(response, "status");
		json_add_string(response, NULL, uc->transient_billboard);
		json_array_end(response);
	}

	/* These should never fail. */
	if (amount_sat_to_msat(&total, uc->fc->funding_sats)
	    && amount_msat_sub(&ours, total, uc->fc->push)) {
		json_add_amount_msat(response, "to_us_msat", ours);
		json_add_amount_msat(response, "total_msat", total);
	}

	json_array_start(response, "features");
	if (feature_negotiated(uc->peer->ld->our_features,
			       uc->peer->their_features,
			       OPT_STATIC_REMOTEKEY))
		json_add_string(response, NULL, "option_static_remotekey");

	if (feature_negotiated(uc->peer->ld->our_features,
			       uc->peer->their_features,
			       OPT_ANCHORS_ZERO_FEE_HTLC_TX))
		json_add_string(response, NULL, "option_anchors_zero_fee_htlc_tx");

	json_array_end(response);
	json_object_end(response);
}

/* Steals fields from uncommitted_channel: returns NULL if can't generate a
 * key for this channel (shouldn't happen!). */
static struct channel *
wallet_commit_channel(struct lightningd *ld,
		      struct uncommitted_channel *uc,
		      struct channel_id *cid,
		      struct bitcoin_tx *remote_commit,
		      struct bitcoin_signature *remote_commit_sig,
		      const struct bitcoin_outpoint *funding,
		      struct amount_sat funding_sats,
		      struct amount_msat push,
		      u8 channel_flags,
		      struct channel_info *channel_info,
		      u32 feerate,
		      const u8 *our_upfront_shutdown_script,
		      const u8 *remote_upfront_shutdown_script,
		      const struct channel_type *type)
{
	struct channel *channel;
	struct amount_msat our_msat;
	struct amount_sat local_funding;
	s64 final_key_idx;
	u64 static_remotekey_start;
	u32 lease_start_blockheight = 0; /* No leases on v1 */
	struct short_channel_id local_alias;
	struct timeabs timestamp;
	bool any_active = peer_any_channel(uc->peer, channel_state_wants_peercomms, NULL);

	/* We cannot both be the fundee *and* have a `fundchannel_start`
	 * command running!
	 */
	assert(!(uc->got_offer && uc->fc));

	/* Get a key to use for closing outputs from this tx */
	final_key_idx = wallet_get_newindex(ld);
	if (final_key_idx == -1) {
		log_broken(uc->log, "Can't get final key index");
		return NULL;
	}

	if (uc->fc) {
		if (!amount_sat_sub_msat(&our_msat, funding_sats, push)) {
			log_broken(uc->log, "push %s exceeds funding %s",
				   fmt_amount_msat(tmpctx, push),
				   fmt_amount_sat(tmpctx, funding_sats));
			return NULL;
		}
		local_funding = funding_sats;
	} else {
		our_msat = push;
		local_funding = AMOUNT_SAT(0);
	}

	/* old_remote_per_commit not valid yet, copy valid one. */
	channel_info->old_remote_per_commit = channel_info->remote_per_commit;

	/* BOLT #2:
	 * 1. type: 35 (`funding_signed`)
	 * 2. data:
	 *     * [`channel_id`:`channel_id`]
	 *     * [`signature`:`signature`]
	 *
	 * #### Requirements
	 *
	 * Both peers:
	 * ...
	 * - MUST use that `channel_type` for all commitment transactions.
	 */
	/* i.e. We set it now for the channel permanently. */
	if (channel_type_has(type, OPT_STATIC_REMOTEKEY))
		static_remotekey_start = 0;
	else
		static_remotekey_start = 0x7FFFFFFFFFFFFFFF;

	/* This won't clash, we don't even bother checking */
	randombytes_buf(&local_alias, sizeof(local_alias));

	channel = new_channel(uc->peer, uc->dbid,
			      NULL, /* No shachain yet */
			      CHANNELD_AWAITING_LOCKIN,
			      uc->fc ? LOCAL : REMOTE,
			      uc->log,
			      take(uc->transient_billboard),
			      channel_flags,
			      false, false,
			      &uc->our_config,
			      uc->minimum_depth,
			      1, 1, 0,
			      funding,
			      funding_sats,
			      push,
			      local_funding,
			      false, /* !remote_channel_ready */
			      NULL, /* no scid yet */
			      &local_alias,
			      NULL, /* They haven't told us an alias yet */
			      cid,
			      /* The three arguments below are msatoshi_to_us,
			       * msatoshi_to_us_min, and msatoshi_to_us_max.
			       * Because, this is a newly-funded channel,
			       * all three are same value. */
			      our_msat,
			      our_msat, /* msat_to_us_min */
			      our_msat, /* msat_to_us_max */
			      remote_commit,
			      remote_commit_sig,
			      NULL, /* No HTLC sigs yet */
			      channel_info,
			      take(new_fee_states(NULL, uc->fc ? LOCAL : REMOTE,
						  &feerate)),
			      NULL, /* No shutdown_scriptpubkey[REMOTE] yet */
			      our_upfront_shutdown_script,
			      final_key_idx, false,
			      NULL, /* No commit sent yet */
			      /* If we're fundee, could be a little before this
			       * in theory, but it's only used for timing out. */
			      get_network_blockheight(ld->topology),
			      feerate, feerate,
			      &uc->local_basepoints,
			      &uc->local_funding_pubkey,
			      false, /* !has_future_per_commitment_point */
			      ld->config.fee_base,
			      ld->config.fee_per_satoshi,
			      remote_upfront_shutdown_script,
			      static_remotekey_start, static_remotekey_start,
			      type,
			      NUM_SIDES, /* closer not yet known */
			      uc->fc ? REASON_USER : REASON_REMOTE,
			      NULL,
			      take(new_height_states(NULL, uc->fc ? LOCAL : REMOTE,
						     &lease_start_blockheight)),
			      0, NULL, 0, 0, /* No leases on v1s */
			      ld->config.htlc_minimum_msat,
			      ld->config.htlc_maximum_msat,
			      ld->config.ignore_fee_limits,
			      NULL,
			      0);

	/* Now we finally put it in the database. */
	wallet_channel_insert(ld->wallet, channel);

	/* Notify that channel state changed (from non existant to existant) */
	timestamp = time_now();
	notify_channel_state_changed(ld, &channel->peer->id,
				     &channel->cid,
				     channel->scid, /* NULL */
				     timestamp,
				     0, /* No prior state */
				     channel->state,
				     channel->state_change_cause,
				     "new channel opened");


	/* We might have disconnected and decided we didn't need to
	 * reconnect because no channels are active.  But the subd
	 * just made it active! */
	if (!any_active && channel->peer->connected == PEER_DISCONNECTED) {
		try_reconnect(channel->peer, channel->peer,
			      &channel->peer->addr);
	}

	return channel;
}

/** cancel_after_fundchannel_complete_success
 *
 * @brief Called to cancel a `fundchannel` after
 * a `fundchannel_complete` succeeds.
 *
 * @desc Specifically, this is called when a
 * `fundchannel_cancel` is blocked due to a
 * parallel `fundchannel_complete` still running.
 * After the `fundchannel_complete` succeeds, we
 * invoke this function to cancel the funding
 * after all.
 *
 * In effect, this forces the `fundchannel_cancel`
 * to be invoked after the `fundchannel_complete`
 * succeeds, leading to a reasonable serial
 * execution.
 *
 * @param cmd - The `fundchannel_cancel` command
 * that wants to cancel this.
 * @param channel - The channel being cancelled.
 */
static void
cancel_after_fundchannel_complete_success(struct command *cmd,
					  struct channel *channel)
{
	was_pending(cancel_channel_before_broadcast(cmd, channel->peer));
}

static void funding_success(struct channel *channel)
{
	struct json_stream *response;
	struct funding_channel *fc =
		channel->peer->uncommitted_channel->fc;
	struct command *cmd = fc->cmd;

	/* Well, those cancels now need to trigger!  */
	for (size_t i = 0; i < tal_count(fc->cancels); i++)
		cancel_after_fundchannel_complete_success(fc->cancels[i],
							  channel);

	response = json_stream_success(cmd);
	json_add_string(response, "channel_id",
			fmt_channel_id(tmpctx,
				       &channel->cid));
	json_add_bool(response, "commitments_secured", true);
	was_pending(command_success(cmd, response));
}

static void funding_started_success(struct funding_channel *fc)
{
	struct json_stream *response;
	struct command *cmd = fc->cmd;
	char *out;

	response = json_stream_success(cmd);
	out = encode_scriptpubkey_to_addr(cmd,
				          chainparams,
					  fc->funding_scriptpubkey);
	if (out) {
		json_add_string(response, "funding_address", out);
		json_add_hex_talarr(response, "scriptpubkey",
				    fc->funding_scriptpubkey);
		if (fc->our_upfront_shutdown_script)
			json_add_hex_talarr(response, "close_to", fc->our_upfront_shutdown_script);
		json_add_channel_type(response, "channel_type", fc->channel_type);
		json_add_string(response, "warning_usage",
				"The funding transaction MUST NOT be broadcast until after channel establishment has been successfully completed by running `fundchannel_complete`");
	}

	/* Clear this so cancel doesn't think it's still in progress */
	fc->cmd = NULL;
	was_pending(command_success(cmd, response));
}

static void opening_funder_start_replied(struct subd *openingd, const u8 *resp,
					 const int *fds,
					 struct funding_channel *fc)
{
	bool supports_shutdown_script;

	if (!fromwire_openingd_funder_start_reply(fc, resp,
						  &fc->funding_scriptpubkey,
						  &supports_shutdown_script,
						  &fc->channel_type)) {
		log_broken(fc->uc->log,
			   "bad OPENING_FUNDER_REPLY %s",
			   tal_hex(resp, resp));
		was_pending(command_fail(fc->cmd, LIGHTNINGD,
					 "bad OPENING_FUNDER_REPLY %s",
					 tal_hex(fc->cmd, resp)));
		goto failed;
	}

	/* If we're not using the upfront shutdown script, forget it */
	if (!supports_shutdown_script)
		fc->our_upfront_shutdown_script =
			tal_free(fc->our_upfront_shutdown_script);

	funding_started_success(fc);

	/* Mark that we're in-flight */
	fc->inflight = true;
	return;

failed:
	/* Frees fc too */
	tal_free(fc->uc);
}

static void opening_funder_finished(struct subd *openingd, const u8 *resp,
				    const int *fds,
				    struct funding_channel *fc)
{
	struct channel_info channel_info;
	struct channel_id cid;
	struct bitcoin_outpoint funding;
	struct bitcoin_signature remote_commit_sig;
	struct bitcoin_tx *remote_commit;
	u32 feerate;
	struct channel *channel;
	struct lightningd *ld = openingd->ld;
	u8 *remote_upfront_shutdown_script;
	struct peer_fd *peer_fd;
	struct penalty_base *pbase;
	struct channel_type *type;

	/* This is a new channel_info.their_config so set its ID to 0 */
	channel_info.their_config.id = 0;

	if (!fromwire_openingd_funder_reply(resp, resp,
					   &channel_info.their_config,
					   &remote_commit,
					   &pbase,
					   &remote_commit_sig,
					   &channel_info.theirbase.revocation,
					   &channel_info.theirbase.payment,
					   &channel_info.theirbase.htlc,
					   &channel_info.theirbase.delayed_payment,
					   &channel_info.remote_per_commit,
					   &fc->uc->minimum_depth,
					   &channel_info.remote_fundingkey,
					   &funding,
					   &feerate,
					   &fc->uc->our_config.channel_reserve,
					   &remote_upfront_shutdown_script,
					   &type)) {
		log_broken(fc->uc->log,
			   "bad OPENING_FUNDER_REPLY %s",
			   tal_hex(resp, resp));
		was_pending(command_fail(fc->cmd, LIGHTNINGD,
					 "bad OPENING_FUNDER_REPLY %s",
					 tal_hex(fc->cmd, resp)));
		goto cleanup;
	}
	remote_commit->chainparams = chainparams;

	peer_fd = new_peer_fd_arr(resp, fds);

	log_debug(ld->log,
		  "%s", fmt_pubkey(tmpctx,
				       &channel_info.remote_per_commit));

	/* Saved with channel to disk */
	derive_channel_id(&cid, &funding);

	/* old_remote_per_commit not valid yet, copy valid one. */
	channel_info.old_remote_per_commit = channel_info.remote_per_commit;

	/* Steals fields from uc */
	channel = wallet_commit_channel(ld, fc->uc,
					&cid,
					remote_commit,
					&remote_commit_sig,
					&funding,
					fc->funding_sats,
					fc->push,
					fc->channel_flags,
					&channel_info,
					feerate,
					fc->our_upfront_shutdown_script,
					remote_upfront_shutdown_script,
					type);
	if (!channel) {
		was_pending(command_fail(fc->cmd, LIGHTNINGD,
					 "Key generation failure"));
		goto cleanup;
	}

	/* Watch for funding confirms */
	channel_watch_funding(ld, channel);

	if (pbase)
		wallet_penalty_base_add(ld->wallet, channel->dbid, pbase);

	/* If this fails, it cleans up */
	if (!peer_start_channeld(channel, peer_fd, NULL, false, NULL))
		return;

	funding_success(channel);

cleanup:
	/* Frees fc too */
	tal_free(fc->uc);
}

static void opening_fundee_finished(struct subd *openingd,
				    const u8 *reply,
				    const int *fds,
				    struct uncommitted_channel *uc)
{
	const u8 *fwd_msg;
	struct channel_info channel_info;
	struct bitcoin_signature remote_commit_sig;
	struct bitcoin_tx *remote_commit;
	struct channel_id cid;
	struct lightningd *ld = openingd->ld;
	struct bitcoin_outpoint funding;
	struct amount_sat funding_sats;
	struct amount_msat push;
	u32 feerate;
	u8 channel_flags;
	struct channel *channel;
	u8 *remote_upfront_shutdown_script, *local_upfront_shutdown_script;
	struct peer_fd *peer_fd;
	struct penalty_base *pbase;
	struct channel_type *type;

	log_debug(uc->log, "Got opening_fundee_finish_response");

	/* This is a new channel_info.their_config, set its ID to 0 */
	channel_info.their_config.id = 0;

	peer_fd = new_peer_fd_arr(tmpctx, fds);
	if (!fromwire_openingd_fundee(tmpctx, reply,
				     &channel_info.their_config,
				     &remote_commit,
				     &pbase,
				     &remote_commit_sig,
				     &channel_info.theirbase.revocation,
				     &channel_info.theirbase.payment,
				     &channel_info.theirbase.htlc,
				     &channel_info.theirbase.delayed_payment,
				     &channel_info.remote_per_commit,
				     &channel_info.remote_fundingkey,
				     &funding,
				     &funding_sats,
				     &push,
				     &channel_flags,
				     &feerate,
				     cast_const2(u8 **, &fwd_msg),
				     &uc->our_config.channel_reserve,
				     &local_upfront_shutdown_script,
				     &remote_upfront_shutdown_script,
				     &type)) {
		log_broken(uc->log, "bad OPENING_FUNDEE_REPLY %s",
			   tal_hex(reply, reply));
		uncommitted_channel_disconnect(uc, LOG_BROKEN,
					       "bad OPENING_FUNDEE_REPLY");
		goto failed;
	}

	remote_commit->chainparams = chainparams;

	derive_channel_id(&cid, &funding);

	/* old_remote_per_commit not valid yet, copy valid one. */
	channel_info.old_remote_per_commit = channel_info.remote_per_commit;

	/* Consumes uc */
	channel = wallet_commit_channel(ld, uc,
					&cid,
					remote_commit,
					&remote_commit_sig,
					&funding,
					funding_sats,
					push,
					channel_flags,
					&channel_info,
					feerate,
					local_upfront_shutdown_script,
					remote_upfront_shutdown_script,
					type);
	if (!channel) {
		uncommitted_channel_disconnect(uc, LOG_BROKEN,
					       "Commit channel failed");
		goto failed;
	}

	log_debug(channel->log, "Watching funding tx %s",
		  fmt_bitcoin_txid(reply,
				 &channel->funding.txid));

	channel_watch_funding(ld, channel);

	/* Tell plugins about the success */
	notify_channel_opened(ld, &channel->peer->id, &channel->funding_sats,
			      &channel->funding.txid, channel->remote_channel_ready);

	if (pbase)
		wallet_penalty_base_add(ld->wallet, channel->dbid, pbase);

	/* On to normal operation (frees if it fails!) */
	if (peer_start_channeld(channel, peer_fd, fwd_msg, false, NULL))
		tal_free(uc);
	return;

failed:
	tal_free(uc);
}

static void
opening_funder_failed_cancel_commands(struct uncommitted_channel *uc,
				      const char *desc)
{
	/* If no funding command(s) pending, do nothing.  */
	if (!uc->fc)
		return;

	/* Tell anyone who was trying to cancel */
	for (size_t i = 0; i < tal_count(uc->fc->cancels); i++) {
		struct json_stream *response;

		response = json_stream_success(uc->fc->cancels[i]);
		json_add_string(response, "cancelled", desc);
		was_pending(command_success(uc->fc->cancels[i], response));
	}

	/* Tell any fundchannel_complete or fundchannel command */
	if (uc->fc->cmd)
		was_pending(command_fail(uc->fc->cmd, LIGHTNINGD, "%s", desc));

	/* Clear uc->fc, so we can try again, and so we don't fail twice
	 * if they close.
	 * This code is also used in the case where we turn out to already
	 * be the fundee, in which case we should not have any `fc` at all,
	 * so we definitely should clear this.
	 */
	uc->fc = tal_free(uc->fc);
}

static void openingd_failed(struct subd *openingd, const u8 *msg,
			    struct uncommitted_channel *uc)
{
	char *desc;

	/* Since we're detaching from uc, we'll be unreferenced until
	 * our imminent exit (as will our parent, openingd->conn). */
	notleak(openingd);
	/* openingd->conn is set to NULL temporarily for this call, so: */
	notleak(tal_parent(openingd));

	if (!fromwire_openingd_failed(msg, msg, &desc)) {
		log_broken(uc->log,
			   "bad OPENINGD_FAILED %s",
			   tal_hex(tmpctx, msg));
		if (uc->fc)
			was_pending(command_fail(uc->fc->cmd, LIGHTNINGD,
						 "bad OPENINGD_FAILED %s",
						 tal_hex(uc->fc->cmd, msg)));
		tal_free(uc);
		return;
	}

	/* Noop if we're not funder. */
	opening_funder_failed_cancel_commands(uc, desc);
	/* Detaches from ->peer */
	tal_free(uc);
}

struct openchannel_hook_payload {
	struct subd *openingd;
	struct uncommitted_channel* uc;
	struct amount_sat funding_satoshis;
	struct amount_msat push_msat;
	struct amount_sat dust_limit_satoshis;
	struct amount_msat max_htlc_value_in_flight_msat;
	struct amount_sat channel_reserve_satoshis;
	struct amount_msat htlc_minimum_msat;
	u32 feerate_per_kw;
	u16 to_self_delay;
	u16 max_accepted_htlcs;
	u8 channel_flags;
	u8 *shutdown_scriptpubkey;
	const u8 *our_upfront_shutdown_script;
	char *errmsg;
};

static void openchannel_hook_serialize(struct openchannel_hook_payload *payload,
				       struct json_stream *stream,
				       struct plugin *plugin)
{
	struct uncommitted_channel *uc = payload->openingd->channel;
	json_object_start(stream, "openchannel");
	json_add_node_id(stream, "id", &uc->peer->id);
	json_add_amount_sat_msat(stream, "funding_msat",
				 payload->funding_satoshis);
	json_add_amount_msat(stream, "push_msat", payload->push_msat);
	json_add_amount_sat_msat(stream, "dust_limit_msat",
				 payload->dust_limit_satoshis);
	json_add_amount_msat(stream, "max_htlc_value_in_flight_msat",
			     payload->max_htlc_value_in_flight_msat);
	json_add_amount_sat_msat(stream, "channel_reserve_msat",
				 payload->channel_reserve_satoshis);
	json_add_amount_msat(stream, "htlc_minimum_msat",
			     payload->htlc_minimum_msat);
	json_add_num(stream, "feerate_per_kw", payload->feerate_per_kw);
	json_add_num(stream, "to_self_delay", payload->to_self_delay);
	json_add_num(stream, "max_accepted_htlcs", payload->max_accepted_htlcs);
	json_add_num(stream, "channel_flags", payload->channel_flags);
	if (tal_count(payload->shutdown_scriptpubkey) != 0)
		json_add_hex_talarr(stream, "shutdown_scriptpubkey",
				    payload->shutdown_scriptpubkey);
	json_object_end(stream); /* .openchannel */
}

/* openingd dies?  Remove openingd ptr from payload */
static void openchannel_payload_remove_openingd(struct subd *openingd,
					    struct openchannel_hook_payload *payload)
{
	assert(payload->openingd == openingd);
	payload->openingd = NULL;
}

static void
openchannel_hook_final(struct openchannel_hook_payload *payload STEALS)
{
	struct subd *openingd = payload->openingd;
	const u8 *our_upfront_shutdown_script = payload->our_upfront_shutdown_script;
	const char *errmsg = payload->errmsg;
	struct uncommitted_channel* uc = payload->uc;
	u32 *upfront_shutdown_script_wallet_index;

	/* We want to free this, whatever happens. */
	tal_steal(tmpctx, payload);

	/* If openingd went away, don't send it anything! */
	if (!openingd)
		return;

	tal_del_destructor2(openingd, openchannel_payload_remove_openingd, payload);

	if (!errmsg) {
		/* Plugins accepted the offer, cancel any of our
		 * funder-side commands.  */
		opening_funder_failed_cancel_commands(uc,
						      "Have in-progress "
						      "`open_channel` from "
						      "peer");
		uc->got_offer = true;
	}

	/* Determine the wallet index for our_upfront_shutdown_script,
	 * NULL if not found. */
	u32 found_wallet_index;
	if (wallet_can_spend(payload->openingd->ld->wallet,
			     our_upfront_shutdown_script,
			     &found_wallet_index)) {
		upfront_shutdown_script_wallet_index = tal(tmpctx, u32);
		*upfront_shutdown_script_wallet_index = found_wallet_index;
	} else
		upfront_shutdown_script_wallet_index = NULL;

	subd_send_msg(openingd,
		      take(towire_openingd_got_offer_reply(NULL, errmsg,
							   our_upfront_shutdown_script,
							   upfront_shutdown_script_wallet_index,
							   payload->uc->reserve,
							   payload->uc->minimum_depth)));
}

static bool
openchannel_hook_deserialize(struct openchannel_hook_payload *payload,
			     const char *buffer,
			     const jsmntok_t *toks)
{
	struct subd *openingd = payload->openingd;

	/* already rejected by prior plugin hook in the chain */
	if (payload->errmsg != NULL)
		return true;

	if (!toks || !buffer)
		return true;

	const jsmntok_t *t_result  = json_get_member(buffer, toks, "result");
	const jsmntok_t *t_errmsg  = json_get_member(buffer, toks, "error_message");
	const jsmntok_t *t_closeto = json_get_member(buffer, toks, "close_to");
	const jsmntok_t *t_mindepth = json_get_member(buffer, toks, "mindepth");
	const jsmntok_t *t_reserve = json_get_member(buffer, toks, "reserve");

	if (!t_result)
		fatal("Plugin returned an invalid response to the"
		      " openchannel hook: %.*s",
		      toks[0].end - toks[0].start, buffer + toks[0].start);

	/* reject */
	if (json_tok_streq(buffer, t_result, "reject")) {
		payload->errmsg = "";
		if (t_errmsg)
			payload->errmsg = json_strdup(payload, buffer, t_errmsg);
		log_debug(openingd->ld->log,
			  "openchannel hook rejects and says '%s'",
			  payload->errmsg);
		if (t_closeto)
			fatal("Plugin rejected openchannel but also set close_to");
		openchannel_hook_final(payload);
		return false;
	} else if (!json_tok_streq(buffer, t_result, "continue")) {
		fatal("Plugin returned an invalid result for the "
		      "openchannel hook: %.*s",
		      t_result->end - t_result->start, buffer + t_result->start);
	}

	/* Check for a valid 'close_to' address passed back */
	if (t_closeto) {
		/* First plugin can set close_to. Log others. */
		if (payload->our_upfront_shutdown_script != NULL) {
			log_broken(openingd->ld->log,
				   "openchannel hook close_to address was"
				   " already set by other plugin. Ignoring!");
			return true;
		}
		switch (json_to_address_scriptpubkey(tmpctx, chainparams,
						     buffer, t_closeto,
						     &payload->our_upfront_shutdown_script)) {
			case ADDRESS_PARSE_UNRECOGNIZED:
				fatal("Plugin returned an invalid response to"
				      " the openchannel.close_to hook: %.*s",
				      t_closeto->end - t_closeto->start,
				      buffer + t_closeto->start);
			case ADDRESS_PARSE_WRONG_NETWORK:
				fatal("Plugin returned invalid response to the"
				      " openchannel.close_to hook: address %s is"
				      " not on network %s",
				      tal_hex(NULL, payload->our_upfront_shutdown_script),
				      chainparams->network_name);
			case ADDRESS_PARSE_SUCCESS:
				break;
		}
	}

	if (t_mindepth != NULL) {
		json_to_u32(buffer, t_mindepth, &payload->uc->minimum_depth);
		log_debug(
		    openingd->ld->log,
		    "Setting mindepth=%d for this channel as requested by "
		    "the openchannel hook",
		    payload->uc->minimum_depth);
	}

	if (t_reserve != NULL) {
		payload->uc->reserve = tal(payload->uc, struct amount_sat);
		json_to_sat(buffer, t_reserve, payload->uc->reserve);
		log_debug(openingd->ld->log,
			  "Setting reserve=%s for this channel as requested by "
			  "the openchannel hook",
			  fmt_amount_sat(tmpctx, *payload->uc->reserve));
	}

	return true;
}

REGISTER_PLUGIN_HOOK(openchannel,
		     openchannel_hook_deserialize,
		     openchannel_hook_final,
		     openchannel_hook_serialize,
		     struct openchannel_hook_payload *);

static void opening_got_offer(struct subd *openingd,
			      const u8 *msg,
			      struct uncommitted_channel *uc)
{
	struct openchannel_hook_payload *payload;

	payload = tal(openingd, struct openchannel_hook_payload);
	payload->openingd = openingd;
	payload->uc = uc;
	payload->our_upfront_shutdown_script = NULL;
	payload->errmsg = NULL;
	if (!fromwire_openingd_got_offer(payload, msg,
					&payload->funding_satoshis,
					&payload->push_msat,
					&payload->dust_limit_satoshis,
					&payload->max_htlc_value_in_flight_msat,
					&payload->channel_reserve_satoshis,
					&payload->htlc_minimum_msat,
					&payload->feerate_per_kw,
					&payload->to_self_delay,
					&payload->max_accepted_htlcs,
					&payload->channel_flags,
					&payload->shutdown_scriptpubkey)) {
		log_broken(openingd->log, "Malformed opening_got_offer %s",
			   tal_hex(tmpctx, msg));
		tal_free(openingd);
		return;
	}

	tal_add_destructor2(openingd, openchannel_payload_remove_openingd, payload);
	plugin_hook_call_openchannel(openingd->ld, NULL, payload);
}

static unsigned int openingd_msg(struct subd *openingd,
				 const u8 *msg, const int *fds)
{
	enum openingd_wire t = fromwire_peektype(msg);
	struct uncommitted_channel *uc = openingd->channel;

	switch (t) {
	case WIRE_OPENINGD_FUNDER_REPLY:
		if (!uc->fc) {
			log_broken(openingd->log, "Unexpected FUNDER_REPLY %s",
				   tal_hex(tmpctx, msg));
			tal_free(openingd);
			return 0;
		}
		if (tal_count(fds) != 1)
			return 1;
		opening_funder_finished(openingd, msg, fds, uc->fc);
		return 0;
	case WIRE_OPENINGD_FUNDER_START_REPLY:
		if (!uc->fc) {
			log_broken(openingd->log, "Unexpected FUNDER_START_REPLY %s",
				   tal_hex(tmpctx, msg));
			tal_free(openingd);
			return 0;
		}
		opening_funder_start_replied(openingd, msg, fds, uc->fc);
		return 0;
	case WIRE_OPENINGD_FAILED:
		openingd_failed(openingd, msg, uc);
		return 0;

	case WIRE_OPENINGD_FUNDEE:
		if (tal_count(fds) != 1)
			return 1;
		opening_fundee_finished(openingd, msg, fds, uc);
		return 0;

	case WIRE_OPENINGD_GOT_OFFER:
		opening_got_offer(openingd, msg, uc);
		return 0;

	/* We send these! */
	case WIRE_OPENINGD_INIT:
	case WIRE_OPENINGD_FUNDER_START:
	case WIRE_OPENINGD_FUNDER_COMPLETE:
	case WIRE_OPENINGD_FUNDER_CANCEL:
	case WIRE_OPENINGD_GOT_OFFER_REPLY:
	case WIRE_OPENINGD_DEV_MEMLEAK:
	/* Replies never get here */
	case WIRE_OPENINGD_DEV_MEMLEAK_REPLY:
		break;
	}

	log_broken(openingd->log, "Unexpected msg %s: %s",
		   openingd_wire_name(t), tal_hex(tmpctx, msg));
	tal_free(openingd);
	return 0;
}

bool peer_start_openingd(struct peer *peer, struct peer_fd *peer_fd)
{
	int hsmfd;
	u32 max_to_self_delay;
	struct amount_msat min_effective_htlc_capacity;
	struct uncommitted_channel *uc;
	const u8 *msg;
	u32 minrate, maxrate;

	assert(peer->uncommitted_channel);
	uc = peer->uncommitted_channel;
	assert(!uc->open_daemon);

	hsmfd = hsm_get_client_fd(peer->ld, &uc->peer->id, uc->dbid,
				  HSM_PERM_COMMITMENT_POINT
				  | HSM_PERM_SIGN_REMOTE_TX);

	if (hsmfd < 0) {
		uncommitted_channel_disconnect(uc, LOG_BROKEN,
					       tal_fmt(tmpctx,
						       "Getting hsmfd for lightning_openingd: %s",
						       strerror(errno)));
		tal_free(uc);
		return false;
	}

	uc->open_daemon = new_channel_subd(peer, peer->ld,
					"lightning_openingd",
					uc, &peer->id, uc->log,
					true, openingd_wire_name,
					openingd_msg,
					opend_channel_errmsg,
					opend_channel_set_billboard,
					take(&peer_fd->fd),
					take(&hsmfd), NULL);
	if (!uc->open_daemon) {
		uncommitted_channel_disconnect(uc, LOG_BROKEN,
					       tal_fmt(tmpctx,
						       "Running lightning_openingd: %s",
						       strerror(errno)));
		tal_free(uc);
		return false;
	}

	channel_config(peer->ld, &uc->our_config,
		       &max_to_self_delay,
		       &min_effective_htlc_capacity);

	if (peer->ld->config.ignore_fee_limits) {
		minrate = 1;
		maxrate = 0xFFFFFFFF;
	} else {
		minrate = feerate_min(peer->ld, NULL);
		maxrate = feerate_max(peer->ld, NULL);
	}

	msg = towire_openingd_init(NULL,
				   chainparams,
				   peer->ld->our_features,
				   peer->their_features,
				   &uc->our_config,
				   max_to_self_delay,
				   min_effective_htlc_capacity,
				   &uc->local_basepoints,
				   &uc->local_funding_pubkey,
				   uc->minimum_depth,
				   minrate, maxrate,
				   peer->ld->dev_force_tmp_channel_id,
				   peer->ld->config.allowdustreserve,
				   peer->ld->dev_any_channel_type);
	subd_send_msg(uc->open_daemon, take(msg));
	return true;
}

static struct command_result *json_fundchannel_complete(struct command *cmd,
							const char *buffer,
							const jsmntok_t *obj UNNEEDED,
							const jsmntok_t *params)
{
	u8 *msg;
	struct node_id *id;
	struct bitcoin_txid *funding_txid;
	struct peer *peer;
	struct wally_psbt *funding_psbt;
	u32 *funding_txout_num = NULL;
	struct funding_channel *fc;

	if (!param_check(cmd, buffer, params,
			 p_req("id", param_node_id, &id),
			 p_req("psbt", param_psbt, &funding_psbt),
			 NULL))
		return command_param_failed();

	peer = peer_by_id(cmd->ld, id);
	if (!peer) {
		return command_fail(cmd, FUNDING_UNKNOWN_PEER, "Unknown peer");
	}

	if (peer->connected != PEER_CONNECTED)
		return command_fail(cmd, FUNDING_PEER_NOT_CONNECTED,
				    "Peer %s",
				    peer->connected == PEER_DISCONNECTED
				    ? "not connected" : "still connecting");

	if (!peer->uncommitted_channel
	    || !peer->uncommitted_channel->fc
	    || !peer->uncommitted_channel->fc->inflight)
		return command_fail(cmd, LIGHTNINGD, "No channel funding in progress.");

	if (peer->uncommitted_channel->fc->cmd)
		return command_fail(cmd, LIGHTNINGD, "Channel funding in progress.");

	fc = peer->uncommitted_channel->fc;

	/* We only deal with V2 internally */
	if (!psbt_set_version(funding_psbt, 2)) {
		return command_fail(cmd, LIGHTNINGD, "Could not set PSBT version.");
	}

	/* Figure out the correct output, and perform sanity checks. */
	for (size_t i = 0; i < funding_psbt->num_outputs; i++) {
		if (memeq(funding_psbt->outputs[i].script,
			  funding_psbt->outputs[i].script_len,
			  fc->funding_scriptpubkey,
			  tal_bytelen(fc->funding_scriptpubkey))) {
			if (funding_txout_num)
				return command_fail(cmd, FUNDING_PSBT_INVALID,
						    "Two outputs to open channel");
			funding_txout_num = tal(cmd, u32);
			*funding_txout_num = i;
		}
	}
	if (!funding_txout_num)
		return command_fail(cmd, FUNDING_PSBT_INVALID,
				    "No output to open channel");

	/* Can't really check amounts for elements. */
	if (!chainparams->is_elements
	    && !amount_sat_eq(amount_sat(funding_psbt->outputs
					 [*funding_txout_num].amount),
			      fc->funding_sats))
		return command_fail(cmd, FUNDING_PSBT_INVALID,
				    "Output to open channel is %"PRIu64"sat,"
				    " should be %s",
				    funding_psbt->outputs
				    [*funding_txout_num].amount,
				    fmt_amount_sat(tmpctx, fc->funding_sats));

	funding_txid = tal(cmd, struct bitcoin_txid);
	psbt_txid(NULL, funding_psbt, funding_txid, NULL);

	/* Fun fact: our wire protocol only allows 16 bits for outnum.
	 * That is reflected in our encoding scheme for short_channel_id. */
	if (*funding_txout_num > UINT16_MAX)
		return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
				    "Invalid parameter: funding tx vout too large %u",
				    *funding_txout_num);

	if (command_check_only(cmd))
		return command_check_done(cmd);

	/* Set the cmd to this new cmd */
	peer->uncommitted_channel->fc->cmd = cmd;
	msg = towire_openingd_funder_complete(NULL,
					      funding_txid,
					      *funding_txout_num,
					      peer->uncommitted_channel->fc->channel_type);
	subd_send_msg(peer->uncommitted_channel->open_daemon, take(msg));
	return command_still_pending(cmd);
}

/**
 * json_fundchannel_cancel - Entrypoint for cancelling a channel which funding isn't broadcast
 */
static struct command_result *json_fundchannel_cancel(struct command *cmd,
						      const char *buffer,
						      const jsmntok_t *obj UNNEEDED,
						      const jsmntok_t *params)
{

	struct node_id *id;
	struct peer *peer;
	u8 *msg;

	if (!param_check(cmd, buffer, params,
			 p_req("id", param_node_id, &id),
			 NULL))
		return command_param_failed();

	peer = peer_by_id(cmd->ld, id);
	if (!peer) {
		return command_fail(cmd, FUNDING_UNKNOWN_PEER, "Unknown peer");
	}

	if (peer->uncommitted_channel) {
		if (!peer->uncommitted_channel->fc || !peer->uncommitted_channel->fc->inflight)
			return command_fail(cmd, FUNDING_NOTHING_TO_CANCEL,
					    "No channel funding in progress.");

		if (command_check_only(cmd))
			return command_check_done(cmd);

		/* Make sure this gets notified if we succeed or cancel */
		tal_arr_expand(&peer->uncommitted_channel->fc->cancels, cmd);
		msg = towire_openingd_funder_cancel(NULL);
		subd_send_msg(peer->uncommitted_channel->open_daemon, take(msg));
		return command_still_pending(cmd);
	}

	if (command_check_only(cmd))
		return command_check_done(cmd);

	log_debug(cmd->ld->log, "fundchannel_cancel no uncommitted_channel!");

	/* Handle `fundchannel_cancel` after `fundchannel_complete`.  */
	return cancel_channel_before_broadcast(cmd, peer);
}

static struct command_result *fundchannel_start(struct command *cmd,
						struct peer *peer,
						struct funding_channel *fc STEALS,
						const struct channel_id *tmp_channel_id,
						u32 mindepth,
						struct amount_sat *reserve STEALS)
{
	int fds[2];

	/* Re-check in case it's changed */
	if (!peer->uncommitted_channel) {
		log_debug(cmd->ld->log, "fundchannel_start: allocating uncommitted_channel");
		peer->uncommitted_channel = new_uncommitted_channel(peer);
	} else
		log_debug(cmd->ld->log, "fundchannel_start: reusing uncommitted_channel");

	if (peer->uncommitted_channel->fc) {
		return command_fail(cmd, LIGHTNINGD, "Already funding channel");
	}

	if (peer->uncommitted_channel->got_offer) {
		return command_fail(cmd, LIGHTNINGD,
				    "Have in-progress "
				    "`open_channel` from "
				    "peer");
	}

	peer->uncommitted_channel->cid = *tmp_channel_id;

	peer->uncommitted_channel->fc = tal_steal(peer->uncommitted_channel, fc);
	fc->uc = peer->uncommitted_channel;

	fc->uc->minimum_depth = mindepth;

	fc->uc->reserve = tal_steal(fc->uc, reserve);

	if (socketpair(AF_LOCAL, SOCK_STREAM, 0, fds) != 0) {
		return command_fail(cmd, FUND_MAX_EXCEEDED,
				    "Failed to create socketpair: %s",
				    strerror(errno));
	}
	if (!peer_start_openingd(peer, new_peer_fd(cmd, fds[0]))) {
		close(fds[1]);
		/* FIXME: gets completed by failure path above! */
		return command_its_complicated("completed by peer_start_openingd");
	}

	/* Tell it to start funding */
	subd_send_msg(peer->uncommitted_channel->open_daemon, fc->open_msg);

	/* Tell connectd connect this to this channel id. */
	subd_send_msg(peer->ld->connectd,
		      take(towire_connectd_peer_connect_subd(NULL,
							     &peer->id,
							     peer->connectd_counter,
							     &peer->uncommitted_channel->cid)));
	subd_send_fd(peer->ld->connectd, fds[1]);
	return command_still_pending(cmd);
}

struct fundchannel_start_info {
	struct command *cmd;
	struct node_id id;
	struct funding_channel *fc;
	struct channel_id tmp_channel_id;
	struct amount_sat *reserve;
	u32 mindepth;
};

static void fundchannel_start_after_sync(struct chain_topology *topo,
					 struct fundchannel_start_info *info)
{
	struct peer *peer;

	/* Look up peer again in case it's gone! */
	peer = peer_by_id(info->cmd->ld, &info->id);
	if (!peer) {
		was_pending(command_fail(info->cmd, FUNDING_UNKNOWN_PEER, "Unknown peer"));
		return;
	}

	if (peer->connected != PEER_CONNECTED)
		was_pending(command_fail(info->cmd, FUNDING_PEER_NOT_CONNECTED,
					 "Peer %s",
					 peer->connected == PEER_DISCONNECTED
					 ? "not connected" : "still connecting"));
	fundchannel_start(info->cmd, peer, info->fc,
			  &info->tmp_channel_id, info->mindepth, info->reserve);
}

/**
 * json_fundchannel_start - Entrypoint for funding a channel
 */
static struct command_result *json_fundchannel_start(struct command *cmd,
						     const char *buffer,
						     const jsmntok_t *obj UNNEEDED,
						     const jsmntok_t *params)
{
	struct funding_channel * fc = tal(cmd, struct funding_channel);
	struct node_id *id;
	struct peer *peer;
	bool *announce_channel;
	u32 *feerate_non_anchor, feerate_anchor, *mindepth;
	struct amount_sat *amount, *reserve;
	struct amount_msat *push_msat;
	u32 *upfront_shutdown_script_wallet_index;
	struct channel_id tmp_channel_id;
	struct channel_type *ctype;

	fc->cmd = cmd;
	fc->cancels = tal_arr(fc, struct command *, 0);
	fc->uc = NULL;
	fc->inflight = false;
	fc->funding_scriptpubkey = NULL;

	if (!param_check(fc->cmd, buffer, params,
			 p_req("id", param_node_id, &id),
			 p_req("amount", param_sat, &amount),
			 p_opt("feerate", param_feerate, &feerate_non_anchor),
			 p_opt_def("announce", param_bool, &announce_channel, true),
			 p_opt("close_to", param_bitcoin_address, &fc->our_upfront_shutdown_script),
			 p_opt("push_msat", param_msat, &push_msat),
			 p_opt("mindepth", param_u32, &mindepth),
			 p_opt("reserve", param_sat, &reserve),
			 p_opt("channel_type", param_channel_type, &ctype),
			 NULL))
		return command_param_failed();

	if (ctype) {
		fc->channel_type = tal_steal(fc, ctype);
		if (!cmd->ld->dev_any_channel_type &&
		    !channel_type_accept(tmpctx,
					 ctype->features,
					 cmd->ld->our_features)) {
			return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
					    "channel_type not supported");
		}
		/* BOLT #2:
		 *
		 * The sender:
		 *   - if `channel_type` includes `option_zeroconf`:
		 *      - MUST set `minimum_depth` to zero.
		 *   - otherwise:
		 *     - SHOULD set `minimum_depth` to a number of blocks it
		 *       considers reasonable to avoid double-spending of the
		 *       funding transaction.
		 */
		if (channel_type_has(ctype, OPT_ZEROCONF)) {
			if (mindepth && *mindepth != 0) {
				return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
						    "Cannot set non-zero mindepth for zero-conf channel_type");
			}
			if (!mindepth) {
				mindepth = tal(cmd, u32);
				*mindepth = 0;
			}
		}
	} else {
		fc->channel_type = NULL;
	}

	if (!mindepth)
		mindepth = tal_dup(cmd, u32, &cmd->ld->config.anchor_confirms);

	if (push_msat && amount_msat_greater_sat(*push_msat, *amount))
		return command_fail(cmd, FUND_CANNOT_AFFORD,
				    "Requested to push_msat of %s is greater than "
				    "available funding amount %s",
				    fmt_amount_msat(tmpctx, *push_msat),
				    fmt_amount_sat(tmpctx, *amount));

	fc->funding_sats = *amount;
	if (!feerate_non_anchor) {
		/* For non-anchors, we default to a low feerate for first
		 * commitment, and update it almost immediately.  That saves
		 * money in the immediate-close case, which is probably soon
		 * and thus current feerates are sufficient. */
		feerate_non_anchor = tal(cmd, u32);
		*feerate_non_anchor = opening_feerate(cmd->ld->topology);
		if (!*feerate_non_anchor) {
			return command_fail(cmd, LIGHTNINGD,
					    "Cannot estimate fees");
		}
	}

	feerate_anchor = unilateral_feerate(cmd->ld->topology, true);
	/* Only complain here if we could possibly open one! */
	if (!feerate_anchor
	    && feature_offered(cmd->ld->our_features->bits[INIT_FEATURE],
			       OPT_ANCHORS_ZERO_FEE_HTLC_TX)) {
		return command_fail(cmd, LIGHTNINGD,
				    "Cannot estimate fees");
	}

	if (*feerate_non_anchor < get_feerate_floor(cmd->ld->topology)) {
		return command_fail(cmd, LIGHTNINGD,
				    "Feerate for non-anchor (%u perkw) below feerate floor %u perkw",
				    *feerate_non_anchor, get_feerate_floor(cmd->ld->topology));
	}

	peer = peer_by_id(cmd->ld, id);
	if (!peer) {
		return command_fail(cmd, FUNDING_UNKNOWN_PEER, "Unknown peer");
	}

	if (peer->connected != PEER_CONNECTED)
		return command_fail(cmd, FUNDING_PEER_NOT_CONNECTED,
				    "Peer %s",
				    peer->connected == PEER_DISCONNECTED
				    ? "not connected" : "still connecting");

	/* BOLT #2:
	 *  - if both nodes advertised `option_support_large_channel`:
	 *    - MAY set `funding_satoshis` greater than or equal to 2^24 satoshi.
	 *  - otherwise:
	 *    - MUST set `funding_satoshis` to less than 2^24 satoshi.
	 */
	if (!feature_negotiated(cmd->ld->our_features,
				peer->their_features, OPT_LARGE_CHANNELS)
	    && amount_sat_greater(*amount, chainparams->max_funding))
		return command_fail(cmd, FUND_MAX_EXCEEDED,
				    "Amount exceeded %s",
				    fmt_amount_sat(tmpctx,
						   chainparams->max_funding));

	if (feature_negotiated(cmd->ld->our_features,
			       peer->their_features,
			       OPT_DUAL_FUND))
		return command_fail(cmd, FUNDING_STATE_INVALID,
				    "Peer negotiated"
				    " `option_dual_fund`,"
				    " must use `openchannel_init` not"
				    " `fundchannel_start`.");

	if (peer->uncommitted_channel) {
		if (peer->uncommitted_channel->fc) {
			return command_fail(cmd, LIGHTNINGD, "Already funding channel");
		}

		if (peer->uncommitted_channel->got_offer) {
			return command_fail(cmd, LIGHTNINGD,
					    "Have in-progress "
					    "`open_channel` from "
					    "peer");
		}
	}

	if (command_check_only(cmd))
		return command_check_done(cmd);

	fc->push = push_msat ? *push_msat : AMOUNT_MSAT(0);
	fc->channel_flags = OUR_CHANNEL_FLAGS;
	if (!*announce_channel) {
		fc->channel_flags &= ~CHANNEL_FLAGS_ANNOUNCE_CHANNEL;
		log_info(peer->ld->log, "Will open private channel with node %s",
			fmt_node_id(fc, id));
	}

	/* Needs to be stolen away from cmd */
	if (fc->our_upfront_shutdown_script)
		fc->our_upfront_shutdown_script
			= tal_steal(fc, fc->our_upfront_shutdown_script);

	/* Determine the wallet index for our_upfront_shutdown_script,
	 * NULL if not found. */
	u32 found_wallet_index;
	if (wallet_can_spend(fc->cmd->ld->wallet,
			     fc->our_upfront_shutdown_script,
			     &found_wallet_index)) {
		upfront_shutdown_script_wallet_index = tal(tmpctx, u32);
		*upfront_shutdown_script_wallet_index = found_wallet_index;
	} else
		upfront_shutdown_script_wallet_index = NULL;

	temporary_channel_id(&tmp_channel_id);
	fc->open_msg = towire_openingd_funder_start(
			fc,
			*amount,
			fc->push,
			fc->our_upfront_shutdown_script,
			upfront_shutdown_script_wallet_index,
			*feerate_non_anchor,
			feerate_anchor,
			&tmp_channel_id,
			fc->channel_flags,
			reserve,
			ctype);

	if (!topology_synced(cmd->ld->topology)) {
		struct fundchannel_start_info *info
			= tal(cmd, struct fundchannel_start_info);

		json_notify_fmt(cmd, LOG_UNUSUAL,
				"Waiting to sync with bitcoind network (block %u of %u)",
				get_block_height(cmd->ld->topology),
				get_network_blockheight(cmd->ld->topology));

		info->cmd = cmd;
		info->fc = fc;
		info->id = *id;
		info->tmp_channel_id = tmp_channel_id;
		info->reserve = reserve;
		info->mindepth = *mindepth;
		topology_add_sync_waiter(cmd, cmd->ld->topology,
					 fundchannel_start_after_sync,
					 info);
		return command_still_pending(cmd);
	}

	return fundchannel_start(cmd, peer, fc,
				 &tmp_channel_id, *mindepth, reserve);
}

static struct channel *stub_chan(struct command *cmd,
				 u64 id,
				 struct node_id nodeid,
				 struct channel_id cid,
				 struct bitcoin_outpoint funding,
				 struct wireaddr addr,
				 struct amount_sat funding_sats,
				 struct channel_type *type)
{
	struct basepoints basepoints;
	struct bitcoin_signature *sig;
	struct channel *channel;
	struct channel_config *our_config;
	struct channel_config *their_config;
	struct channel_info *channel_info;
	struct lightningd *ld;
	struct peer *peer;
	struct pubkey localFundingPubkey;
	struct pubkey pk;
	struct short_channel_id *scid;
	u32 blockht;
	u32 feerate;
	u8 *dummy_sig = tal_hexdata(cmd,
				    "30450221009b2e0eef267b94c3899fb0dc73750"
				    "12e2cee4c10348a068fe78d1b82b4b1403602207"
				    "7c3fad3adac2ddf33f415e45f0daf6658b7a0b09"
				    "647de4443938ae2dbafe2b9" "01",
				    144);

	/* If the channel is already stored, return NULL. */
	if (channel_exists_by_id(cmd->ld->wallet, id)) {
		log_debug(cmd->ld->log, "channel %s already exists!",
				fmt_channel_id(tmpctx, &cid));
		return NULL;
	} else {
		struct wireaddr_internal wint;

		wint.itype = ADDR_INTERNAL_WIREADDR;
		wint.u.wireaddr.is_websocket = false;
		wint.u.wireaddr.wireaddr = addr;
		peer = new_peer(cmd->ld,
				0,
				&nodeid,
				&wint,
				NULL,
				false);
	}

	ld = cmd->ld;
	feerate = FEERATE_FLOOR;

	sig = tal(cmd, struct bitcoin_signature);
	signature_from_der(dummy_sig,
			   tal_bytelen(dummy_sig)
			   ,sig);

	if (!pubkey_from_der(tal_hexdata(cmd,
					 fmt_node_id(tmpctx, &nodeid),
					 66),
					 33,
					 &pk))
	{
		fatal("Invalid node id!");
	}

	get_channel_basepoints(ld,
			       &nodeid,
			       id,
			       &basepoints,
			       &localFundingPubkey);

	channel_info = tal(cmd,
			   struct channel_info);

	our_config = tal(cmd, struct channel_config);
	their_config = tal(cmd, struct channel_config);

	/* FIXME: Makeake these a pointer, so they could be NULL */
	memset(our_config, 0, sizeof(struct channel_config));
	memset(their_config, 0, sizeof(struct channel_config));
	channel_info->their_config = *their_config;
	channel_info->theirbase = basepoints;
	channel_info->remote_fundingkey = pk;
	channel_info->remote_per_commit = pk;
	channel_info->old_remote_per_commit = pk;

	blockht = 100;
	scid = tal(cmd, struct short_channel_id);

	/*To indicate this is an stub channel we keep it's scid to 1x1x1.*/
	if (!mk_short_channel_id(scid, 1, 1, 1))
                fatal("Failed to make short channel 1x1x1!");

	/* Channel Shell with Dummy data(mostly) */
	channel = new_channel(peer, id,
			      NULL, /* No shachain yet */
			      CHANNELD_NORMAL,
			      LOCAL,
			      NULL,
			      "restored from static channel backup",
			      0, false, false,
			      our_config,
			      0,
			      1, 1, 1,
			      &funding,
			      funding_sats,
			      AMOUNT_MSAT(0),
			      AMOUNT_SAT(0),
			      true, /* remote_channel_ready */
			      scid,
			      scid,
			      scid,
			      &cid,
			      /* The three arguments below are msatoshi_to_us,
			       * msatoshi_to_us_min, and msatoshi_to_us_max.
			       * Because, this is a newly-funded channel,
			       * all three are same value. */
			      AMOUNT_MSAT(0),
			      AMOUNT_MSAT(0), /* msat_to_us_min */
			      AMOUNT_MSAT(0), /* msat_to_us_max */
			      NULL,
			      sig,
			      NULL, /* No HTLC sigs */
			      channel_info,
			      new_fee_states(cmd, LOCAL, &feerate),
			      NULL, /* No shutdown_scriptpubkey[REMOTE] */
			      NULL,
			      1, false,
			      NULL, /* No commit sent */
			      /* If we're fundee, could be a little before this
			       * in theory, but it's only used for timing out. */
			      get_network_blockheight(ld->topology),
                              FEERATE_FLOOR,
                              funding_sats.satoshis / MINIMUM_TX_WEIGHT * 1000 /* Raw: convert to feerate */,
			      &basepoints,
			      &localFundingPubkey,
			      false,
			      ld->config.fee_base,
			      ld->config.fee_per_satoshi,
			      NULL,
			      0, 0,
			      type,
			      NUM_SIDES, /* closer not yet known */
			      REASON_REMOTE,
			      NULL,
			      take(new_height_states(ld->wallet, LOCAL,
						    &blockht)),
			      0, NULL, 0, 0, /* No leases on v1s */
			      ld->config.htlc_minimum_msat,
			      ld->config.htlc_maximum_msat,
			      false,
			      NULL,
			      0);

	/* We don't want to gossip about this, ever. */
	channel->channel_gossip = tal_free(channel->channel_gossip);

	return channel;
}

static struct command_result *json_recoverchannel(struct command *cmd,
						const char *buffer,
						const jsmntok_t *obj UNNEEDED,
						const jsmntok_t *params)
{
	const jsmntok_t *scb, *t;
	size_t i;
	struct json_stream *response;
	struct scb_chan *scb_chan = tal(cmd, struct scb_chan);

	if (!param(cmd, buffer, params,
		p_req("scb", param_array, &scb),
		NULL))
		return command_param_failed();

	response = json_stream_success(cmd);

	json_array_start(response, "stubs");
	json_for_each_arr(i,t,scb){

		char *token = json_strdup(tmpctx, buffer, t);
		const u8 *scb_arr = tal_hexdata(cmd, token, strlen(token));
		size_t scblen = tal_count(scb_arr);

		scb_chan = fromwire_scb_chan(cmd ,&scb_arr, &scblen);

		if (scb_chan == NULL) {
			log_broken(cmd->ld->log, "SCB is invalid!");
			continue;
		}

		struct lightningd *ld = cmd->ld;
		struct channel *channel= stub_chan(cmd,
						   scb_chan->id,
						   scb_chan->node_id,
						   scb_chan->cid,
						   scb_chan->funding,
						   scb_chan->addr,
						   scb_chan->funding_sats,
						   scb_chan->type);

		/* Returns NULL only when channel already exists, so we skip over it. */
		if (channel == NULL)
			continue;

		/* Now we put this in the database. */
		wallet_channel_insert(ld->wallet, channel);

		/* Watch the Funding */
		channel_watch_funding(ld, channel);

		json_add_channel_id(response, NULL, &scb_chan->cid);
	}

	/* This will try to reconnect to the peers and start
	* initiating the process */
	setup_peers(cmd->ld);

	json_array_end(response);

	return command_success(cmd, response);
}

static const struct json_command fundchannel_start_command = {
    "fundchannel_start",
    "channels",
    json_fundchannel_start,
    "Start fund channel with {id} using {amount} satoshis. "
    "Returns a bech32 address to use as an output for a funding transaction."
};
AUTODATA(json_command, &fundchannel_start_command);

static const struct json_command fundchannel_cancel_command = {
    "fundchannel_cancel",
    "channels",
    json_fundchannel_cancel,
    "Cancel inflight channel establishment with peer {id}."
};
AUTODATA(json_command, &fundchannel_cancel_command);

static const struct json_command fundchannel_complete_command = {
    "fundchannel_complete",
    "channels",
    json_fundchannel_complete,
    "Complete channel establishment with peer {id} for funding transaction"
    "with {psbt}. Returns true on success, false otherwise."
};
AUTODATA(json_command, &fundchannel_complete_command);

static const struct json_command json_commitchan_command = {
        "recoverchannel",
        "channels",
        json_recoverchannel,
        "Populate the DB with a channel and peer"
        "Used for recovering the channel using DLP."
        "This needs param in the form of an array [scb1,scb2,...]"
};
AUTODATA(json_command, &json_commitchan_command);
