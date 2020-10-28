#include "bitcoin/feerate.h"
#include <bitcoin/privkey.h>
#include <bitcoin/script.h>
#include <ccan/tal/str/str.h>
#include <common/addr.h>
#include <common/channel_config.h>
#include <common/features.h>
#include <common/fee_states.h>
#include <common/json_helpers.h>
#include <common/jsonrpc_errors.h>
#include <common/key_derive.h>
#include <common/param.h>
#include <common/penalty_base.h>
#include <common/per_peer_state.h>
#include <common/utils.h>
#include <common/wire_error.h>
#include <connectd/connectd_wiregen.h>
#include <errno.h>
#include <lightningd/chaintopology.h>
#include <lightningd/channel_control.h>
#include <lightningd/closing_control.h>
#include <lightningd/hsm_control.h>
#include <lightningd/json.h>
#include <lightningd/jsonrpc.h>
#include <lightningd/lightningd.h>
#include <lightningd/notification.h>
#include <lightningd/opening_common.h>
#include <lightningd/opening_control.h>
#include <lightningd/options.h>
#include <lightningd/plugin_hook.h>
#include <lightningd/subd.h>
#include <openingd/openingd_wiregen.h>
#include <string.h>
#include <wire/common_wiregen.h>
#include <wire/wire.h>
#include <wire/wire_sync.h>

void json_add_uncommitted_channel(struct json_stream *response,
				  const struct uncommitted_channel *uc)
{
	struct amount_msat total, ours;
	if (!uc)
		return;

	/* If we're chatting but no channel, that's shown by connected: True */
	if (!uc->fc)
		return;

	json_object_start(response, NULL);
	json_add_string(response, "state", "OPENINGD");
	json_add_string(response, "owner", "lightning_openingd");
	json_add_string(response, "funding", "LOCAL");
	if (uc->transient_billboard) {
		json_array_start(response, "status");
		json_add_string(response, NULL, uc->transient_billboard);
		json_array_end(response);
	}

	/* These should never fail. */
	if (amount_sat_to_msat(&total, uc->fc->funding)
	    && amount_msat_sub(&ours, total, uc->fc->push)) {
		json_add_amount_msat_compat(response, ours,
					    "msatoshi_to_us", "to_us_msat");
		json_add_amount_msat_compat(response, total,
					    "msatoshi_total", "total_msat");
	}

	json_array_start(response, "features");
	if (feature_negotiated(uc->peer->ld->our_features,
			       uc->peer->their_features,
			       OPT_STATIC_REMOTEKEY))
		json_add_string(response, NULL, "option_static_remotekey");

	if (feature_negotiated(uc->peer->ld->our_features,
			       uc->peer->their_features,
			       OPT_ANCHOR_OUTPUTS))
		json_add_string(response, NULL, "option_anchor_outputs");
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
		      const struct bitcoin_txid *funding_txid,
		      u16 funding_outnum,
		      struct amount_sat funding,
		      struct amount_msat push,
		      u8 channel_flags,
		      struct channel_info *channel_info,
		      u32 feerate,
		      const u8 *our_upfront_shutdown_script,
		      const u8 *remote_upfront_shutdown_script)
{
	struct channel *channel;
	struct amount_msat our_msat;
	struct amount_sat local_funding;
	s64 final_key_idx;
	bool option_static_remotekey;
	bool option_anchor_outputs;

	/* Get a key to use for closing outputs from this tx */
	final_key_idx = wallet_get_newindex(ld);
	if (final_key_idx == -1) {
		log_broken(uc->log, "Can't get final key index");
		return NULL;
	}

	if (uc->fc) {
		if (!amount_sat_sub_msat(&our_msat, funding, push)) {
			log_broken(uc->log, "push %s exceeds funding %s",
				   type_to_string(tmpctx, struct amount_msat,
						  &push),
				   type_to_string(tmpctx, struct amount_sat,
						  &funding));
			return NULL;
		}
		local_funding = funding;
	} else {
		our_msat = push;
		local_funding = AMOUNT_SAT(0);
	}

	/* old_remote_per_commit not valid yet, copy valid one. */
	channel_info->old_remote_per_commit = channel_info->remote_per_commit;

	/* BOLT-a12da24dd0102c170365124782b46d9710950ac1 #2:
	 * 1. type: 35 (`funding_signed`)
	 * 2. data:
	 *     * [`channel_id`:`channel_id`]
	 *     * [`signature`:`signature`]
	 *
	 * #### Requirements
	 *
	 * Both peers:
	 *   - if `option_static_remotekey` or `option_anchor_outputs` was negotiated:
	 *     - `option_static_remotekey` or `option_anchor_outputs` applies to all commitment
	 *       transactions
	 *   - otherwise:
	 *     - `option_static_remotekey` or `option_anchor_outputs` does not apply to any commitment
	 *        transactions
	 */
	/* i.e. We set it now for the channel permanently. */
	option_static_remotekey
		= feature_negotiated(ld->our_features,
				     uc->peer->their_features,
				     OPT_STATIC_REMOTEKEY);
	option_anchor_outputs
		= feature_negotiated(ld->our_features,
				     uc->peer->their_features,
				     OPT_ANCHOR_OUTPUTS);

	channel = new_channel(uc->peer, uc->dbid,
			      NULL, /* No shachain yet */
			      CHANNELD_AWAITING_LOCKIN,
			      uc->fc ? LOCAL : REMOTE,
			      uc->log,
			      take(uc->transient_billboard),
			      channel_flags,
			      &uc->our_config,
			      uc->minimum_depth,
			      1, 1, 0,
			      funding_txid,
			      funding_outnum,
			      funding,
			      push,
			      local_funding,
			      false, /* !remote_funding_locked */
			      NULL, /* no scid yet */
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
			      /* We are connected */
			      true,
			      &uc->local_basepoints,
			      &uc->local_funding_pubkey,
			      NULL,
			      ld->config.fee_base,
			      ld->config.fee_per_satoshi,
			      remote_upfront_shutdown_script,
			      option_static_remotekey,
			      option_anchor_outputs,
			      NULL,
			      NUM_SIDES, /* closer not yet known */
			      uc->fc ? REASON_USER : REASON_REMOTE);

	/* Now we finally put it in the database. */
	wallet_channel_insert(ld->wallet, channel);

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
			type_to_string(tmpctx, struct channel_id,
				       &channel->cid));
	json_add_bool(response, "commitments_secured", true);
	was_pending(command_success(cmd, response));
}

static void funding_started_success(struct funding_channel *fc,
				    u8 *scriptPubkey,
				    bool supports_shutdown)
{
	struct json_stream *response;
	struct command *cmd = fc->cmd;
	char *out;

	response = json_stream_success(cmd);
	out = encode_scriptpubkey_to_addr(cmd,
				          chainparams,
					  scriptPubkey);
	if (out) {
		json_add_string(response, "funding_address", out);
		json_add_hex_talarr(response, "scriptpubkey", scriptPubkey);
		if (fc->our_upfront_shutdown_script)
			json_add_hex_talarr(response, "close_to", fc->our_upfront_shutdown_script);
	}

	/* Clear this so cancel doesn't think it's still in progress */
	fc->cmd = NULL;
	was_pending(command_success(cmd, response));
}

static void opening_funder_start_replied(struct subd *openingd, const u8 *resp,
					 const int *fds,
					 struct funding_channel *fc)
{
	u8 *funding_scriptPubkey;
	bool supports_shutdown_script;

	if (!fromwire_openingd_funder_start_reply(resp, resp,
						 &funding_scriptPubkey,
						 &supports_shutdown_script)) {
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

	funding_started_success(fc, funding_scriptPubkey, supports_shutdown_script);

	/* Mark that we're in-flight */
	fc->inflight = true;
	return;

failed:
	subd_release_channel(openingd, fc->uc);
	fc->uc->open_daemon = NULL;
	/* Frees fc too, and tmpctx */
	tal_free(fc->uc);
}

static void opening_funder_finished(struct subd *openingd, const u8 *resp,
				    const int *fds,
				    struct funding_channel *fc)
{
	struct channel_info channel_info;
	struct channel_id cid;
	struct bitcoin_txid funding_txid;
	u16 funding_txout;
	struct bitcoin_signature remote_commit_sig;
	struct bitcoin_tx *remote_commit;
	u32 feerate;
	struct channel *channel;
	struct lightningd *ld = openingd->ld;
	u8 *remote_upfront_shutdown_script;
	struct per_peer_state *pps;
	struct penalty_base *pbase;

	/* This is a new channel_info.their_config so set its ID to 0 */
	channel_info.their_config.id = 0;

	if (!fromwire_openingd_funder_reply(resp, resp,
					   &channel_info.their_config,
					   &remote_commit,
					   &pbase,
					   &remote_commit_sig,
					   &pps,
					   &channel_info.theirbase.revocation,
					   &channel_info.theirbase.payment,
					   &channel_info.theirbase.htlc,
					   &channel_info.theirbase.delayed_payment,
					   &channel_info.remote_per_commit,
					   &fc->uc->minimum_depth,
					   &channel_info.remote_fundingkey,
					   &funding_txid,
					   &funding_txout,
					   &feerate,
					   &fc->uc->our_config.channel_reserve,
					   &remote_upfront_shutdown_script)) {
		log_broken(fc->uc->log,
			   "bad OPENING_FUNDER_REPLY %s",
			   tal_hex(resp, resp));
		was_pending(command_fail(fc->cmd, LIGHTNINGD,
					 "bad OPENING_FUNDER_REPLY %s",
					 tal_hex(fc->cmd, resp)));
		goto cleanup;
	}
	remote_commit->chainparams = chainparams;
	per_peer_state_set_fds_arr(pps, fds);

	log_debug(ld->log,
		  "%s", type_to_string(tmpctx, struct pubkey,
				       &channel_info.remote_per_commit));

	/* Saved with channel to disk */
	derive_channel_id(&cid, &funding_txid, funding_txout);

	/* old_remote_per_commit not valid yet, copy valid one. */
	channel_info.old_remote_per_commit = channel_info.remote_per_commit;

	/* Steals fields from uc */
	channel = wallet_commit_channel(ld, fc->uc,
					&cid,
					remote_commit,
					&remote_commit_sig,
					&funding_txid,
					funding_txout,
					fc->funding,
					fc->push,
					fc->channel_flags,
					&channel_info,
					feerate,
					fc->our_upfront_shutdown_script,
					remote_upfront_shutdown_script);
	if (!channel) {
		was_pending(command_fail(fc->cmd, LIGHTNINGD,
					 "Key generation failure"));
		goto cleanup;
	}

	/* Watch for funding confirms */
	channel_watch_funding(ld, channel);

	if (pbase)
		wallet_penalty_base_add(ld->wallet, channel->dbid, pbase);

	funding_success(channel);
	peer_start_channeld(channel, pps, NULL, NULL, false);

cleanup:
	subd_release_channel(openingd, fc->uc);
	fc->uc->open_daemon = NULL;
	/* Frees fc too, and tmpctx */
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
	struct bitcoin_txid funding_txid;
	u16 funding_outnum;
	struct amount_sat funding;
	struct amount_msat push;
	u32 feerate;
	u8 channel_flags;
	struct channel *channel;
	u8 *remote_upfront_shutdown_script, *local_upfront_shutdown_script;
	struct per_peer_state *pps;
	struct penalty_base *pbase;

	log_debug(uc->log, "Got opening_fundee_finish_response");

	/* This is a new channel_info.their_config, set its ID to 0 */
	channel_info.their_config.id = 0;

	if (!fromwire_openingd_fundee(tmpctx, reply,
				     &channel_info.their_config,
				     &remote_commit,
				     &pbase,
				     &remote_commit_sig,
				     &pps,
				     &channel_info.theirbase.revocation,
				     &channel_info.theirbase.payment,
				     &channel_info.theirbase.htlc,
				     &channel_info.theirbase.delayed_payment,
				     &channel_info.remote_per_commit,
				     &channel_info.remote_fundingkey,
				     &funding_txid,
				     &funding_outnum,
				     &funding,
				     &push,
				     &channel_flags,
				     &feerate,
				     cast_const2(u8 **, &fwd_msg),
				     &uc->our_config.channel_reserve,
				     &local_upfront_shutdown_script,
				     &remote_upfront_shutdown_script)) {
		log_broken(uc->log, "bad OPENING_FUNDEE_REPLY %s",
			   tal_hex(reply, reply));
		uncommitted_channel_disconnect(uc, LOG_BROKEN,
					       "bad OPENING_FUNDEE_REPLY");
		goto failed;
	}

	remote_commit->chainparams = chainparams;
	per_peer_state_set_fds_arr(pps, fds);

	/* openingd should never accept them funding channel in this case. */
	if (peer_active_channel(uc->peer)) {
		uncommitted_channel_disconnect(uc,
					       LOG_BROKEN,
					       "already have active channel");
		goto failed;
	}

	derive_channel_id(&cid, &funding_txid, funding_outnum);

	/* old_remote_per_commit not valid yet, copy valid one. */
	channel_info.old_remote_per_commit = channel_info.remote_per_commit;

	/* Consumes uc */
	channel = wallet_commit_channel(ld, uc,
					&cid,
					remote_commit,
					&remote_commit_sig,
					&funding_txid,
					funding_outnum,
					funding,
					push,
					channel_flags,
					&channel_info,
					feerate,
					local_upfront_shutdown_script,
					remote_upfront_shutdown_script);
	if (!channel) {
		uncommitted_channel_disconnect(uc, LOG_BROKEN,
					       "Commit channel failed");
		goto failed;
	}

	log_debug(channel->log, "Watching funding tx %s",
		  type_to_string(reply, struct bitcoin_txid,
				 &channel->funding_txid));

	channel_watch_funding(ld, channel);

	/* Tell plugins about the success */
	notify_channel_opened(ld, &channel->peer->id, &channel->funding,
			      &channel->funding_txid, &channel->remote_funding_locked);

	if (pbase)
		wallet_penalty_base_add(ld->wallet, channel->dbid, pbase);

	/* On to normal operation! */
	peer_start_channeld(channel, pps, fwd_msg, NULL, false);

	subd_release_channel(openingd, uc);
	uc->open_daemon = NULL;
	tal_free(uc);
	return;

failed:
	close(fds[0]);
	close(fds[1]);
	close(fds[3]);
	tal_free(uc);
}

static void opening_funder_failed(struct subd *openingd, const u8 *msg,
				  struct uncommitted_channel *uc)
{
	char *desc;

	if (!fromwire_openingd_funder_failed(msg, msg, &desc)) {
		log_broken(uc->log,
			   "bad OPENING_FUNDER_FAILED %s",
			   tal_hex(tmpctx, msg));
		was_pending(command_fail(uc->fc->cmd, LIGHTNINGD,
					 "bad OPENING_FUNDER_FAILED %s",
					 tal_hex(uc->fc->cmd, msg)));
		tal_free(uc);
		return;
	}

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
	 * if they close. */
	uc->fc = tal_free(uc->fc);
}

struct openchannel_hook_payload {
	struct subd *openingd;
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

static void
openchannel_hook_serialize(struct openchannel_hook_payload *payload,
		       struct json_stream *stream)
{
	struct uncommitted_channel *uc = payload->openingd->channel;
	json_object_start(stream, "openchannel");
	json_add_node_id(stream, "id", &uc->peer->id);
	json_add_amount_sat_only(stream, "funding_satoshis",
				 payload->funding_satoshis);
	json_add_amount_msat_only(stream, "push_msat", payload->push_msat);
	json_add_amount_sat_only(stream, "dust_limit_satoshis",
				 payload->dust_limit_satoshis);
	json_add_amount_msat_only(stream, "max_htlc_value_in_flight_msat",
				  payload->max_htlc_value_in_flight_msat);
	json_add_amount_sat_only(stream, "channel_reserve_satoshis",
				 payload->channel_reserve_satoshis);
	json_add_amount_msat_only(stream, "htlc_minimum_msat",
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

	/* We want to free this, whatever happens. */
	tal_steal(tmpctx, payload);

	/* If openingd went away, don't send it anything! */
	if (!openingd)
		return;

	tal_del_destructor2(openingd, openchannel_payload_remove_openingd, payload);

	subd_send_msg(openingd,
		      take(towire_openingd_got_offer_reply(NULL, errmsg,
							  our_upfront_shutdown_script)));
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
			  "openchannel_hook rejects and says '%s'",
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
				   "openchannel_hook close_to address was"
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

	/* Tell them they can't open, if we already have open channel. */
	if (peer_active_channel(uc->peer)) {
		subd_send_msg(openingd,
			      take(towire_openingd_got_offer_reply(NULL,
					  "Already have active channel", NULL)));
		return;
	}

	payload = tal(openingd, struct openchannel_hook_payload);
	payload->openingd = openingd;
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
	plugin_hook_call_openchannel(openingd->ld, payload);
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
		if (tal_count(fds) != 3)
			return 3;
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
	case WIRE_OPENINGD_FUNDER_FAILED:
		if (!uc->fc) {
			log_unusual(openingd->log, "Unexpected FUNDER_FAILED %s",
				   tal_hex(tmpctx, msg));
			tal_free(openingd);
			return 0;
		}
		opening_funder_failed(openingd, msg, uc);
		return 0;

	case WIRE_OPENINGD_FUNDEE:
		if (tal_count(fds) != 3)
			return 3;
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

	switch ((enum common_wire)t) {
#if DEVELOPER
	case WIRE_CUSTOMMSG_IN:
		handle_custommsg_in(openingd->ld, openingd->node_id, msg);
		return 0;
#else
	case WIRE_CUSTOMMSG_IN:
#endif
	/* We send these. */
	case WIRE_CUSTOMMSG_OUT:
		break;
	}

	log_broken(openingd->log, "Unexpected msg %s: %s",
		   openingd_wire_name(t), tal_hex(tmpctx, msg));
	tal_free(openingd);
	return 0;
}

void peer_start_openingd(struct peer *peer,
			 struct per_peer_state *pps,
			 const u8 *send_msg)
{
	int hsmfd;
	u32 max_to_self_delay;
	struct amount_msat min_effective_htlc_capacity;
	struct uncommitted_channel *uc;
	const u8 *msg;

	assert(!peer->uncommitted_channel);

	uc = peer->uncommitted_channel = new_uncommitted_channel(peer);

	hsmfd = hsm_get_client_fd(peer->ld, &uc->peer->id, uc->dbid,
				  HSM_CAP_COMMITMENT_POINT
				  | HSM_CAP_SIGN_REMOTE_TX);

	uc->open_daemon = new_channel_subd(peer->ld,
					"lightning_openingd",
					uc, &peer->id, uc->log,
					true, openingd_wire_name,
					openingd_msg,
					opend_channel_errmsg,
					opend_channel_set_billboard,
					take(&pps->peer_fd),
					take(&pps->gossip_fd),
					take(&pps->gossip_store_fd),
					take(&hsmfd), NULL);
	if (!uc->open_daemon) {
		uncommitted_channel_disconnect(uc, LOG_BROKEN,
					       tal_fmt(tmpctx,
						       "Running lightning_openingd: %s",
						       strerror(errno)));
		tal_free(uc);
		return;
	}

	channel_config(peer->ld, &uc->our_config,
		       &max_to_self_delay,
		       &min_effective_htlc_capacity);

	/* BOLT #2:
	 *
	 * The sender:
	 *   - SHOULD set `minimum_depth` to a number of blocks it considers
	 *     reasonable to avoid double-spending of the funding transaction.
	 */
	uc->minimum_depth = peer->ld->config.anchor_confirms;

	msg = towire_openingd_init(NULL,
				  chainparams,
				  peer->ld->our_features,
				  &uc->our_config,
				  max_to_self_delay,
				  min_effective_htlc_capacity,
				  pps, &uc->local_basepoints,
				  &uc->local_funding_pubkey,
				  uc->minimum_depth,
				  feerate_min(peer->ld, NULL),
				  feerate_max(peer->ld, NULL),
				  peer->their_features,
				  feature_negotiated(peer->ld->our_features,
						     peer->their_features,
						     OPT_STATIC_REMOTEKEY),
				  feature_negotiated(peer->ld->our_features,
						     peer->their_features,
						     OPT_ANCHOR_OUTPUTS),
				  send_msg,
				  IFDEV(peer->ld->dev_force_tmp_channel_id, NULL),
				  IFDEV(peer->ld->dev_fast_gossip, false));
	subd_send_msg(uc->open_daemon, take(msg));
}

static struct command_result *json_fund_channel_complete(struct command *cmd,
							 const char *buffer,
							 const jsmntok_t *obj UNNEEDED,
							 const jsmntok_t *params)
{
	u8 *msg;
	struct node_id *id;
	struct bitcoin_txid *funding_txid;
	struct peer *peer;
	struct channel *channel;
	u32 *funding_txout_num;
	u16 funding_txout;

	if (!param(cmd, buffer, params,
		   p_req("id", param_node_id, &id),
		   p_req("txid", param_txid, &funding_txid),
		   p_req("txout", param_number, &funding_txout_num),
		   NULL))
		return command_param_failed();

	if (*funding_txout_num > UINT16_MAX)
		return command_fail(cmd, LIGHTNINGD,
				    "Invalid parameter: funding tx vout too large %u",
				    *funding_txout_num);

	funding_txout = *funding_txout_num;
	peer = peer_by_id(cmd->ld, id);
	if (!peer) {
		return command_fail(cmd, FUNDING_UNKNOWN_PEER, "Unknown peer");
	}

	channel = peer_active_channel(peer);
	if (channel)
		return command_fail(cmd, LIGHTNINGD, "Peer already %s",
				    channel_state_name(channel));

	if (!peer->uncommitted_channel)
		return command_fail(cmd, FUNDING_PEER_NOT_CONNECTED,
				    "Peer not connected");

	if (!peer->uncommitted_channel->fc || !peer->uncommitted_channel->fc->inflight)
		return command_fail(cmd, LIGHTNINGD, "No channel funding in progress.");
	if (peer->uncommitted_channel->fc->cmd)
		return command_fail(cmd, LIGHTNINGD, "Channel funding in progress.");

	/* Set the cmd to this new cmd */
	peer->uncommitted_channel->fc->cmd = cmd;
	msg = towire_openingd_funder_complete(NULL,
					     funding_txid,
					     funding_txout);
	subd_send_msg(peer->uncommitted_channel->open_daemon, take(msg));
	return command_still_pending(cmd);
}

/**
 * json_fund_channel_cancel - Entrypoint for cancelling a channel which funding isn't broadcast
 */
static struct command_result *json_fund_channel_cancel(struct command *cmd,
						       const char *buffer,
						       const jsmntok_t *obj UNNEEDED,
						       const jsmntok_t *params)
{

	struct node_id *id;
	struct peer *peer;
	u8 *msg;

	if (!param(cmd, buffer, params,
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

		/* Make sure this gets notified if we succeed or cancel */
		tal_arr_expand(&peer->uncommitted_channel->fc->cancels, cmd);
		msg = towire_openingd_funder_cancel(NULL);
		subd_send_msg(peer->uncommitted_channel->open_daemon, take(msg));
		return command_still_pending(cmd);
	}

	/* Handle `fundchannel_cancel` after `fundchannel_complete`.  */
	return cancel_channel_before_broadcast(cmd, peer);
}

/**
 * json_fund_channel_start - Entrypoint for funding a channel
 */
static struct command_result *json_fund_channel_start(struct command *cmd,
						      const char *buffer,
						      const jsmntok_t *obj UNNEEDED,
						      const jsmntok_t *params)
{
	struct funding_channel * fc = tal(cmd, struct funding_channel);
	struct node_id *id;
	struct peer *peer;
	struct channel *channel;
	bool *announce_channel;
	u32 *feerate_per_kw;

	u8 *msg = NULL;
	struct amount_sat *amount;
	struct amount_msat *push_msat;

	fc->cmd = cmd;
	fc->cancels = tal_arr(fc, struct command *, 0);
	fc->uc = NULL;
	fc->inflight = false;

	if (!param(fc->cmd, buffer, params,
		   p_req("id", param_node_id, &id),
		   p_req("amount", param_sat, &amount),
		   p_opt("feerate", param_feerate, &feerate_per_kw),
		   p_opt_def("announce", param_bool, &announce_channel, true),
		   p_opt("close_to", param_bitcoin_address, &fc->our_upfront_shutdown_script),
		   p_opt("push_msat", param_msat, &push_msat),
		   NULL))
		return command_param_failed();

	if (push_msat && amount_msat_greater_sat(*push_msat, *amount))
		return command_fail(cmd, FUND_CANNOT_AFFORD,
				    "Requested to push_msat of %s is greater than "
				    "available funding amount %s",
				    type_to_string(tmpctx, struct amount_msat, push_msat),
				    type_to_string(tmpctx, struct amount_sat, amount));

	fc->funding = *amount;
	if (!feerate_per_kw) {
		feerate_per_kw = tal(cmd, u32);
		*feerate_per_kw = opening_feerate(cmd->ld->topology);
		if (!*feerate_per_kw) {
			return command_fail(cmd, LIGHTNINGD,
					    "Cannot estimate fees");
		}
	}

	if (*feerate_per_kw < feerate_floor()) {
		return command_fail(cmd, LIGHTNINGD,
				    "Feerate below feerate floor");
	}

	if (!topology_synced(cmd->ld->topology)) {
		return command_fail(cmd, FUNDING_STILL_SYNCING_BITCOIN,
				    "Still syncing with bitcoin network");
	}

	peer = peer_by_id(cmd->ld, id);
	if (!peer) {
		return command_fail(cmd, FUNDING_UNKNOWN_PEER, "Unknown peer");
	}

	channel = peer_active_channel(peer);
	if (channel) {
		return command_fail(cmd, LIGHTNINGD, "Peer already %s",
				    channel_state_name(channel));
	}

	if (!peer->uncommitted_channel) {
		return command_fail(cmd, FUNDING_PEER_NOT_CONNECTED,
				    "Peer not connected");
	}

	if (peer->uncommitted_channel->fc) {
		return command_fail(cmd, LIGHTNINGD, "Already funding channel");
	}

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
				    type_to_string(tmpctx, struct amount_sat,
						   &chainparams->max_funding));

	fc->push = push_msat ? *push_msat : AMOUNT_MSAT(0);
	fc->channel_flags = OUR_CHANNEL_FLAGS;
	if (!*announce_channel) {
		fc->channel_flags &= ~CHANNEL_FLAGS_ANNOUNCE_CHANNEL;
		log_info(peer->ld->log, "Will open private channel with node %s",
			type_to_string(fc, struct node_id, id));
	}

	peer->uncommitted_channel->fc = tal_steal(peer->uncommitted_channel, fc);
	fc->uc = peer->uncommitted_channel;

	/* Needs to be stolen away from cmd */
	if (fc->our_upfront_shutdown_script)
		fc->our_upfront_shutdown_script
			= tal_steal(fc, fc->our_upfront_shutdown_script);

	msg = towire_openingd_funder_start(NULL,
					  *amount,
					  fc->push,
					  fc->our_upfront_shutdown_script,
					  *feerate_per_kw,
					  fc->channel_flags);

	subd_send_msg(peer->uncommitted_channel->open_daemon, take(msg));
	return command_still_pending(cmd);
}

static const struct json_command fund_channel_start_command = {
    "fundchannel_start",
    "channels",
    json_fund_channel_start,
    "Start fund channel with {id} using {amount} satoshis. "
    "Returns a bech32 address to use as an output for a funding transaction."
};
AUTODATA(json_command, &fund_channel_start_command);

static const struct json_command fund_channel_cancel_command = {
    "fundchannel_cancel",
    "channels",
    json_fund_channel_cancel,
    "Cancel inflight channel establishment with peer {id}."
};
AUTODATA(json_command, &fund_channel_cancel_command);

static const struct json_command fund_channel_complete_command = {
    "fundchannel_complete",
    "channels",
    json_fund_channel_complete,
    "Complete channel establishment with peer {id} for funding transaction"
    "with {txid}. Returns true on success, false otherwise."
};
AUTODATA(json_command, &fund_channel_complete_command);

struct subd *peer_get_owning_subd(struct peer *peer)
{
	struct channel *channel;
	channel = peer_active_channel(peer);

	if (channel != NULL) {
		return channel->owner;
	} else if (peer->uncommitted_channel != NULL) {
		return peer->uncommitted_channel->open_daemon;
	}
	return NULL;
}
