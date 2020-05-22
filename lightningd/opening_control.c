#include "bitcoin/feerate.h"
#include <bitcoin/privkey.h>
#include <bitcoin/script.h>
#include <ccan/tal/str/str.h>
#include <common/addr.h>
#include <common/channel_config.h>
#include <common/features.h>
#include <common/fee_states.h>
#include <common/funding_tx.h>
#include <common/json_command.h>
#include <common/json_helpers.h>
#include <common/jsonrpc_errors.h>
#include <common/key_derive.h>
#include <common/param.h>
#include <common/penalty_base.h>
#include <common/per_peer_state.h>
#include <common/utils.h>
#include <common/wallet_tx.h>
#include <common/wire_error.h>
#include <connectd/gen_connect_wire.h>
#include <errno.h>
#include <hsmd/gen_hsm_wire.h>
#include <lightningd/chaintopology.h>
#include <lightningd/channel_control.h>
#include <lightningd/closing_control.h>
#include <lightningd/hsm_control.h>
#include <lightningd/json.h>
#include <lightningd/jsonrpc.h>
#include <lightningd/lightningd.h>
#include <lightningd/log.h>
#include <lightningd/notification.h>
#include <lightningd/opening_control.h>
#include <lightningd/options.h>
#include <lightningd/plugin_hook.h>
#include <lightningd/subd.h>
#include <openingd/gen_opening_wire.h>
#include <wire/gen_common_wire.h>
#include <wire/wire.h>
#include <wire/wire_sync.h>

/* Channel we're still opening. */
struct uncommitted_channel {
	/* peer->uncommitted_channel == this */
	struct peer *peer;

	/* openingd which is running now */
	struct subd *openingd;

	/* Reserved dbid for if we become a real struct channel */
	u64 dbid;

	/* For logging */
	struct log *log;

	/* Openingd can tell us stuff. */
	const char *transient_billboard;

	/* If we offered channel, this contains information, otherwise NULL */
	struct funding_channel *fc;

	/* Our basepoints for the channel. */
	struct basepoints local_basepoints;

	/* Public key for funding tx. */
	struct pubkey local_funding_pubkey;

	/* These are *not* filled in by new_uncommitted_channel: */

	/* Minimum funding depth (if opener == REMOTE). */
	u32 minimum_depth;

	/* Our channel config. */
	struct channel_config our_config;
};


struct funding_channel {
	struct command *cmd; /* Which initially owns us until openingd request */

	struct wallet_tx *wtx;
	struct amount_msat push;
	struct amount_sat funding;
	u8 channel_flags;
	const u8 *our_upfront_shutdown_script;

	/* Variables we need to compose fields in cmd's response */
	const char *hextx;
	struct channel_id cid;

	/* Peer we're trying to reach. */
	struct pubkey peerid;

	/* Channel, subsequent owner of us */
	struct uncommitted_channel *uc;

	/* Whether or not this is in the middle of getting funded */
	bool inflight;

	/* Any commands trying to cancel us. */
	struct command **cancels;
};

static void uncommitted_channel_disconnect(struct uncommitted_channel *uc,
					   enum log_level level,
					   const char *desc)
{
	u8 *msg = towire_connectctl_peer_disconnected(tmpctx, &uc->peer->id);
	log_(uc->log, level, NULL, false, "%s", desc);
	subd_send_msg(uc->peer->ld->connectd, msg);
	if (uc->fc && uc->fc->cmd)
		was_pending(command_fail(uc->fc->cmd, LIGHTNINGD, "%s", desc));
	notify_disconnect(uc->peer->ld, &uc->peer->id);
}

void kill_uncommitted_channel(struct uncommitted_channel *uc,
			      const char *why)
{
	log_info(uc->log, "Killing openingd: %s", why);

	/* Close openingd. */
	subd_release_channel(uc->openingd, uc);
	uc->openingd = NULL;

	uncommitted_channel_disconnect(uc, LOG_INFORM, why);
	tal_free(uc);
}

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
	json_object_end(response);
}

/* Steals fields from uncommitted_channel: returns NULL if can't generate a
 * key for this channel (shouldn't happen!). */
static struct channel *
wallet_commit_channel(struct lightningd *ld,
		      struct uncommitted_channel *uc,
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

	channel_info->fee_states = new_fee_states(uc, uc->fc ? LOCAL : REMOTE,
						  &feerate);

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
	 *   - if `option_static_remotekey` was negotiated:
	 *     - `option_static_remotekey` applies to all commitment
	 *       transactions
	 *   - otherwise:
	 *     - `option_static_remotekey` does not apply to any commitment
	 *        transactions
	 */
	/* i.e. We set it now for the channel permanently. */
	option_static_remotekey
		= feature_negotiated(ld->our_features,
				     uc->peer->their_features,
				     OPT_STATIC_REMOTEKEY);

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
			      NULL, /* No shutdown_scriptpubkey[REMOTE] yet */
			      our_upfront_shutdown_script,
			      final_key_idx, false,
			      NULL, /* No commit sent yet */
			      /* If we're fundee, could be a little before this
			       * in theory, but it's only used for timing out. */
			      get_block_height(ld->topology),
			      feerate, feerate,
			      /* We are connected */
			      true,
			      &uc->local_basepoints,
			      &uc->local_funding_pubkey,
			      NULL,
			      ld->config.fee_base,
			      ld->config.fee_per_satoshi,
			      remote_upfront_shutdown_script,
			      option_static_remotekey);

	/* Now we finally put it in the database. */
	wallet_channel_insert(ld->wallet, channel);

	return channel;
}

static void funding_success(struct channel *channel)
{
	struct json_stream *response;
	struct funding_channel *fc = channel->peer->uncommitted_channel->fc;
	struct command *cmd = fc->cmd;

	/* Well, those cancels didn't work! */
	for (size_t i = 0; i < tal_count(fc->cancels); i++)
		was_pending(command_fail(fc->cancels[i], LIGHTNINGD,
					 "Funding succeeded before cancel. "
					 "Try fundchannel_cancel again."));

	response = json_stream_success(cmd);
	json_add_string(response, "channel_id",
			type_to_string(tmpctx, struct channel_id, &fc->cid));
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

	if (!fromwire_opening_funder_start_reply(resp, resp,
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
	fc->uc->openingd = NULL;
	/* Frees fc too, and tmpctx */
	tal_free(fc->uc);
}

static void opening_funder_finished(struct subd *openingd, const u8 *resp,
				    const int *fds,
				    struct funding_channel *fc)
{
	struct channel_info channel_info;
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

	if (!fromwire_opening_funder_reply(resp, resp,
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

	/* Steals fields from uc */
	channel = wallet_commit_channel(ld, fc->uc,
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

	/* Needed for the success statement */
	derive_channel_id(&fc->cid, &channel->funding_txid, funding_txout);

	if (pbase)
		wallet_penalty_base_add(ld->wallet, channel->dbid, pbase);

	funding_success(channel);
	peer_start_channeld(channel, pps, NULL, false);

cleanup:
	subd_release_channel(openingd, fc->uc);
	fc->uc->openingd = NULL;
	/* Frees fc too, and tmpctx */
	tal_free(fc->uc);
}

static void opening_fundee_finished(struct subd *openingd,
				    const u8 *reply,
				    const int *fds,
				    struct uncommitted_channel *uc)
{
	u8 *funding_signed;
	struct channel_info channel_info;
	struct bitcoin_signature remote_commit_sig;
	struct bitcoin_tx *remote_commit;
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

	if (!fromwire_opening_fundee(tmpctx, reply,
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
				     &funding_signed,
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

	/* Consumes uc */
	channel = wallet_commit_channel(ld, uc,
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
	peer_start_channeld(channel, pps, funding_signed, false);

	subd_release_channel(openingd, uc);
	uc->openingd = NULL;
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

	if (!fromwire_opening_funder_failed(msg, msg, &desc)) {
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

static void opening_channel_errmsg(struct uncommitted_channel *uc,
				   struct per_peer_state *pps,
				   const struct channel_id *channel_id UNUSED,
				   const char *desc,
				   bool soft_error UNUSED,
				   const u8 *err_for_them UNUSED)
{
	/* Close fds, if any. */
	tal_free(pps);
	uncommitted_channel_disconnect(uc, LOG_INFORM, desc);
	tal_free(uc);
}

/* There's nothing permanent in an unconfirmed transaction */
static void opening_channel_set_billboard(struct uncommitted_channel *uc,
					  bool perm UNUSED,
					  const char *happenings TAKES)
{
	uc->transient_billboard = tal_free(uc->transient_billboard);
	if (happenings)
		uc->transient_billboard = tal_strdup(uc, happenings);
}

static void destroy_uncommitted_channel(struct uncommitted_channel *uc)
{
	if (uc->openingd) {
		struct subd *openingd = uc->openingd;
		uc->openingd = NULL;
		subd_release_channel(openingd, uc);
	}

	/* This is how shutdown_subdaemons tells us not to delete from db! */
	if (!uc->peer->uncommitted_channel)
		return;

	uc->peer->uncommitted_channel = NULL;

	maybe_delete_peer(uc->peer);
}

static struct uncommitted_channel *
new_uncommitted_channel(struct peer *peer)
{
	struct lightningd *ld = peer->ld;
	struct uncommitted_channel *uc = tal(ld, struct uncommitted_channel);
	u8 *msg;

	uc->peer = peer;
	assert(!peer->uncommitted_channel);

	uc->transient_billboard = NULL;
	uc->dbid = wallet_get_channel_dbid(ld->wallet);

	uc->log = new_log(uc, ld->log_book, &uc->peer->id,
			  "chan#%"PRIu64, uc->dbid);

	uc->fc = NULL;
	uc->our_config.id = 0;

	/* Declare the new channel to the HSM. */
	msg = towire_hsm_new_channel(NULL, &uc->peer->id, uc->dbid);
	if (!wire_sync_write(ld->hsm_fd, take(msg)))
		fatal("Could not write to HSM: %s", strerror(errno));
	msg = wire_sync_read(tmpctx, ld->hsm_fd);
	if (!fromwire_hsm_new_channel_reply(msg))
		fatal("HSM gave bad hsm_new_channel_reply %s",
		      tal_hex(msg, msg));

	get_channel_basepoints(ld, &uc->peer->id, uc->dbid,
			       &uc->local_basepoints, &uc->local_funding_pubkey);

	uc->peer->uncommitted_channel = uc;
	tal_add_destructor(uc, destroy_uncommitted_channel);

	return uc;
}

static void channel_config(struct lightningd *ld,
			   struct channel_config *ours,
			   u32 *max_to_self_delay,
			   struct amount_msat *min_effective_htlc_capacity)
{
	struct amount_msat dust_limit;

	/* FIXME: depend on feerate. */
	*max_to_self_delay = ld->config.locktime_max;

	/* Take minimal effective capacity from config min_capacity_sat */
	if (!amount_msat_from_sat_u64(min_effective_htlc_capacity,
				ld->config.min_capacity_sat))
		fatal("amount_msat overflow for config.min_capacity_sat");
	/* Substract 2 * dust_limit, so fundchannel with min value is possible */
	if (!amount_sat_to_msat(&dust_limit, chainparams->dust_limit))
		fatal("amount_msat overflow for dustlimit");
	if (!amount_msat_sub(min_effective_htlc_capacity,
				*min_effective_htlc_capacity,
				dust_limit))
		*min_effective_htlc_capacity = AMOUNT_MSAT(0);
	if (!amount_msat_sub(min_effective_htlc_capacity,
				*min_effective_htlc_capacity,
				dust_limit))
		*min_effective_htlc_capacity = AMOUNT_MSAT(0);

	/* BOLT #2:
	 *
	 * The sending node SHOULD:
	 *...
	 *   - set `dust_limit_satoshis` to a sufficient value to allow
	 *     commitment transactions to propagate through the Bitcoin network.
	 */
	ours->dust_limit = chainparams->dust_limit;
	ours->max_htlc_value_in_flight = AMOUNT_MSAT(UINT64_MAX);

	/* Don't care */
	ours->htlc_minimum = AMOUNT_MSAT(0);

	/* BOLT #2:
	 *
	 * The sending node SHOULD:
	 *   - set `to_self_delay` sufficient to ensure the sender can
	 *     irreversibly spend a commitment transaction output, in case of
	 *     misbehavior by the receiver.
	 */
	 ours->to_self_delay = ld->config.locktime_blocks;

	 ours->max_accepted_htlcs = ld->config.max_concurrent_htlcs;

	 /* This is filled in by lightning_openingd, for consistency. */
	 ours->channel_reserve = AMOUNT_SAT(UINT64_MAX);
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

static void openchannel_hook_cb(struct openchannel_hook_payload *payload STEALS,
			    const char *buffer,
			    const jsmntok_t *toks)
{
	struct subd *openingd = payload->openingd;
	const u8 *our_upfront_shutdown_script;
	const char *errmsg = NULL;

	/* We want to free this, whatever happens. */
	tal_steal(tmpctx, payload);

	/* If openingd went away, don't send it anything! */
	if (!openingd)
		return;

	tal_del_destructor2(openingd, openchannel_payload_remove_openingd, payload);

	/* If we had a hook, check what it says */
	if (buffer) {
		const jsmntok_t *t = json_get_member(buffer, toks, "result");
		if (!t)
			fatal("Plugin returned an invalid response to the"
			      " openchannel hook: %.*s",
			      toks[0].end - toks[0].start,
			      buffer + toks[0].start);

		if (json_tok_streq(buffer, t, "reject")) {
			t = json_get_member(buffer, toks, "error_message");
			if (t)
				errmsg = json_strdup(tmpctx, buffer, t);
			else
				errmsg = "";
			log_debug(openingd->ld->log,
				  "openchannel_hook_cb says '%s'",
				  errmsg);
			our_upfront_shutdown_script = NULL;
		} else if (!json_tok_streq(buffer, t, "continue"))
			fatal("Plugin returned an invalid result for the "
			      "openchannel hook: %.*s",
			      t->end - t->start, buffer + t->start);

		/* Check for a 'close_to' address passed back */
		if (!errmsg) {
			t = json_get_member(buffer, toks, "close_to");
			if (t) {
				switch (json_to_address_scriptpubkey(tmpctx, chainparams,
								     buffer, t,
								     &our_upfront_shutdown_script)) {
					case ADDRESS_PARSE_UNRECOGNIZED:
						fatal("Plugin returned an invalid response to the"
						      " openchannel.close_to hook: %.*s",
						      t->end - t->start, buffer + t->start);
					case ADDRESS_PARSE_WRONG_NETWORK:
						fatal("Plugin returned invalid response to the"
						      " openchannel.close_to hook: address %s is"
						      " not on network %s",
						      tal_hex(NULL, our_upfront_shutdown_script),
						      chainparams->network_name);
					case ADDRESS_PARSE_SUCCESS:
						errmsg = NULL;
				}
			} else
				our_upfront_shutdown_script = NULL;
		}
	} else
		our_upfront_shutdown_script = NULL;

	subd_send_msg(openingd,
		      take(towire_opening_got_offer_reply(NULL, errmsg,
							  our_upfront_shutdown_script)));
}

REGISTER_SINGLE_PLUGIN_HOOK(openchannel,
			    openchannel_hook_cb,
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
			      take(towire_opening_got_offer_reply(NULL,
					  "Already have active channel", NULL)));
		return;
	}

	payload = tal(openingd, struct openchannel_hook_payload);
	payload->openingd = openingd;
	if (!fromwire_opening_got_offer(payload, msg,
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
	enum opening_wire_type t = fromwire_peektype(msg);
	struct uncommitted_channel *uc = openingd->channel;

	switch (t) {
	case WIRE_OPENING_FUNDER_REPLY:
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
	case WIRE_OPENING_FUNDER_START_REPLY:
		if (!uc->fc) {
			log_broken(openingd->log, "Unexpected FUNDER_START_REPLY %s",
				   tal_hex(tmpctx, msg));
			tal_free(openingd);
			return 0;
		}
		opening_funder_start_replied(openingd, msg, fds, uc->fc);
		return 0;
	case WIRE_OPENING_FUNDER_FAILED:
		if (!uc->fc) {
			log_unusual(openingd->log, "Unexpected FUNDER_FAILED %s",
				   tal_hex(tmpctx, msg));
			tal_free(openingd);
			return 0;
		}
		opening_funder_failed(openingd, msg, uc);
		return 0;

	case WIRE_OPENING_FUNDEE:
		if (tal_count(fds) != 3)
			return 3;
		opening_fundee_finished(openingd, msg, fds, uc);
		return 0;

	case WIRE_OPENING_GOT_OFFER:
		opening_got_offer(openingd, msg, uc);
		return 0;

	/* We send these! */
	case WIRE_OPENING_INIT:
	case WIRE_OPENING_FUNDER_START:
	case WIRE_OPENING_FUNDER_COMPLETE:
	case WIRE_OPENING_FUNDER_CANCEL:
	case WIRE_OPENING_GOT_OFFER_REPLY:
	case WIRE_OPENING_DEV_MEMLEAK:
	/* Replies never get here */
	case WIRE_OPENING_DEV_MEMLEAK_REPLY:
		break;
	}

	switch ((enum common_wire_type)t) {
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
		   opening_wire_type_name(t), tal_hex(tmpctx, msg));
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

	uc->openingd = new_channel_subd(peer->ld,
					"lightning_openingd",
					uc, &peer->id, uc->log,
					true, opening_wire_type_name,
					openingd_msg,
					opening_channel_errmsg,
					opening_channel_set_billboard,
					take(&pps->peer_fd),
					take(&pps->gossip_fd),
					take(&pps->gossip_store_fd),
					take(&hsmfd), NULL);
	if (!uc->openingd) {
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

	msg = towire_opening_init(NULL,
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
				  send_msg,
				  IFDEV(peer->ld->dev_force_tmp_channel_id, NULL),
				  IFDEV(peer->ld->dev_fast_gossip, false));
	subd_send_msg(uc->openingd, take(msg));
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
	msg = towire_opening_funder_complete(NULL,
					     funding_txid,
					     funding_txout);
	subd_send_msg(peer->uncommitted_channel->openingd, take(msg));
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
	const jsmntok_t *cidtok;
	u8 *msg;

	if (!param(cmd, buffer, params,
		   p_req("id", param_node_id, &id),
		   p_opt("channel_id", param_tok, &cidtok),
		   NULL))
		return command_param_failed();

	peer = peer_by_id(cmd->ld, id);
	if (!peer) {
		return command_fail(cmd, FUNDING_UNKNOWN_PEER, "Unknown peer");
	}

	if (peer->uncommitted_channel) {
		if (!peer->uncommitted_channel->fc || !peer->uncommitted_channel->fc->inflight)
			return command_fail(cmd, LIGHTNINGD, "No channel funding in progress.");

		/* Make sure this gets notified if we succeed or cancel */
		tal_arr_expand(&peer->uncommitted_channel->fc->cancels, cmd);
		msg = towire_opening_funder_cancel(NULL);
		subd_send_msg(peer->uncommitted_channel->openingd, take(msg));
		return command_still_pending(cmd);
	}

	return cancel_channel_before_broadcast(cmd, buffer, peer, cidtok);
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

	msg = towire_opening_funder_start(NULL,
					  *amount,
					  fc->push,
					  fc->our_upfront_shutdown_script,
					  *feerate_per_kw,
					  fc->channel_flags);

	subd_send_msg(peer->uncommitted_channel->openingd, take(msg));
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

#if DEVELOPER
 /* Indented to avoid include ordering check */
 #include <lightningd/memdump.h>

static void opening_died_forget_memleak(struct subd *openingd,
					struct command *cmd)
{
	/* FIXME: We ignore the remaining openingds in this case. */
	opening_memleak_done(cmd, NULL);
}

/* Mutual recursion */
static void opening_memleak_req_next(struct command *cmd, struct peer *prev);
static void opening_memleak_req_done(struct subd *openingd,
				     const u8 *msg, const int *fds UNUSED,
				     struct command *cmd)
{
	bool found_leak;
	struct uncommitted_channel *uc = openingd->channel;

	tal_del_destructor2(openingd, opening_died_forget_memleak, cmd);
	if (!fromwire_opening_dev_memleak_reply(msg, &found_leak)) {
		was_pending(command_fail(cmd, LIGHTNINGD,
					 "Bad opening_dev_memleak"));
		return;
	}

	if (found_leak) {
		opening_memleak_done(cmd, openingd);
		return;
	}
	opening_memleak_req_next(cmd, uc->peer);
}

static void opening_memleak_req_next(struct command *cmd, struct peer *prev)
{
	struct peer *p;

	list_for_each(&cmd->ld->peers, p, list) {
		if (!p->uncommitted_channel)
			continue;
		if (p == prev) {
			prev = NULL;
			continue;
		}
		if (prev != NULL)
			continue;

		subd_req(p,
			 p->uncommitted_channel->openingd,
			 take(towire_opening_dev_memleak(NULL)),
			 -1, 0, opening_memleak_req_done, cmd);
		/* Just in case it dies before replying! */
		tal_add_destructor2(p->uncommitted_channel->openingd,
				    opening_died_forget_memleak, cmd);
		return;
	}
	opening_memleak_done(cmd, NULL);
}

void opening_dev_memleak(struct command *cmd)
{
	opening_memleak_req_next(cmd, NULL);
}
#endif /* DEVELOPER */

struct subd *peer_get_owning_subd(struct peer *peer)
{
	struct channel *channel;
	channel = peer_active_channel(peer);

	if (channel != NULL) {
		return channel->owner;
	} else if (peer->uncommitted_channel != NULL) {
		return peer->uncommitted_channel->openingd;
	}
	return NULL;
}
