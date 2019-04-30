#include "bitcoin/feerate.h"
#include <bitcoin/privkey.h>
#include <bitcoin/script.h>
#include <ccan/tal/str/str.h>
#include <common/channel_config.h>
#include <common/funding_tx.h>
#include <common/json_command.h>
#include <common/jsonrpc_errors.h>
#include <common/key_derive.h>
#include <common/param.h>
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
#include <lightningd/peer_control.h>
#include <lightningd/subd.h>
#include <openingd/gen_opening_wire.h>
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

	/* Minimum funding depth (if funder == REMOTE). */
	u32 minimum_depth;

	/* Our channel config. */
	struct channel_config our_config;
};


struct funding_channel {
	struct command *cmd; /* Which initially owns us until openingd request */

	struct wallet_tx wtx;
	struct amount_msat push;
	u8 channel_flags;

	/* Variables we need to compose fields in cmd's response */
	const char *hextx;
	struct channel_id cid;

	/* Peer we're trying to reach. */
	struct pubkey peerid;

	/* Channel, subsequent owner of us */
	struct uncommitted_channel *uc;
};

static void uncommitted_channel_disconnect(struct uncommitted_channel *uc,
					   const char *desc)
{
	u8 *msg = towire_connectctl_peer_disconnected(tmpctx, &uc->peer->id);
	log_info(uc->log, "%s", desc);
	subd_send_msg(uc->peer->ld->connectd, msg);
	if (uc->fc)
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

	uncommitted_channel_disconnect(uc, why);
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
	if (amount_sat_to_msat(&total, uc->fc->wtx.amount)
	    && amount_msat_sub(&ours, total, uc->fc->push)) {
		json_add_amount_msat(response, ours,
			     "msatoshi_to_us", "to_us_msat");
		json_add_amount_msat(response, total,
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
		      const u8 *remote_upfront_shutdown_script)
{
	struct channel *channel;
	struct amount_msat our_msat;
	s64 final_key_idx;

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
	} else
		our_msat = push;

	/* Feerates begin identical. */
	channel_info->feerate_per_kw[LOCAL]
		= channel_info->feerate_per_kw[REMOTE]
		= feerate;

	/* old_remote_per_commit not valid yet, copy valid one. */
	channel_info->old_remote_per_commit = channel_info->remote_per_commit;

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
			      NULL, /* No remote_shutdown_scriptpubkey yet */
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
			      remote_upfront_shutdown_script);

	/* Now we finally put it in the database. */
	wallet_channel_insert(ld->wallet, channel);

	return channel;
}

static void funding_broadcast_failed(struct channel *channel,
				     int exitstatus, const char *msg)
{
	struct funding_channel *fc = channel->peer->uncommitted_channel->fc;
	struct command *cmd = fc->cmd;

	/* Massage output into shape so it doesn't kill the JSON serialization */
	char *output = tal_strjoin(cmd, tal_strsplit(cmd, msg, "\n", STR_NO_EMPTY), " ", STR_NO_TRAIL);
	was_pending(command_fail(cmd, FUNDING_BROADCAST_FAIL,
			"Error broadcasting funding transaction: %s", output));

	/* Frees fc too */
	tal_free(fc->uc);

	/* Keep in state CHANNELD_AWAITING_LOCKIN until (manual) broadcast */
}

static void funding_broadcast_success(struct channel *channel)
{
	struct json_stream *response;
	struct funding_channel *fc = channel->peer->uncommitted_channel->fc;
	struct command *cmd = fc->cmd;

	response = json_stream_success(cmd);
	json_object_start(response, NULL);
	json_add_string(response, "tx", fc->hextx);
	json_add_txid(response, "txid", &channel->funding_txid);
	json_add_string(response, "channel_id",
					type_to_string(tmpctx, struct channel_id, &fc->cid));
	json_object_end(response);
	was_pending(command_success(cmd, response));

	/* Frees fc too */
	tal_free(fc->uc);
}

static void funding_broadcast_failed_or_success(struct channel *channel,
				     int exitstatus, const char *msg)
{
	if (exitstatus == 0) {
		funding_broadcast_success(channel);
	} else {
		funding_broadcast_failed(channel, exitstatus, msg);
	}
}

static void opening_funder_finished(struct subd *openingd, const u8 *resp,
				    const int *fds,
				    struct funding_channel *fc)
{
	u8 *msg;
	struct channel_info channel_info;
	struct bitcoin_tx *fundingtx;
	struct bitcoin_txid funding_txid, expected_txid;
	struct pubkey changekey;
	struct crypto_state cs;
	struct bitcoin_signature remote_commit_sig;
	struct bitcoin_tx *remote_commit;
	u16 funding_outnum;
	u32 feerate;
	struct amount_sat change;
	struct channel *channel;
	struct lightningd *ld = openingd->ld;
	u8 *remote_upfront_shutdown_script;

	assert(tal_count(fds) == 2);

	/* This is a new channel_info.their_config so set its ID to 0 */
	channel_info.their_config.id = 0;

	if (!fromwire_opening_funder_reply(resp, resp,
					   &channel_info.their_config,
					   &remote_commit,
					   &remote_commit_sig,
					   &cs,
					   &channel_info.theirbase.revocation,
					   &channel_info.theirbase.payment,
					   &channel_info.theirbase.htlc,
					   &channel_info.theirbase.delayed_payment,
					   &channel_info.remote_per_commit,
					   &fc->uc->minimum_depth,
					   &channel_info.remote_fundingkey,
					   &expected_txid,
					   &feerate,
					   &fc->uc->our_config.channel_reserve,
					   &remote_upfront_shutdown_script)) {
		log_broken(fc->uc->log,
			   "bad OPENING_FUNDER_REPLY %s",
			   tal_hex(resp, resp));
		was_pending(command_fail(fc->cmd, LIGHTNINGD,
					 "bad OPENING_FUNDER_REPLY %s",
					 tal_hex(fc->cmd, resp)));
		goto failed;
	}
	log_debug(ld->log,
		  "%s", type_to_string(tmpctx, struct pubkey,
				       &channel_info.remote_per_commit));

	/* Generate the funding tx. */
	if (!amount_sat_eq(fc->wtx.change, AMOUNT_SAT(0))
	    && !bip32_pubkey(ld->wallet->bip32_base,
			     &changekey, fc->wtx.change_key_index))
		fatal("Error deriving change key %u", fc->wtx.change_key_index);

	fundingtx = funding_tx(tmpctx, &funding_outnum,
			       fc->wtx.utxos, fc->wtx.amount,
			       &fc->uc->local_funding_pubkey,
			       &channel_info.remote_fundingkey,
			       fc->wtx.change, &changekey,
			       ld->wallet->bip32_base);

	log_debug(fc->uc->log, "Funding tx has %zi inputs, %zu outputs:",
		  fundingtx->wtx->num_inputs,
		  fundingtx->wtx->num_outputs);

	for (size_t i = 0; i < fundingtx->wtx->num_inputs; i++) {
		struct bitcoin_txid tmptxid;
		bitcoin_tx_input_get_txid(fundingtx, i, &tmptxid);
		log_debug(fc->uc->log, "%zi: %s (%s) %s\n",
			  i,
			  type_to_string(tmpctx, struct amount_sat,
					 &fc->wtx.utxos[i]->amount),
			  fc->wtx.utxos[i]->is_p2sh ? "P2SH" : "SEGWIT",
			  type_to_string(tmpctx, struct bitcoin_txid,
					 &tmptxid));
	}

	bitcoin_txid(fundingtx, &funding_txid);

	if (!bitcoin_txid_eq(&funding_txid, &expected_txid)) {
		log_broken(fc->uc->log,
			   "Funding txid mismatch:"
			   " amount %s change %s"
			   " changeidx %u"
			   " localkey %s remotekey %s",
			   type_to_string(tmpctx, struct amount_sat,
					  &fc->wtx.amount),
			   type_to_string(tmpctx, struct amount_sat,
					  &fc->wtx.change),
			   fc->wtx.change_key_index,
			   type_to_string(fc, struct pubkey,
					  &fc->uc->local_funding_pubkey),
			   type_to_string(fc, struct pubkey,
					  &channel_info.remote_fundingkey));
		was_pending(command_fail(fc->cmd, JSONRPC2_INVALID_PARAMS,
					 "Funding txid mismatch:"
					 " amount %s change %s"
					 " changeidx %u"
					 " localkey %s remotekey %s",
					 type_to_string(tmpctx,
							struct amount_sat,
							&fc->wtx.amount),
					 type_to_string(tmpctx,
							struct amount_sat,
							&fc->wtx.change),
					 fc->wtx.change_key_index,
					 type_to_string(fc, struct pubkey,
							&fc->uc->local_funding_pubkey),
					 type_to_string(fc, struct pubkey,
							&channel_info.remote_fundingkey)));
		goto failed;
	}

	/* Steals fields from uc */
	channel = wallet_commit_channel(ld, fc->uc,
					remote_commit,
					&remote_commit_sig,
					&funding_txid,
					funding_outnum,
					fc->wtx.amount,
					fc->push,
					fc->channel_flags,
					&channel_info,
					feerate,
					remote_upfront_shutdown_script);
	if (!channel) {
		was_pending(command_fail(fc->cmd, LIGHTNINGD,
					 "Key generation failure"));
		goto failed;
	}

	/* Get HSM to sign the funding tx. */
	log_debug(channel->log, "Getting HSM to sign funding tx");

	msg = towire_hsm_sign_funding(tmpctx, channel->funding,
				      fc->wtx.change,
				      fc->wtx.change_key_index,
				      &fc->uc->local_funding_pubkey,
				      &channel_info.remote_fundingkey,
				      fc->wtx.utxos);

	if (!wire_sync_write(ld->hsm_fd, take(msg)))
		fatal("Could not write to HSM: %s", strerror(errno));

	msg = wire_sync_read(fc, ld->hsm_fd);
	if (!fromwire_hsm_sign_funding_reply(tmpctx, msg, &fundingtx))
		fatal("HSM gave bad sign_funding_reply %s",
		      tal_hex(msg, resp));

	/* Extract the change output and add it to the DB */
	wallet_extract_owned_outputs(ld->wallet, fundingtx, NULL, &change);

	/* Make sure we recognize our change output by its scriptpubkey in
	 * future. This assumes that we have only two outputs, may not be true
	 * if we add support for multifundchannel */
	if (fundingtx->wtx->num_outputs == 2)
		txfilter_add_scriptpubkey(ld->owned_txfilter, bitcoin_tx_output_get_script(tmpctx, fundingtx, !funding_outnum));

	/* We need these to compose cmd's response in funding_broadcast_success */
	fc->hextx = tal_hex(fc, linearize_tx(fc->cmd, fundingtx));
	derive_channel_id(&fc->cid, &channel->funding_txid, funding_outnum);

	/* Send it out and watch for confirms. */
	broadcast_tx(ld->topology, channel, fundingtx, funding_broadcast_failed_or_success);
	channel_watch_funding(ld, channel);

	/* Mark consumed outputs as spent */
	wallet_confirm_utxos(ld->wallet, fc->wtx.utxos);

	/* Start normal channel daemon. */
	peer_start_channeld(channel, &cs, fds[0], fds[1], NULL, false);

	subd_release_channel(openingd, fc->uc);
	fc->uc->openingd = NULL;

	return;

failed:
	close(fds[0]);
	close(fds[1]);
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
	struct crypto_state cs;
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
	u8 *remote_upfront_shutdown_script;

	log_debug(uc->log, "Got opening_fundee_finish_response");
	assert(tal_count(fds) == 2);

	/* This is a new channel_info.their_config, set its ID to 0 */
	channel_info.their_config.id = 0;

	if (!fromwire_opening_fundee(tmpctx, reply,
					   &channel_info.their_config,
					   &remote_commit,
					   &remote_commit_sig,
					   &cs,
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
				           &remote_upfront_shutdown_script)) {
		log_broken(uc->log, "bad OPENING_FUNDEE_REPLY %s",
			   tal_hex(reply, reply));
		uncommitted_channel_disconnect(uc, "bad OPENING_FUNDEE_REPLY");
		goto failed;
	}

	/* openingd should never accept them funding channel in this case. */
	if (peer_active_channel(uc->peer)) {
		log_broken(uc->log, "openingd accepted peer funding channel");
		uncommitted_channel_disconnect(uc, "already have active channel");
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
					remote_upfront_shutdown_script);
	if (!channel) {
		uncommitted_channel_disconnect(uc, "Commit channel failed");
		goto failed;
	}

	log_debug(channel->log, "Watching funding tx %s",
		     type_to_string(reply, struct bitcoin_txid,
				    &channel->funding_txid));

	channel_watch_funding(ld, channel);

	/* On to normal operation! */
	peer_start_channeld(channel, &cs,
			    fds[0], fds[1], funding_signed, false);

	subd_release_channel(openingd, uc);
	uc->openingd = NULL;
	tal_free(uc);
	return;

failed:
	close(fds[0]);
	close(fds[1]);
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

	was_pending(command_fail(uc->fc->cmd, LIGHTNINGD, "%s", desc));

	/* Clear uc->fc, so we can try again, and so we don't fail twice
	 * if they close. */
	uc->fc = tal_free(uc->fc);
}

static void opening_channel_errmsg(struct uncommitted_channel *uc,
				   int peer_fd, int gossip_fd,
				   const struct crypto_state *cs,
				   const struct channel_id *channel_id UNUSED,
				   const char *desc,
				   const u8 *err_for_them UNUSED)
{
	if (peer_fd != -1) {
		close(peer_fd);
		close(gossip_fd);
	}
	uncommitted_channel_disconnect(uc, desc);
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
	const char *idname;

	uc->peer = peer;
	assert(!peer->uncommitted_channel);

	uc->transient_billboard = NULL;
	uc->dbid = wallet_get_channel_dbid(ld->wallet);

	idname = type_to_string(uc, struct node_id, &uc->peer->id);
	uc->log = new_log(uc, uc->peer->log_book, "%s chan #%"PRIu64":",
			  idname, uc->dbid);
	tal_free(idname);

	uc->fc = NULL;
	uc->our_config.id = 0;

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
	if (!amount_sat_to_msat(&dust_limit, get_chainparams(ld)->dust_limit))
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
	ours->dust_limit = get_chainparams(ld)->dust_limit;
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

	 /* BOLT #2:
	  *
	  * The receiving node MUST fail the channel if:
	  *...
	  *   - `max_accepted_htlcs` is greater than 483.
	  */
	 ours->max_accepted_htlcs = 483;

	 /* This is filled in by lightning_openingd, for consistency. */
	 ours->channel_reserve = AMOUNT_SAT(UINT64_MAX);
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
		if (tal_count(fds) != 2)
			return 2;
		opening_funder_finished(openingd, msg, fds, uc->fc);
		return 0;

	case WIRE_OPENING_FUNDER_FAILED:
		if (!uc->fc) {
			log_broken(openingd->log, "Unexpected FUNDER_FAILED %s",
				   tal_hex(tmpctx, msg));
			tal_free(openingd);
			return 0;
		}
		opening_funder_failed(openingd, msg, uc);
		return 0;

	case WIRE_OPENING_FUNDEE:
		if (tal_count(fds) != 2)
			return 2;
		opening_fundee_finished(openingd, msg, fds, uc);
		return 0;

	/* We send these! */
	case WIRE_OPENING_INIT:
	case WIRE_OPENING_FUNDER:
	case WIRE_OPENING_CAN_ACCEPT_CHANNEL:
	case WIRE_OPENING_DEV_MEMLEAK:
	/* Replies never get here */
	case WIRE_OPENING_DEV_MEMLEAK_REPLY:
		break;
	}
	log_broken(openingd->log, "Unexpected msg %s: %s",
		   opening_wire_type_name(t), tal_hex(tmpctx, msg));
	tal_free(openingd);
	return 0;
}

void peer_start_openingd(struct peer *peer,
			 const struct crypto_state *cs,
			 int peer_fd, int gossip_fd,
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
					uc, uc->log,
					true, opening_wire_type_name,
					openingd_msg,
					opening_channel_errmsg,
					opening_channel_set_billboard,
					take(&peer_fd), take(&gossip_fd),
					take(&hsmfd), NULL);
	if (!uc->openingd) {
		uncommitted_channel_disconnect(uc,
					       tal_fmt(tmpctx,
						       "Running lightning_openingd: %s",
						       strerror(errno)));
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
				  &get_chainparams(peer->ld)->genesis_blockhash,
				  &uc->our_config,
				  max_to_self_delay,
				  min_effective_htlc_capacity,
				  cs, &uc->local_basepoints,
				  &uc->local_funding_pubkey,
				  uc->minimum_depth,
				  feerate_min(peer->ld, NULL),
				  feerate_max(peer->ld, NULL),
				  !peer_active_channel(peer),
				  peer->localfeatures,
				  send_msg);
	subd_send_msg(uc->openingd, take(msg));
}

void opening_peer_no_active_channels(struct peer *peer)
{
	assert(!peer_active_channel(peer));
	if (peer->uncommitted_channel) {
		subd_send_msg(peer->uncommitted_channel->openingd,
			      take(towire_opening_can_accept_channel(NULL)));
	}
}

/**
 * json_fund_channel - Entrypoint for funding a channel
 */
static struct command_result *json_fund_channel(struct command *cmd,
						const char *buffer,
						const jsmntok_t *obj UNNEEDED,
						const jsmntok_t *params)
{
	struct command_result *res;
	struct funding_channel * fc = tal(cmd, struct funding_channel);
	struct node_id *id;
	struct peer *peer;
	struct channel *channel;
	u32 *feerate_per_kw, *minconf, maxheight;
	bool *announce_channel;
	u8 *msg;
	struct amount_sat max_funding_satoshi;

	max_funding_satoshi = get_chainparams(cmd->ld)->max_funding;

	fc->cmd = cmd;
	fc->uc = NULL;
	wtx_init(cmd, &fc->wtx, max_funding_satoshi);
	if (!param(fc->cmd, buffer, params,
		   p_req("id", param_node_id, &id),
		   p_req("satoshi", param_wtx, &fc->wtx),
		   p_opt("feerate", param_feerate, &feerate_per_kw),
		   p_opt_def("announce", param_bool, &announce_channel, true),
		   p_opt_def("minconf", param_number, &minconf, 1),
		   NULL))
		return command_param_failed();

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

	peer = peer_by_id(cmd->ld, id);
	if (!peer) {
		return command_fail(cmd, LIGHTNINGD, "Unknown peer");
	}

	channel = peer_active_channel(peer);
	if (channel) {
		return command_fail(cmd, LIGHTNINGD, "Peer already %s",
				    channel_state_name(channel));
	}

	if (!peer->uncommitted_channel) {
		return command_fail(cmd, LIGHTNINGD, "Peer not connected");
	}

	if (peer->uncommitted_channel->fc) {
		return command_fail(cmd, LIGHTNINGD, "Already funding channel");
	}

	/* FIXME: Support push_msat? */
	fc->push = AMOUNT_MSAT(0);
	fc->channel_flags = OUR_CHANNEL_FLAGS;
	if (!*announce_channel) {
		fc->channel_flags &= ~CHANNEL_FLAGS_ANNOUNCE_CHANNEL;
		log_info(peer->ld->log, "Will open private channel with node %s",
			type_to_string(fc, struct node_id, id));
	}

	maxheight = minconf_to_maxheight(*minconf, cmd->ld);
	res = wtx_select_utxos(&fc->wtx, *feerate_per_kw,
			       BITCOIN_SCRIPTPUBKEY_P2WSH_LEN, maxheight);
	if (res)
		return res;

	assert(!amount_sat_greater(fc->wtx.amount, max_funding_satoshi));

	peer->uncommitted_channel->fc = tal_steal(peer->uncommitted_channel, fc);
	fc->uc = peer->uncommitted_channel;

	msg = towire_opening_funder(NULL,
				    fc->wtx.amount,
				    fc->push,
				    *feerate_per_kw,
				    fc->wtx.change,
				    fc->wtx.change_key_index,
				    fc->channel_flags,
				    fc->wtx.utxos,
				    cmd->ld->wallet->bip32_base);

	/* Openingd will either succeed, or fail, or tell us the other side
	 * funded first. */
	subd_send_msg(peer->uncommitted_channel->openingd, take(msg));
	return command_still_pending(cmd);
}

static const struct json_command fund_channel_command = {
    "fundchannel", json_fund_channel,
    "Fund channel with {id} using {satoshi} (or 'all') satoshis, at optional "
    "{feerate}. Only use outputs that have {minconf} confirmations."
};
AUTODATA(json_command, &fund_channel_command);

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
