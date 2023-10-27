#include "config.h"
#include <arpa/inet.h>
#include <bitcoin/feerate.h>
#include <bitcoin/script.h>
#include <bitcoin/tx.h>
#include <ccan/array_size/array_size.h>
#include <ccan/cast/cast.h>
#include <ccan/io/io.h>
#include <ccan/mem/mem.h>
#include <ccan/noerr/noerr.h>
#include <ccan/str/str.h>
#include <ccan/take/take.h>
#include <ccan/tal/str/str.h>
#include <channeld/channeld_wiregen.h>
#include <common/addr.h>
#include <common/closing_fee.h>
#include <common/configdir.h>
#include <common/dev_disconnect.h>
#include <common/features.h>
#include <common/htlc_trim.h>
#include <common/initial_commit_tx.h>
#include <common/json_command.h>
#include <common/json_param.h>
#include <common/jsonrpc_errors.h>
#include <common/key_derive.h>
#include <common/scb_wiregen.h>
#include <common/shutdown_scriptpubkey.h>
#include <common/status.h>
#include <common/timeout.h>
#include <common/type_to_string.h>
#include <common/utils.h>
#include <common/version.h>
#include <common/wire_error.h>
#include <connectd/connectd_wiregen.h>
#include <errno.h>
#include <fcntl.h>
#include <gossipd/gossipd_wiregen.h>
#include <hsmd/hsmd_wiregen.h>
#include <inttypes.h>
#include <lightningd/anchorspend.h>
#include <lightningd/bitcoind.h>
#include <lightningd/chaintopology.h>
#include <lightningd/channel.h>
#include <lightningd/channel_control.h>
#include <lightningd/closing_control.h>
#include <lightningd/connect_control.h>
#include <lightningd/dual_open_control.h>
#include <lightningd/gossip_control.h>
#include <lightningd/hsm_control.h>
#include <lightningd/jsonrpc.h>
#include <lightningd/lightningd.h>
#include <lightningd/log.h>
#include <lightningd/memdump.h>
#include <lightningd/notification.h>
#include <lightningd/onchain_control.h>
#include <lightningd/opening_common.h>
#include <lightningd/opening_control.h>
#include <lightningd/options.h>
#include <lightningd/peer_control.h>
#include <lightningd/peer_fd.h>
#include <lightningd/peer_htlcs.h>
#include <lightningd/plugin_hook.h>
#include <lightningd/subd.h>
#include <limits.h>
#include <onchaind/onchaind_wiregen.h>
#include <openingd/dualopend_wiregen.h>
#include <openingd/openingd_wiregen.h>
#include <stdlib.h>
#include <unistd.h>
#include <wally_bip32.h>
#include <wire/onion_wire.h>
#include <wire/wire_sync.h>

static void destroy_peer(struct peer *peer)
{
	peer_node_id_map_del(peer->ld->peers, peer);
	if (peer->dbid)
		peer_dbid_map_del(peer->ld->peers_by_dbid, peer);
}

void peer_set_dbid(struct peer *peer, u64 dbid)
{
	assert(!peer->dbid);
	assert(dbid);
	peer->dbid = dbid;
	peer_dbid_map_add(peer->ld->peers_by_dbid, peer);
}

struct peer *new_peer(struct lightningd *ld, u64 dbid,
		      const struct node_id *id,
		      const struct wireaddr_internal *addr,
		      const u8 *their_features,
		      bool connected_incoming)
{
	/* We are owned by our channels, and freed manually by destroy_channel */
	struct peer *peer = tal(NULL, struct peer);

	peer->ld = ld;
	peer->dbid = dbid;
	peer->id = *id;
	peer->uncommitted_channel = NULL;
	peer->addr = *addr;
	peer->connected_incoming = connected_incoming;
	peer->remote_addr = NULL;
	list_head_init(&peer->channels);
	peer->direction = node_id_idx(&peer->ld->id, &peer->id);
	peer->connected = PEER_DISCONNECTED;
	peer->last_connect_attempt.ts.tv_sec
		= peer->last_connect_attempt.ts.tv_nsec = 0;
	if (their_features)
		peer->their_features = tal_dup_talarr(peer, u8, their_features);
	else
		peer->their_features = NULL;

	peer->dev_ignore_htlcs = false;

	peer_node_id_map_add(ld->peers, peer);
	if (dbid)
		peer_dbid_map_add(ld->peers_by_dbid, peer);
	tal_add_destructor(peer, destroy_peer);
	return peer;
}

static void delete_peer(struct peer *peer)
{
	assert(list_empty(&peer->channels));
	assert(!peer->uncommitted_channel);
	/* If it only ever existed because of uncommitted channel, it won't
	 * be in the database */
	if (peer->dbid != 0)
		wallet_delete_peer_if_unused(peer->ld->wallet, peer->dbid);
	tal_free(peer);
}

/* Last one out deletes peer. */
void maybe_delete_peer(struct peer *peer)
{
	if (!list_empty(&peer->channels))
		return;
	if (peer->uncommitted_channel) {
		/* This isn't sufficient to keep it in db! */
		if (peer->dbid != 0) {
			wallet_delete_peer_if_unused(peer->ld->wallet, peer->dbid);
			peer_dbid_map_del(peer->ld->peers_by_dbid, peer);
			peer->dbid = 0;
		}
		return;
	}
	/* Maybe it's reconnected / reconnecting? */
	if (peer->connected != PEER_DISCONNECTED)
		return;
	delete_peer(peer);
}

static void peer_channels_cleanup(struct lightningd *ld,
				  const struct node_id *id)
{
	struct peer *peer;
	struct channel *c, **channels;

	peer = peer_by_id(ld, id);
	if (!peer)
		return;

	/* Freeing channels can free peer, so gather first. */
	channels = tal_arr(tmpctx, struct channel *, 0);
	list_for_each(&peer->channels, c, list)
		tal_arr_expand(&channels, c);

	if (peer->uncommitted_channel) {
		/* Frees peer if no channels */
		kill_uncommitted_channel(peer->uncommitted_channel,
					 "Disconnected");
	} else if (tal_count(channels) == 0)
		/* Was completely idle. */
		tal_free(peer);

	for (size_t i = 0; i < tal_count(channels); i++) {
		c = channels[i];
		if (channel_state_wants_peercomms(c->state)) {
			channel_cleanup_commands(c, "Disconnected");
			channel_fail_transient(c, true, "Disconnected");
		} else if (channel_state_uncommitted(c->state)) {
			channel_unsaved_close_conn(c, "Disconnected");
		}
	}
}

struct peer *find_peer_by_dbid(struct lightningd *ld, u64 dbid)
{
	return peer_dbid_map_get(ld->peers_by_dbid, dbid);
}

struct peer *peer_by_id(struct lightningd *ld, const struct node_id *id)
{
	return peer_node_id_map_get(ld->peers, id);
}

struct peer *peer_from_json(struct lightningd *ld,
			    const char *buffer,
			    const jsmntok_t *peeridtok)
{
	struct node_id peerid;

	if (!json_to_node_id(buffer, peeridtok, &peerid))
		return NULL;

	return peer_by_id(ld, &peerid);
}

u8 *p2wpkh_for_keyidx(const tal_t *ctx, struct lightningd *ld, u64 keyidx)
{
	struct pubkey shutdownkey;

	bip32_pubkey(ld, &shutdownkey, keyidx);
	return scriptpubkey_p2wpkh(ctx, &shutdownkey);
}

u8 *p2tr_for_keyidx(const tal_t *ctx, struct lightningd *ld, u64 keyidx)
{
	struct pubkey shutdownkey;

	bip32_pubkey(ld, &shutdownkey, keyidx);

	return scriptpubkey_p2tr(ctx, &shutdownkey);
}

static struct bitcoin_tx *sign_last_tx(const tal_t *ctx,
				       const struct channel *channel,
				       const struct bitcoin_tx *last_tx,
				       const struct bitcoin_signature *last_sig)
{
	struct lightningd *ld = channel->peer->ld;
	struct bitcoin_signature sig;
	const u8 *msg;
	u8 **witness;
	u64 commit_index = channel->next_index[LOCAL] - 1;
	struct bitcoin_tx *tx = clone_bitcoin_tx(ctx, last_tx);

	assert(!tx->wtx->inputs[0].witness);
	msg = towire_hsmd_sign_commitment_tx(NULL,
					     &channel->peer->id,
					     channel->dbid,
					     tx,
					     &channel->channel_info
					     .remote_fundingkey,
					     commit_index);

	msg = hsm_sync_req(tmpctx, ld, take(msg));
	if (!fromwire_hsmd_sign_commitment_tx_reply(msg, &sig))
		fatal("HSM gave bad sign_commitment_tx_reply %s",
		      tal_hex(tmpctx, msg));

	witness =
	    bitcoin_witness_2of2(tx, last_sig,
				 &sig, &channel->channel_info.remote_fundingkey,
				 &channel->local_funding_pubkey);

	bitcoin_tx_input_set_witness(tx, 0, take(witness));
	return tx;
}

bool invalid_last_tx(const struct bitcoin_tx *tx)
{
	/* This problem goes back further, but was discovered just before the
	 * 0.7.1 release. */
#ifdef COMPAT_V070
	/* Old bug had commitment txs with no outputs; bitcoin_txid asserts. */
	return !tx || !tx->wtx || tx->wtx->num_outputs == 0;
#else
	return false;
#endif
}

static bool commit_tx_send_finished(struct channel *channel,
				    const struct bitcoin_tx *tx,
				    bool success,
				    const char *err,
				    struct anchor_details *adet)
{
	struct bitcoin_txid txid;

	bitcoin_txid(tx, &txid);

	/* If it's already mined, stop retransmitting, stop boosting. */
	if (wallet_transaction_height(channel->peer->ld->wallet, &txid) != 0) {
		tal_free(adet);
		return true;
	}

	/* Boost (if possible), and keep trying! */
	commit_tx_boost(channel, adet, success);
	return false;
}

static struct bitcoin_tx *sign_and_send_last(const tal_t *ctx,
					     struct lightningd *ld,
					     struct channel *channel,
					     const char *cmd_id,
					     const struct bitcoin_tx *last_tx,
					     const struct bitcoin_signature *last_sig)
{
	struct bitcoin_txid txid;
	struct anchor_details *adet;
	struct bitcoin_tx *tx;

	tx = sign_last_tx(ctx, channel, last_tx, last_sig);
	bitcoin_txid(tx, &txid);
	wallet_transaction_add(ld->wallet, tx->wtx, 0, 0);
	wallet_extract_owned_outputs(ld->wallet, tx->wtx, false, NULL, NULL);

	/* Remember anchor information for commit_tx_boost */
	adet = create_anchor_details(NULL, channel, tx);

	/* Keep broadcasting until we say stop (can fail due to dup,
	 * if they beat us to the broadcast). */
	broadcast_tx(channel, ld->topology, channel, tx, cmd_id, false, 0,
		     commit_tx_send_finished, NULL, take(adet));

	return tx;
}

/* FIXME: reorder! */
static enum watch_result funding_spent(struct channel *channel,
				       const struct bitcoin_tx *tx,
				       size_t inputnum UNUSED,
				       const struct block *block);

/* We coop-closed channel: if another inflight confirms, force close */
static enum watch_result closed_inflight_depth_cb(struct lightningd *ld,
						  const struct bitcoin_txid *txid,
						  const struct bitcoin_tx *tx,
						  unsigned int depth,
						  struct channel_inflight *inflight)
{
	if (depth == 0)
		return KEEP_WATCHING;

	/* This is now the main tx. */
	update_channel_from_inflight(ld, inflight->channel, inflight);
	channel_fail_permanent(inflight->channel,
			       REASON_UNKNOWN,
			       "Inflight tx %s confirmed after mutual close",
			       type_to_string(tmpctx, struct bitcoin_txid, txid));
	return DELETE_WATCH;
}

void drop_to_chain(struct lightningd *ld, struct channel *channel,
		   bool cooperative)
{
	struct channel_inflight *inflight;
	const char *cmd_id;

	/* If we're not already (e.g. close before channel fully open),
	 * make sure we're watching for the funding spend */
	if (!channel->funding_spend_watch) {
		log_debug(channel->log, "Adding funding_spend_watch");
		channel->funding_spend_watch = watch_txo(channel,
							 ld->topology, channel,
							 &channel->funding,
							 funding_spent);
	}

	/* If this was triggered by a close command, get a copy of the cmd id */
	cmd_id = cmd_id_from_close_command(tmpctx, ld, channel);

	/* BOLT #2:
	 *
	 * - if `next_revocation_number` is greater than expected
	 *   above, AND `your_last_per_commitment_secret` is correct for that
	 *   `next_revocation_number` minus 1:
	 *      - MUST NOT broadcast its commitment transaction.
	 */
	if (channel->future_per_commitment_point && !cooperative) {
		log_broken(channel->log,
			   "Cannot broadcast our commitment tx:"
			   " they have a future one");
	} else if (channel_state_open_uncommitted(channel->state)) {
		/* There's no commitment transaction, we can
		 * safely forget this channel */
		log_info(channel->log,
			 "Initialized channel (v2) received error"
			 ", we're deleting the channel");
	} else if (invalid_last_tx(channel->last_tx)) {
		log_broken(channel->log,
			   "Cannot broadcast our commitment tx:"
			   " it's invalid! (ancient channel?)");
	} else {
		struct bitcoin_tx *tx COMPILER_WANTS_INIT("gcc 12.3.0");

		/* We need to drop *every* commitment transaction to chain */
		if (!cooperative && !list_empty(&channel->inflights)) {
			list_for_each(&channel->inflights, inflight, list) {
				if (!inflight->last_tx)
					continue;
				tx = sign_and_send_last(tmpctx, ld, channel, cmd_id,
							inflight->last_tx,
							&inflight->last_sig);
			}
		} else
			tx = sign_and_send_last(tmpctx, ld, channel, cmd_id, channel->last_tx,
						&channel->last_sig);

		resolve_close_command(ld, channel, cooperative, tx);
	}

	/* In cooperative mode, we're assuming that we closed the right one:
	 * this might not happen if we're splicing, or dual-funding still
	 * opening.  So, if we get any unexpected inflight confirming, we
	 * force close. */
	if (cooperative) {
		list_for_each(&channel->inflights, inflight, list) {
			if (bitcoin_outpoint_eq(&inflight->funding->outpoint,
						&channel->funding)) {
				continue;
			}
			watch_txid(inflight, ld->topology,
				   &inflight->funding->outpoint.txid,
				   closed_inflight_depth_cb, inflight);
		}
	}
}

void resend_closing_transactions(struct lightningd *ld)
{
	struct peer *peer;
	struct channel *channel;
	struct peer_node_id_map_iter it;

	for (peer = peer_node_id_map_first(ld->peers, &it);
	     peer;
	     peer = peer_node_id_map_next(ld->peers, &it)) {
		list_for_each(&peer->channels, channel, list) {
			switch (channel->state) {
			case CHANNELD_AWAITING_LOCKIN:
			case CHANNELD_NORMAL:
			case DUALOPEND_OPEN_INIT:
			case DUALOPEND_OPEN_COMMIT_READY:
			case DUALOPEND_OPEN_COMMITTED:
			case DUALOPEND_AWAITING_LOCKIN:
			case CHANNELD_AWAITING_SPLICE:
			case CHANNELD_SHUTTING_DOWN:
			case CLOSINGD_SIGEXCHANGE:
			case FUNDING_SPEND_SEEN:
			case ONCHAIN:
			case CLOSED:
				continue;
			case CLOSINGD_COMPLETE:
				drop_to_chain(ld, channel, true);
				continue;
			case AWAITING_UNILATERAL:
				drop_to_chain(ld, channel, false);
				continue;
			}
			abort();
		}
	}
}

void channel_errmsg(struct channel *channel,
		    struct peer_fd *peer_fd,
		    const char *desc,
		    const u8 *err_for_them,
		    bool disconnect,
		    bool warning)
{
	/* Clean up any in-progress open attempts */
	channel_cleanup_commands(channel, desc);

	if (channel_state_uncommitted(channel->state)) {
		log_info(channel->log, "%s", "Unsaved peer failed."
			 " Deleting channel.");
		delete_channel(channel);
		return;
	}

	/* No peer_fd means a subd crash or disconnection. */
	if (!peer_fd) {
		/* If the channel is unsaved, we forget it */
		channel_fail_transient(channel, disconnect, "%s: %s",
				       channel->owner->name, desc);
		return;
	}

	/* Do we have an error to send? */
	if (err_for_them && !channel->error && !warning)
		channel->error = tal_dup_talarr(channel, u8, err_for_them);

	/* LND sends "internal error" and we close the channel.  But
	 * prior to 0.11 we would turn this into a warning, and they
	 * would recover after a reconnect.  So we downgrade, but snark
	 * about it in the logs. */
	if (!err_for_them && strends(desc, "internal error")) {
		channel_fail_transient(channel, disconnect, "%s: %s",
				       channel->owner->name,
				       "lnd sent 'internal error':"
				       " let's give it some space");
		return;
	}

	/* This is us, sending a warning.  */
	if (warning) {
		channel_fail_transient(channel, disconnect, "%s sent %s",
				       channel->owner->name,
				       desc);
		return;
	}

	/* BOLT #1:
	 *
	 * A sending node:
	 *...
	 *   - when sending `error`:
	 *     - MUST fail the channel(s) referred to by the error message.
	 *     - MAY set `channel_id` to all zero to indicate all channels.
	 */
	/* FIXME: Close if it's an all-channels error sent or rcvd */

	/* BOLT #1:
	 *
	 * A sending node:
	 *...
	 *  - when sending `error`:
	 *    - MUST fail the channel(s) referred to by the error message.
	 *    - MAY set `channel_id` to all zero to indicate all channels.
	 *...
	 * The receiving node:
	 *  - upon receiving `error`:
	 *    - if `channel_id` is all zero:
	 *       - MUST fail all channels with the sending node.
	 *    - otherwise:
	 *      - MUST fail the channel referred to by `channel_id`, if that channel is with the
	 *        sending node.
	 */

	/* FIXME: We don't close all channels */
	/* We should immediately forget the channel if we receive error during
	 * CHANNELD_AWAITING_LOCKIN if we are fundee. */
	if (!err_for_them && channel->opener == REMOTE
	    && channel->state == CHANNELD_AWAITING_LOCKIN)
		channel_fail_forget(channel, "%s: %s %s",
				    channel->owner->name,
				    err_for_them ? "sent" : "received", desc);
	else
		channel_fail_permanent(channel,
				       err_for_them ? REASON_LOCAL : REASON_PROTOCOL,
				       "%s: %s %s",
				       channel->owner->name,
				       err_for_them ? "sent" : "received", desc);
}

static void json_add_htlcs(struct lightningd *ld,
			   struct json_stream *response,
			   const struct channel *channel)
{
	/* FIXME: make per-channel htlc maps! */
	const struct htlc_in *hin;
	struct htlc_in_map_iter ini;
	const struct htlc_out *hout;
	struct htlc_out_map_iter outi;
	u32 local_feerate = get_feerate(channel->fee_states,
					channel->opener, LOCAL);

	/* FIXME: Add more fields. */
	json_array_start(response, "htlcs");
	for (hin = htlc_in_map_first(ld->htlcs_in, &ini);
	     hin;
	     hin = htlc_in_map_next(ld->htlcs_in, &ini)) {
		if (hin->key.channel != channel)
			continue;

		json_object_start(response, NULL);
		json_add_string(response, "direction", "in");
		json_add_u64(response, "id", hin->key.id);
		json_add_amount_msat(response, "amount_msat", hin->msat);
		json_add_u32(response, "expiry", hin->cltv_expiry);
		json_add_sha256(response, "payment_hash", &hin->payment_hash);
		json_add_string(response, "state",
				htlc_state_name(hin->hstate));
		if (htlc_is_trimmed(REMOTE, hin->msat, local_feerate,
				    channel->our_config.dust_limit, LOCAL,
				    channel_has(channel, OPT_ANCHOR_OUTPUTS),
				    channel_has(channel, OPT_ANCHORS_ZERO_FEE_HTLC_TX)))
			json_add_bool(response, "local_trimmed", true);
		if (hin->status != NULL)
			json_add_string(response, "status", hin->status);
		json_object_end(response);
	}

	for (hout = htlc_out_map_first(ld->htlcs_out, &outi);
	     hout;
	     hout = htlc_out_map_next(ld->htlcs_out, &outi)) {
		if (hout->key.channel != channel)
			continue;

		json_object_start(response, NULL);
		json_add_string(response, "direction", "out");
		json_add_u64(response, "id", hout->key.id);
		json_add_amount_msat(response, "amount_msat", hout->msat);
		json_add_u64(response, "expiry", hout->cltv_expiry);
		json_add_sha256(response, "payment_hash", &hout->payment_hash);
		json_add_string(response, "state",
				htlc_state_name(hout->hstate));
		if (htlc_is_trimmed(LOCAL, hout->msat, local_feerate,
				    channel->our_config.dust_limit, LOCAL,
				    channel_has(channel, OPT_ANCHOR_OUTPUTS),
				    channel_has(channel, OPT_ANCHORS_ZERO_FEE_HTLC_TX)))
			json_add_bool(response, "local_trimmed", true);
		json_object_end(response);
	}
	json_array_end(response);
}

/* Fee a commitment transaction would currently cost */
static struct amount_sat commit_txfee(const struct channel *channel,
				      struct amount_msat amount,
				      enum side side)
{
	/* FIXME: make per-channel htlc maps! */
	const struct htlc_in *hin;
	struct htlc_in_map_iter ini;
	const struct htlc_out *hout;
	struct htlc_out_map_iter outi;
	struct lightningd *ld = channel->peer->ld;
	size_t num_untrimmed_htlcs = 0;
	u32 feerate = get_feerate(channel->fee_states,
				  channel->opener, side);
	struct amount_sat dust_limit;
	struct amount_sat fee;
	bool option_anchor_outputs = channel_has(channel, OPT_ANCHOR_OUTPUTS);
	bool option_anchors_zero_fee_htlc_tx = channel_has(channel, OPT_ANCHORS_ZERO_FEE_HTLC_TX);

	if (side == LOCAL)
		dust_limit = channel->our_config.dust_limit;
	if (side == REMOTE)
		dust_limit = channel->channel_info.their_config.dust_limit;

	/* Assume we tried to add "amount" */
	if (!htlc_is_trimmed(side, amount, feerate, dust_limit, side,
			     option_anchor_outputs, option_anchors_zero_fee_htlc_tx))
		num_untrimmed_htlcs++;

	for (hin = htlc_in_map_first(ld->htlcs_in, &ini);
	     hin;
	     hin = htlc_in_map_next(ld->htlcs_in, &ini)) {
		if (hin->key.channel != channel)
			continue;
		if (!htlc_is_trimmed(!side, hin->msat, feerate, dust_limit,
				     side, option_anchor_outputs, option_anchors_zero_fee_htlc_tx))
			num_untrimmed_htlcs++;
	}
	for (hout = htlc_out_map_first(ld->htlcs_out, &outi);
	     hout;
	     hout = htlc_out_map_next(ld->htlcs_out, &outi)) {
		if (hout->key.channel != channel)
			continue;
		if (!htlc_is_trimmed(side, hout->msat, feerate, dust_limit,
				     side, option_anchor_outputs, option_anchors_zero_fee_htlc_tx))
			num_untrimmed_htlcs++;
	}

	/*
	 * BOLT #2:
	 * A sending node:
	 *...
	 * - SHOULD NOT offer `amount_msat` if, after adding that HTLC to its
	 *   commitment transaction, its remaining balance doesn't allow it to
	 *   pay the commitment transaction fee when receiving or sending a
	 *   future additional non-dust HTLC while maintaining its channel
	 *   reserve. It is recommended that this "fee spike buffer" can
	 *   handle twice the current `feerate_per_kw` to ensure
	 *   predictability between implementations.
	*/
	fee = commit_tx_base_fee(2 * feerate, num_untrimmed_htlcs + 1,
				 option_anchor_outputs, option_anchors_zero_fee_htlc_tx);

	if (option_anchor_outputs || option_anchors_zero_fee_htlc_tx) {
		/* BOLT #3:
		 * If `option_anchors` applies to the commitment
		 * transaction, also subtract two times the fixed anchor size
		 * of 330 sats from the funder (either `to_local` or
		 * `to_remote`).
		 */
		if (!amount_sat_add(&fee, fee, AMOUNT_SAT(660)))
			; /* fee is somehow astronomical already.... */
	}

	return fee;
}

static void subtract_offered_htlcs(const struct channel *channel,
				   struct amount_msat *amount)
{
	const struct htlc_out *hout;
	struct htlc_out_map_iter outi;
	struct lightningd *ld = channel->peer->ld;

	for (hout = htlc_out_map_first(ld->htlcs_out, &outi);
	     hout;
	     hout = htlc_out_map_next(ld->htlcs_out, &outi)) {
		if (hout->key.channel != channel)
			continue;
		if (!amount_msat_sub(amount, *amount, hout->msat))
			*amount = AMOUNT_MSAT(0);
	}
}

static void subtract_received_htlcs(const struct channel *channel,
				    struct amount_msat *amount)
{
	const struct htlc_in *hin;
	struct htlc_in_map_iter ini;
	struct lightningd *ld = channel->peer->ld;

	for (hin = htlc_in_map_first(ld->htlcs_in, &ini);
	     hin;
	     hin = htlc_in_map_next(ld->htlcs_in, &ini)) {
		if (hin->key.channel != channel)
			continue;
		if (!amount_msat_sub(amount, *amount, hin->msat))
			*amount = AMOUNT_MSAT(0);
	}
}

struct amount_msat channel_amount_spendable(const struct channel *channel)
{
	struct amount_msat spendable;
	bool wumbo;

	/* Compute how much we can send via this channel in one payment. */
	if (!amount_msat_sub_sat(&spendable,
				 channel->our_msat,
				 channel->channel_info.their_config.channel_reserve))
		return AMOUNT_MSAT(0);

	/* Take away any currently-offered HTLCs. */
	subtract_offered_htlcs(channel, &spendable);

	/* If we're opener, subtract txfees we'll need to spend this */
	if (channel->opener == LOCAL) {
		if (!amount_msat_sub_sat(&spendable, spendable,
					 commit_txfee(channel, spendable,
						      LOCAL)))
			return AMOUNT_MSAT(0);
	}

	/* We can't offer an HTLC less than the other side will accept. */
	if (amount_msat_less(spendable,
			     channel->channel_info.their_config.htlc_minimum))
		return AMOUNT_MSAT(0);

	wumbo = feature_negotiated(channel->peer->ld->our_features,
				   channel->peer->their_features,
				   OPT_LARGE_CHANNELS);

	/* We can't offer an HTLC over the max payment threshold either. */
	if (amount_msat_greater(spendable, chainparams->max_payment)
	    && !wumbo) {
		spendable = chainparams->max_payment;
	}

	return spendable;
}

struct amount_msat channel_amount_receivable(const struct channel *channel)
{
	struct amount_msat their_msat, receivable;
	bool wumbo;

	/* Compute how much we can receive via this channel in one payment */
	if (!amount_sat_sub_msat(&their_msat,
				 channel->funding_sats, channel->our_msat))
		their_msat = AMOUNT_MSAT(0);

	if (!amount_msat_sub_sat(&receivable,
				 their_msat,
				 channel->our_config.channel_reserve))
		return AMOUNT_MSAT(0);

	/* Take away any currently-offered HTLCs. */
	subtract_received_htlcs(channel, &receivable);

	/* If they're opener, subtract txfees they'll need to spend this */
	if (channel->opener == REMOTE) {
		if (!amount_msat_sub_sat(&receivable, receivable,
					 commit_txfee(channel,
						      receivable, REMOTE)))
			return AMOUNT_MSAT(0);
	}

	/* They can't offer an HTLC less than what we will accept. */
	if (amount_msat_less(receivable, channel->our_config.htlc_minimum))
		return AMOUNT_MSAT(0);

	wumbo = feature_negotiated(channel->peer->ld->our_features,
				   channel->peer->their_features,
				   OPT_LARGE_CHANNELS);

	/* They can't offer an HTLC over the max payment threshold either. */
	if (amount_msat_greater(receivable, chainparams->max_payment)
	    && !wumbo) {
		receivable = chainparams->max_payment;
	}

	return receivable;
}

void json_add_channel_type(struct json_stream *response,
			   const char *fieldname,
			   const struct channel_type *channel_type)
{
	const char **fnames;

	json_object_start(response, fieldname);
	json_array_start(response, "bits");
	for (size_t i = 0; i < tal_bytelen(channel_type->features) * CHAR_BIT; i++) {
		if (!feature_is_set(channel_type->features, i))
			continue;
		json_add_u64(response, NULL, i);
	}
	json_array_end(response);

	json_array_start(response, "names");
	fnames = channel_type_name(tmpctx, channel_type);
	for (size_t i = 0; i < tal_count(fnames); i++)
		json_add_string(response, NULL, fnames[i]);
	json_array_end(response);
	json_object_end(response);
}

static void json_add_channel(struct lightningd *ld,
			     struct json_stream *response, const char *key,
			     const struct channel *channel,
			     /* Only set for listpeerchannels */
			     const struct peer *peer)
{
	struct channel_stats channel_stats;
	struct amount_msat funding_msat;
	struct amount_sat peer_funded_sats;
	struct state_change_entry *state_changes;
	u32 feerate;

	json_object_start(response, key);
	if (peer) {
		json_add_node_id(response, "peer_id", &peer->id);
		json_add_bool(response, "peer_connected", peer->connected == PEER_CONNECTED);
		json_add_channel_type(response, "channel_type", channel->type);
		if (channel->ignore_fee_limits) {
			json_add_bool(response, "ignore_fee_limits", channel->ignore_fee_limits);
		}
	}
	json_add_string(response, "state", channel_state_name(channel));
	if (channel->last_tx && !invalid_last_tx(channel->last_tx)) {
		struct bitcoin_txid txid;
		bitcoin_txid(channel->last_tx, &txid);

		json_add_txid(response, "scratch_txid", &txid);
		json_add_amount_sat_msat(response, "last_tx_fee_msat",
					 bitcoin_tx_compute_fee(channel->last_tx));
	}

	json_object_start(response, "feerate");
	feerate = get_feerate(channel->fee_states, channel->opener, LOCAL);
	json_add_u32(response, feerate_style_name(FEERATE_PER_KSIPA), feerate);
	json_add_u32(response, feerate_style_name(FEERATE_PER_KBYTE),
		     feerate_to_style(feerate, FEERATE_PER_KBYTE));
	json_object_end(response);

	if (channel->owner)
		json_add_string(response, "owner", channel->owner->name);

	if (channel->scid)
		json_add_short_channel_id(response, "short_channel_id",
					  channel->scid);

	/* If there is any way we can use the channel we'd better have
	 * a direction attached. Technically we could always add it,
	 * as it's just the lexicographic order between node_ids, but
	 * why bother if we can't use it? */
	if (channel->scid || channel->alias[LOCAL] || channel->alias[REMOTE])
		json_add_num(response, "direction",
			     node_id_idx(&ld->id, &channel->peer->id));

	json_add_string(response, "channel_id",
			type_to_string(tmpctx, struct channel_id, &channel->cid));
	json_add_txid(response, "funding_txid", &channel->funding.txid);
	json_add_num(response, "funding_outnum", channel->funding.n);

	if (!list_empty(&channel->inflights)) {
		struct channel_inflight *initial, *inflight;
		u32 last_feerate, next_feerate;

		initial = list_top(&channel->inflights,
				   struct channel_inflight, list);
		json_add_string(response, "initial_feerate",
			        tal_fmt(tmpctx, "%d%s",
					initial->funding->feerate,
					feerate_style_name(FEERATE_PER_KSIPA)));

		last_feerate = channel_last_funding_feerate(channel);
		assert(last_feerate > 0);
		json_add_string(response, "last_feerate",
				tal_fmt(tmpctx, "%d%s", last_feerate,
					feerate_style_name(FEERATE_PER_KSIPA)));

		/* BOLT-9e7723387c8859b511e178485605a0b9133b9869 #2:
		 * - MUST set `funding_feerate_perkw` greater than or equal to
		 *   65/64 times the last sent `funding_feerate_perkw`
		 *   rounded down.
		 */
		next_feerate = last_feerate * 65 / 64;
		assert(next_feerate > last_feerate);
		json_add_string(response, "next_feerate",
				tal_fmt(tmpctx, "%d%s", next_feerate,
					feerate_style_name(FEERATE_PER_KSIPA)));

		/* List the inflights */
		json_array_start(response, "inflight");
		list_for_each(&channel->inflights, inflight, list) {
			struct bitcoin_txid txid;

			json_object_start(response, NULL);
			json_add_txid(response, "funding_txid",
				      &inflight->funding->outpoint.txid);
			json_add_num(response, "funding_outnum",
				     inflight->funding->outpoint.n);
			json_add_string(response, "feerate",
					tal_fmt(tmpctx, "%d%s",
						inflight->funding->feerate,
						feerate_style_name(
							FEERATE_PER_KSIPA)));
			json_add_amount_sat_msat(response,
						 "total_funding_msat",
						 inflight->funding->total_funds);
			json_add_amount_sat_msat(response,
						 "our_funding_msat",
						 inflight->funding->our_funds);
			json_add_s64(response,
				     "splice_amount",
				     inflight->funding->splice_amnt);
			/* Add the expected commitment tx id also */
			if (inflight->last_tx) {
				bitcoin_txid(inflight->last_tx, &txid);
				json_add_txid(response, "scratch_txid", &txid);
			}
			json_object_end(response);
		}
		json_array_end(response);
	}

	if (channel->shutdown_scriptpubkey[LOCAL]) {
		char *addr = encode_scriptpubkey_to_addr(tmpctx,
					chainparams,
					channel->shutdown_scriptpubkey[LOCAL]);
		if (addr)
			json_add_string(response, "close_to_addr", addr);
		json_add_hex_talarr(response, "close_to",
				    channel->shutdown_scriptpubkey[LOCAL]);
	}

	json_add_bool(
	    response, "private",
	    !(channel->channel_flags & CHANNEL_FLAGS_ANNOUNCE_CHANNEL));

	/* opener and closer */
	assert(channel->opener != NUM_SIDES);
	json_add_string(response, "opener", channel->opener == LOCAL ?
					    "local" : "remote");
	if (channel->closer != NUM_SIDES)
		json_add_string(response, "closer", channel->closer == LOCAL ?
						    "local" : "remote");

	if (channel->alias[LOCAL] || channel->alias[REMOTE]) {
		json_object_start(response, "alias");
		if (channel->alias[LOCAL])
			json_add_short_channel_id(response, "local",
						  channel->alias[LOCAL]);
		if (channel->alias[REMOTE])
			json_add_short_channel_id(response, "remote",
						  channel->alias[REMOTE]);
		json_object_end(response);
	}

	json_array_start(response, "features");
	if (channel_has(channel, OPT_STATIC_REMOTEKEY))
		json_add_string(response, NULL, "option_static_remotekey");
	if (channel_has(channel, OPT_ANCHOR_OUTPUTS))
		json_add_string(response, NULL, "option_anchor_outputs");
	if (channel_has(channel, OPT_ANCHORS_ZERO_FEE_HTLC_TX))
		json_add_string(response, NULL, "option_anchors_zero_fee_htlc_tx");
	if (channel_has(channel, OPT_ZEROCONF))
		json_add_string(response, NULL, "option_zeroconf");
	if (channel_has(channel, OPT_SCID_ALIAS))
		json_add_string(response, NULL, "option_scid_alias");
	json_array_end(response);

	if (!amount_sat_sub(&peer_funded_sats, channel->funding_sats,
			    channel->our_funds)) {
		log_broken(channel->log,
			   "Overflow subtracing funding %s, our funds %s",
			   type_to_string(tmpctx, struct amount_sat,
					  &channel->funding_sats),
			   type_to_string(tmpctx, struct amount_sat,
					  &channel->our_funds));
		peer_funded_sats = AMOUNT_SAT(0);
	}

	json_object_start(response, "funding");

	if (channel->lease_commit_sig) {
		struct amount_sat funds, total;
		if (!amount_msat_to_sat(&funds, channel->push)) {
			log_broken(channel->log,
				   "Can't convert channel->push %s to sats"
				   " (lease fees?)",
				   type_to_string(tmpctx, struct amount_msat,
						  &channel->push));
			funds = AMOUNT_SAT(0);
		}

		if (channel->opener == LOCAL) {
			if (!amount_sat_add(&total, funds, channel->our_funds)) {
				log_broken(channel->log,
					   "Overflow adding our_funds to push");
				total = channel->our_funds;
			}
			json_add_amount_sat_msat(response, "local_funds_msat", total);

			if (!amount_sat_sub(&total, peer_funded_sats, funds)) {
				log_broken(channel->log,
					   "Underflow sub'ing push from"
					   " peer's funds");
				total = peer_funded_sats;
			}
			json_add_amount_sat_msat(response, "remote_funds_msat", total);

			json_add_amount_msat(response, "fee_paid_msat",
					     channel->push);
		} else {
			if (!amount_sat_add(&total, peer_funded_sats, funds)) {
				log_broken(channel->log,
					   "Overflow adding peer funds to push");
				total = peer_funded_sats;
			}
			json_add_amount_sat_msat(response, "remote_funds_msat", total);

			if (!amount_sat_sub(&total, channel->our_funds, funds)) {
				log_broken(channel->log,
					   "Underflow sub'ing push from"
					   " our_funds");
				total = channel->our_funds;
			}
			json_add_amount_sat_msat(response, "local_funds_msat", total);
			json_add_amount_msat(response, "fee_rcvd_msat",
					     channel->push);
		}

	} else {
		json_add_amount_sat_msat(response, "local_funds_msat",
				  channel->our_funds);
		json_add_amount_sat_msat(response, "remote_funds_msat",
				  peer_funded_sats);
		json_add_amount_msat(response, "pushed_msat",
				     channel->push);
	}

	json_object_end(response);

	if (!amount_sat_to_msat(&funding_msat, channel->funding_sats)) {
		log_broken(channel->log,
			   "Overflow converting funding %s",
			   type_to_string(tmpctx, struct amount_sat,
					  &channel->funding_sats));
		funding_msat = AMOUNT_MSAT(0);
	}
	json_add_amount_msat(response, "to_us_msat", channel->our_msat);
	json_add_amount_msat(response,
			     "min_to_us_msat", channel->msat_to_us_min);
	json_add_amount_msat(response,
			     "max_to_us_msat", channel->msat_to_us_max);
	json_add_amount_msat(response, "total_msat", funding_msat);

	/* routing fees */
	json_add_amount_msat(response, "fee_base_msat",
			     amount_msat(channel->feerate_base));
	json_add_u32(response, "fee_proportional_millionths",
		     channel->feerate_ppm);

	/* channel config */
	json_add_amount_sat_msat(response, "dust_limit_msat",
				 channel->our_config.dust_limit);
	json_add_amount_msat(response, "max_total_htlc_in_msat",
			     channel->our_config.max_htlc_value_in_flight);

	/* The `channel_reserve_satoshis` is imposed on
	 * the *other* side (see `channel_reserve_msat`
	 * function in, it uses `!side` to flip sides).
	 * So our configuration `channel_reserve_satoshis`
	 * is imposed on their side, while their
	 * configuration `channel_reserve_satoshis` is
	 * imposed on ours. */
	json_add_amount_sat_msat(response,
				 "their_reserve_msat",
				 channel->our_config.channel_reserve);
	json_add_amount_sat_msat(response,
				 "our_reserve_msat",
				 channel->channel_info.their_config.channel_reserve);

	/* append spendable to JSON output */
	json_add_amount_msat(response,
			     "spendable_msat",
			     channel_amount_spendable(channel));

	/* append receivable to JSON output */
	json_add_amount_msat(response,
			     "receivable_msat",
			     channel_amount_receivable(channel));

	json_add_amount_msat(response,
			     "minimum_htlc_in_msat",
			     channel->our_config.htlc_minimum);
	json_add_amount_msat(response,
			     "minimum_htlc_out_msat",
			     channel->htlc_minimum_msat);
	json_add_amount_msat(response,
			     "maximum_htlc_out_msat",
			     channel->htlc_maximum_msat);

	/* The `to_self_delay` is imposed on the *other*
	 * side, so our configuration `to_self_delay` is
	 * imposed on their side, while their configuration
	 * `to_self_delay` is imposed on ours. */
	json_add_num(response, "their_to_self_delay",
		     channel->our_config.to_self_delay);
	json_add_num(response, "our_to_self_delay",
		     channel->channel_info.their_config.to_self_delay);
	json_add_num(response, "max_accepted_htlcs",
		     channel->our_config.max_accepted_htlcs);

	state_changes = wallet_state_change_get(ld->wallet, tmpctx, channel->dbid);
	json_array_start(response, "state_changes");
	for (size_t i = 0; i < tal_count(state_changes); i++) {
		json_object_start(response, NULL);
		json_add_timeiso(response, "timestamp",
				 state_changes[i].timestamp);
		json_add_string(response, "old_state",
				channel_state_str(state_changes[i].old_state));
		json_add_string(response, "new_state",
				channel_state_str(state_changes[i].new_state));
		json_add_string(response, "cause",
				channel_change_state_reason_str(state_changes[i].cause));
		json_add_string(response, "message", state_changes[i].message);
		json_object_end(response);
	}
	json_array_end(response);

	json_array_start(response, "status");
	for (size_t i = 0; i < ARRAY_SIZE(channel->billboard.permanent); i++) {
		if (!channel->billboard.permanent[i])
			continue;
		json_add_string(response, NULL,
				channel->billboard.permanent[i]);
	}
	if (channel->billboard.transient)
		json_add_string(response, NULL, channel->billboard.transient);
	json_array_end(response);

	/* Provide channel statistics */
	wallet_channel_stats_load(ld->wallet, channel->dbid, &channel_stats);
	json_add_u64(response, "in_payments_offered",
		     channel_stats.in_payments_offered);
	json_add_amount_msat(response,
			     "in_offered_msat",
			     channel_stats.in_msatoshi_offered);
	json_add_u64(response, "in_payments_fulfilled",
		     channel_stats.in_payments_fulfilled);
	json_add_amount_msat(response,
			     "in_fulfilled_msat",
			     channel_stats.in_msatoshi_fulfilled);
	json_add_u64(response, "out_payments_offered",
		     channel_stats.out_payments_offered);
	json_add_amount_msat(response,
			     "out_offered_msat",
			     channel_stats.out_msatoshi_offered);
	json_add_u64(response, "out_payments_fulfilled",
		     channel_stats.out_payments_fulfilled);
	json_add_amount_msat(response,
			     "out_fulfilled_msat",
			     channel_stats.out_msatoshi_fulfilled);

	json_add_htlcs(ld, response, channel);
	json_object_end(response);
}

struct peer_connected_hook_payload {
	struct lightningd *ld;
	struct wireaddr_internal addr;
	struct wireaddr *remote_addr;
	bool incoming;
	/* We don't keep a pointer to peer: it might be freed! */
	struct node_id peer_id;
	u8 *error;
};

static void
peer_connected_serialize(struct peer_connected_hook_payload *payload,
			 struct json_stream *stream, struct plugin *plugin)
{
	json_object_start(stream, "peer");
	json_add_node_id(stream, "id", &payload->peer_id);
	json_add_string(stream, "direction", payload->incoming ? "in" : "out");
	json_add_string(
	    stream, "addr",
	    type_to_string(stream, struct wireaddr_internal, &payload->addr));
	if (payload->remote_addr)
		json_add_string(
		    stream, "remote_addr",
		    type_to_string(stream, struct wireaddr, payload->remote_addr));
	/* Since this is start of hook, peer is always in table! */
	json_add_hex_talarr(stream, "features",
			    peer_by_id(payload->ld, &payload->peer_id)
			    ->their_features);
	json_object_end(stream); /* .peer */
}

/* Talk to connectd about an active channel */
static void connect_activate_subd(struct lightningd *ld, struct channel *channel)
{
	const u8 *error;
	int fds[2];

	/* If we have a canned error for this channel, send it now */
	if (channel->error) {
		error = channel->error;
		goto send_error;
	}

	switch (channel->state) {
	case ONCHAIN:
	case FUNDING_SPEND_SEEN:
	case CLOSINGD_COMPLETE:
	case CLOSED:
	case DUALOPEND_OPEN_INIT:
		/* Channel is active */
		abort();
	case AWAITING_UNILATERAL:
		/* channel->error is not saved in db, so this can
		 * happen if we restart. */
		error = towire_errorfmt(tmpctx, &channel->cid,
					"Awaiting unilateral close");
		goto send_error;

	case DUALOPEND_OPEN_COMMIT_READY:
	case DUALOPEND_OPEN_COMMITTED:
	case DUALOPEND_AWAITING_LOCKIN:
		assert(!channel->owner);
		if (socketpair(AF_LOCAL, SOCK_STREAM, 0, fds) != 0) {
			log_broken(channel->log,
				   "Failed to create socketpair: %s",
				   strerror(errno));
			error = towire_warningfmt(tmpctx, &channel->cid,
						  "Trouble in paradise?");
			goto send_error;
		}
		if (peer_restart_dualopend(channel->peer,
					   new_peer_fd(tmpctx, fds[0]),
					   channel, false))
			goto tell_connectd;
		close(fds[1]);
		return;

	case CHANNELD_AWAITING_LOCKIN:
	case CHANNELD_NORMAL:
	case CHANNELD_AWAITING_SPLICE:
	case CHANNELD_SHUTTING_DOWN:
	case CLOSINGD_SIGEXCHANGE:
		assert(!channel->owner);
		if (socketpair(AF_LOCAL, SOCK_STREAM, 0, fds) != 0) {
			log_broken(channel->log,
				   "Failed to create socketpair: %s",
				   strerror(errno));
			error = towire_warningfmt(tmpctx, &channel->cid,
						  "Trouble in paradise?");
			goto send_error;
		}
		if (peer_start_channeld(channel,
					new_peer_fd(tmpctx, fds[0]),
					NULL, true,
					NULL)) {
			goto tell_connectd;
		}
		close(fds[1]);
		return;
	}
	abort();

tell_connectd:
	subd_send_msg(ld->connectd,
		      take(towire_connectd_peer_connect_subd(NULL,
							     &channel->peer->id,
							     channel->peer->connectd_counter,
							     &channel->cid)));
	subd_send_fd(ld->connectd, fds[1]);
	return;

send_error:
	log_debug(channel->log, "Telling connectd to send error %s",
		       tal_hex(tmpctx, error));
	/* Get connectd to send error and close. */
	subd_send_msg(ld->connectd,
		      take(towire_connectd_peer_final_msg(NULL, &channel->peer->id,
							  channel->peer->connectd_counter,
							  error)));
}

static void peer_connected_hook_final(struct peer_connected_hook_payload *payload STEALS)
{
	struct lightningd *ld = payload->ld;
	struct channel *channel;
	struct wireaddr_internal addr = payload->addr;
	struct peer *peer;
	u8 *error;

	/* Whatever happens, we free payload (it's currently a child
	 * of the peer, which may be freed if we fail to start
	 * subd). */
	tal_steal(tmpctx, payload);

	/* Peer might have gone away while we were waiting for plugin! */
	peer = peer_by_id(ld, &payload->peer_id);
	if (!peer)
		return;

	/* If we disconnected in the meantime, forget about it.
	 * (disconnect will have failed any connect commands).
	 * And if it has reconnected, and we're the second time the
	 * hook has been called, it'll be PEER_CONNECTED. */
	if (peer->connected != PEER_CONNECTING)
		return;

	/* Check for specific errors of a hook */
	if (payload->error) {
		error = payload->error;
		goto send_error;
	}

	/* Now we finally consider ourselves connected! */
	assert(peer->connected == PEER_CONNECTING);
	peer->connected = PEER_CONNECTED;

	/* Succeed any connect() commands */
	connect_succeeded(ld, peer, payload->incoming, &payload->addr);

	/* Notify anyone who cares */
	notify_connect(ld, &peer->id, payload->incoming, &addr);

	/* Developer hack to fail all channels on permfail line. */
	if (dev_disconnect_permanent(ld)) {
		list_for_each(&peer->channels, channel, list) {
			channel_fail_permanent(channel, REASON_LOCAL,
					       "dev_disconnect permfail");
			subd_send_msg(ld->connectd,
				      take(towire_connectd_peer_final_msg(NULL, &peer->id,
									  peer->connectd_counter,
									  channel->error)));
		}
		return;
	}

	/* connect appropriate subds for all (active) channels! */
	list_for_each(&peer->channels, channel, list) {
		/* FIXME: It can race by opening a channel before this! */
		if (channel_state_wants_peercomms(channel->state) && !channel->owner) {
			log_debug(channel->log, "Peer has reconnected, state %s: connecting subd",
				  channel_state_name(channel));

			connect_activate_subd(ld, channel);
		}
	}
	return;

send_error:
	log_peer_debug(ld->log, &peer->id, "Telling connectd to send error %s",
		       tal_hex(tmpctx, error));
	/* Get connectd to send error and close. */
	subd_send_msg(ld->connectd,
		      take(towire_connectd_peer_final_msg(NULL, &peer->id,
							  peer->connectd_counter,
							  error)));
}

static bool
peer_connected_hook_deserialize(struct peer_connected_hook_payload *payload,
				const char *buffer,
				const jsmntok_t *toks)
{
	struct lightningd *ld = payload->ld;

	/* already rejected by prior plugin hook in the chain */
	if (payload->error != NULL)
		return true;

	if (!toks || !buffer)
		return true;

	/* If we had a hook, interpret result. */
	const jsmntok_t *t_res = json_get_member(buffer, toks, "result");
	const jsmntok_t *t_err = json_get_member(buffer, toks, "error_message");

	/* fail */
	if (!t_res)
		fatal("Plugin returned an invalid response to the "
		      "peer_connected hook: %s", buffer);

	/* reject */
	if (json_tok_streq(buffer, t_res, "disconnect")) {
		payload->error = (u8*)"";
		if (t_err) {
			payload->error = towire_warningfmt(tmpctx, NULL, "%.*s",
							   t_err->end - t_err->start,
							   buffer + t_err->start);
		}
		log_debug(ld->log, "peer_connected hook rejects and says '%s'",
			  payload->error);
		/* At this point we suppress other plugins in the chain and
		 * directly move to final */
		peer_connected_hook_final(payload);
		return false;
	} else if (!json_tok_streq(buffer, t_res, "continue"))
		fatal("Plugin returned an invalid response to the "
		      "peer_connected hook: %s", buffer);

	/* call next hook */
	return true;
}

/* Compare and store `remote_addr` and the `peer_id` that reported it.
 * If new address was reported by at least one other, do node_announcement */
static void update_remote_addr(struct lightningd *ld,
			       const struct wireaddr *remote_addr,
			       const struct node_id peer_id)
{
	/* failsafe to prevent privacy leakage. */
	if (ld->always_use_proxy ||
	    ld->config.ip_discovery == OPT_AUTOBOOL_FALSE)
		return;

	switch (remote_addr->type) {
	case ADDR_TYPE_IPV4:
		/* init pointers first time */
		if (ld->remote_addr_v4 == NULL) {
			ld->remote_addr_v4 = tal_dup(ld, struct wireaddr,
						     remote_addr);
			ld->remote_addr_v4_peer = peer_id;
		}
		/* if updated by the same peer just remember the latest addr */
		if (node_id_eq(&ld->remote_addr_v4_peer, &peer_id)) {
			*ld->remote_addr_v4 = *remote_addr;
			break;
		}
		/* tell gossip we have a valid update */
		if (wireaddr_eq_without_port(ld->remote_addr_v4, remote_addr)) {
			ld->discovered_ip_v4 = tal_dup(ld, struct wireaddr,
						       ld->remote_addr_v4);
			ld->discovered_ip_v4->port = ld->config.ip_discovery_port;
			subd_send_msg(ld->gossip, towire_gossipd_discovered_ip(
							  tmpctx,
							  ld->discovered_ip_v4));
		}
		/* store latest values */
		*ld->remote_addr_v4 = *remote_addr;
		ld->remote_addr_v4_peer = peer_id;
		break;
	case ADDR_TYPE_IPV6:
		/* same code :s/4/6/ without the comments ;) */
		if (ld->remote_addr_v6 == NULL) {
			ld->remote_addr_v6 = tal_dup(ld, struct wireaddr,
						     remote_addr);
			ld->remote_addr_v6_peer = peer_id;
		}
		if (node_id_eq(&ld->remote_addr_v6_peer, &peer_id)) {
			*ld->remote_addr_v6 = *remote_addr;
			break;
		}
		if (wireaddr_eq_without_port(ld->remote_addr_v6, remote_addr)) {
			ld->discovered_ip_v6 = tal_dup(ld, struct wireaddr,
						       ld->remote_addr_v6);
			ld->discovered_ip_v6->port = ld->config.ip_discovery_port;
			subd_send_msg(ld->gossip, towire_gossipd_discovered_ip(
							  tmpctx,
							  ld->discovered_ip_v6));
		}
		*ld->remote_addr_v6 = *remote_addr;
		ld->remote_addr_v6_peer = peer_id;
		break;

	/* ignore all other cases */
	case ADDR_TYPE_TOR_V2_REMOVED:
	case ADDR_TYPE_TOR_V3:
	case ADDR_TYPE_DNS:
		break;
	}
}

REGISTER_PLUGIN_HOOK(peer_connected,
		     peer_connected_hook_deserialize,
		     peer_connected_hook_final,
		     peer_connected_serialize,
		     struct peer_connected_hook_payload *);

/* Connectd tells us a peer has connected: it never hands us duplicates, since
 * it holds them until we say peer_disconnected. */
void peer_connected(struct lightningd *ld, const u8 *msg)
{
	struct node_id id;
	u8 *their_features;
	struct peer *peer;
	struct peer_connected_hook_payload *hook_payload;
	u64 connectd_counter;
	const char *cmd_id;

	hook_payload = tal(NULL, struct peer_connected_hook_payload);
	hook_payload->ld = ld;
	hook_payload->error = NULL;
	if (!fromwire_connectd_peer_connected(hook_payload, msg,
					      &id, &connectd_counter,
					      &hook_payload->addr,
					      &hook_payload->remote_addr,
					      &hook_payload->incoming,
					      &their_features))
		fatal("Connectd gave bad CONNECT_PEER_CONNECTED message %s",
		      tal_hex(msg, msg));

	/* When a peer disconnects, we give subds time to clean themselves up
	 * (this lets connectd ensure they've seen the final messages).  But
	 * now it's reconnected, we've gotta force them out. */
	peer_channels_cleanup(ld, &id);

	/* If we're already dealing with this peer, hand off to correct
	 * subdaemon.  Otherwise, we'll hand to openingd to wait there. */
	peer = peer_by_id(ld, &id);
	if (!peer)
		peer = new_peer(ld, 0, &id, &hook_payload->addr,
				take(their_features), hook_payload->incoming);
	else {
		tal_free(peer->their_features);
		peer->their_features = tal_steal(peer, their_features);
	}

	/* We track this, because messages can race between connectd and us.
	 * For example, we could tell it to attach a subd, but it's actually
	 * already reconnected: we would tell it again when we read the
	 * "peer_connected" message, and it would get upset (plus, our first
	 * subd wouldn't die as expected.  So we echo this back to connectd
	 * on peer commands, and it knows to ignore if it's wrong. */
	peer->connectd_counter = connectd_counter;

	/* We mark peer in "connecting" state until hooks have passed. */
	assert(peer->connected == PEER_DISCONNECTED);
	peer->connected = PEER_CONNECTING;

	/* Update peer address and direction */
	peer->addr = hook_payload->addr;
	peer->connected_incoming = hook_payload->incoming;
	if (peer->remote_addr)
		tal_free(peer->remote_addr);
	peer->remote_addr = NULL;
	hook_payload->peer_id = id;

	/* If there's a connect command, use its id as basis for hook id */
	cmd_id = connect_any_cmd_id(tmpctx, ld, peer);

	/* Log and update remote_addr for Nat/IP discovery. */
	if (hook_payload->remote_addr) {
		log_peer_debug(ld->log, &id, "Peer says it sees our address as: %s",
			       fmt_wireaddr(tmpctx, hook_payload->remote_addr));
		peer->remote_addr = tal_dup(peer, struct wireaddr,
					    hook_payload->remote_addr);
		/* Currently only from peers we have a channel with, until we
		 * do stuff like probing for remote_addr to a random node. */
		if (!list_empty(&peer->channels))
			update_remote_addr(ld, hook_payload->remote_addr, id);
	}

	plugin_hook_call_peer_connected(ld, cmd_id, hook_payload);
}

/* connectd tells us a peer has a message and we've not already attached
 * a subd.  Normally this is a race, but it happens for real when opening
 * a new channel, or referring to a channel we no longer want to talk to
 * it about. */
void peer_spoke(struct lightningd *ld, const u8 *msg)
{
	struct node_id id;
	u16 msgtype;
	u64 connectd_counter;
	struct channel *channel;
	struct channel_id channel_id;
	struct peer *peer;
	bool dual_fund;
	u8 *error;
	int fds[2];
	char *errmsg;

	if (!fromwire_connectd_peer_spoke(msg, msg, &id, &connectd_counter, &msgtype, &channel_id, &errmsg))
		fatal("Connectd gave bad CONNECTD_PEER_SPOKE message %s",
		      tal_hex(msg, msg));

	/* We must know it, and it must be the right connectd_id */
	peer = peer_by_id(ld, &id);
	assert(peer->connectd_counter == connectd_counter);

	/* Do we know what channel they're talking about? */
	channel = find_channel_by_id(peer, &channel_id);
	if (channel) {
		/* If we have a canned error for this channel, send it now */
		if (channel->error) {
			error = channel->error;
			goto send_error;
		}

		if (channel_state_wants_peercomms(channel->state)) {
			/* If they send an error, handle it immediately. */
			if (errmsg) {
				channel_fail_permanent(channel, REASON_REMOTE,
						       "They sent %s", errmsg);
				return;
			}

			/* If channel is active there are two possibilities:
			 * 1. We have started subd, but channeld hasn't processed
			 *    the connectd_peer_connect_subd message yet.
			 * 2. subd exited */
			if (channel->owner) {
				/* We raced... */
				return;
			}

			log_debug(channel->log, "channel already active");
			if (channel->state == DUALOPEND_AWAITING_LOCKIN) {
				if (socketpair(AF_LOCAL, SOCK_STREAM, 0, fds) != 0) {
					log_broken(ld->log,
						   "Failed to create socketpair: %s",
						   strerror(errno));
					error = towire_warningfmt(tmpctx, &channel_id,
								  "Trouble in paradise?");
					goto send_error;
				}
				if (peer_restart_dualopend(peer, new_peer_fd(tmpctx, fds[0]), channel, false))
					goto tell_connectd;
				/* FIXME: Send informative error? */
				close(fds[1]);
			}
			return;
		}

		if (msgtype == WIRE_CHANNEL_REESTABLISH) {
			log_debug(channel->log,
				  "Reestablish on %s channel: using channeld to reply",
				  channel_state_name(channel));
			if (socketpair(AF_LOCAL, SOCK_STREAM, 0, fds) != 0) {
				log_broken(channel->log,
					   "Failed to create socketpair: %s",
					   strerror(errno));
				error = towire_warningfmt(tmpctx, &channel->cid,
							  "Trouble in paradise?");
				goto send_error;
			}
			if (peer_start_channeld(channel, new_peer_fd(tmpctx, fds[0]), NULL, true, true)) {
				goto tell_connectd;
			}
			/* FIXME: Send informative error? */
			close(fds[1]);
			return;
		}

		/* Send generic error. */
		error = towire_errorfmt(tmpctx, &channel_id,
					"channel in state %s",
					channel_state_name(channel));
		goto send_error;
	}

	dual_fund = feature_negotiated(ld->our_features,
				       peer->their_features,
				       OPT_DUAL_FUND);

	/* OK, it's an unknown channel.  Create a new one if they're trying. */
	switch (msgtype) {
	case WIRE_OPEN_CHANNEL:
		if (dual_fund) {
			error = towire_errorfmt(tmpctx, &channel_id,
						"OPT_DUAL_FUND: cannot use open_channel");
			goto send_error;
		}
		if (peer->uncommitted_channel) {
			error = towire_errorfmt(tmpctx, &channel_id,
						"Multiple simulteneous opens not supported");
			goto send_error;
		}
		peer->uncommitted_channel = new_uncommitted_channel(peer);
		peer->uncommitted_channel->cid = channel_id;
		if (socketpair(AF_LOCAL, SOCK_STREAM, 0, fds) != 0) {
			log_broken(ld->log,
				   "Failed to create socketpair: %s",
				   strerror(errno));
			error = towire_warningfmt(tmpctx, &channel_id,
						  "Trouble in paradise?");
			goto send_error;
		}
		if (peer_start_openingd(peer, new_peer_fd(tmpctx, fds[0]))) {
			goto tell_connectd;
		}
		/* FIXME: Send informative error? */
		close(fds[1]);
		return;

	case WIRE_OPEN_CHANNEL2:
		if (!dual_fund) {
			error = towire_errorfmt(tmpctx, &channel_id,
						"Didn't negotiate OPT_DUAL_FUND: cannot use open_channel2");
			goto send_error;
		}
		channel = new_unsaved_channel(peer,
					      peer->ld->config.fee_base,
					      peer->ld->config.fee_per_satoshi);
		channel->cid = channel_id;
		if (socketpair(AF_LOCAL, SOCK_STREAM, 0, fds) != 0) {
			log_broken(ld->log,
				   "Failed to create socketpair: %s",
				   strerror(errno));
			error = towire_warningfmt(tmpctx, &channel_id,
						  "Trouble in paradise?");
			goto send_error;
		}
		if (peer_start_dualopend(peer, new_peer_fd(tmpctx, fds[0]), channel))
			goto tell_connectd;
		/* FIXME: Send informative error? */
		close(fds[1]);
		return;
	}

	/* Weird message?  Log and reply with error. */
	log_peer_unusual(ld->log, &peer->id,
			 "Unknown channel %s for %s",
			 type_to_string(tmpctx, struct channel_id,
					&channel_id),
			 peer_wire_name(msgtype));
	error = towire_errorfmt(tmpctx, &channel_id,
				"Unknown channel for %s", peer_wire_name(msgtype));

send_error:
	log_peer_debug(ld->log, &peer->id, "Telling connectd to send error %s",
		       tal_hex(tmpctx, error));
	/* Get connectd to send error and close. */
	subd_send_msg(ld->connectd,
		      take(towire_connectd_peer_final_msg(NULL, &peer->id,
							  peer->connectd_counter,
							  error)));
	return;

tell_connectd:
	subd_send_msg(ld->connectd,
		      take(towire_connectd_peer_connect_subd(NULL, &id,
							     peer->connectd_counter,
							     &channel_id)));
	subd_send_fd(ld->connectd, fds[1]);
}

struct disconnect_command {
	struct list_node list;
	/* Command structure. This is the parent of the close command. */
	struct command *cmd;
	/* node being disconnected. */
	struct node_id id;
};

static void destroy_disconnect_command(struct disconnect_command *dc)
{
	list_del(&dc->list);
}

void peer_disconnect_done(struct lightningd *ld, const u8 *msg)
{
	struct node_id id;
	u64 connectd_counter;
	struct disconnect_command *i, *next;
	struct peer *p;

	if (!fromwire_connectd_peer_disconnect_done(msg, &id, &connectd_counter))
		fatal("Connectd gave bad PEER_DISCONNECT_DONE message %s",
		      tal_hex(msg, msg));

	/* If we still have peer, it's disconnected now */
	/* FIXME: We should keep peers until it tells us they're disconnected,
	 * and not free when no more channels. */
	p = peer_by_id(ld, &id);
	if (p) {
		assert(p->connectd_counter == connectd_counter);
		log_peer_debug(ld->log, &id, "peer_disconnect_done");
		p->connected = PEER_DISCONNECTED;
	}

	/* If you were trying to connect, it failed. */
	connect_failed_disconnect(ld, &id,
				  p && !p->connected_incoming ? &p->addr : NULL);

	/* Fire off plugin notifications */
	notify_disconnect(ld, &id);

	/* Wake any disconnect commands (removes self from list) */
	list_for_each_safe(&ld->disconnect_commands, i, next, list) {
		if (!node_id_eq(&i->id, &id))
			continue;

		was_pending(command_success(i->cmd,
					    json_stream_success(i->cmd)));
	}

	/* If connection was only thing keeping it, this will delete it. */
	if (p)
		maybe_delete_peer(p);
}

void update_channel_from_inflight(struct lightningd *ld,
				  struct channel *channel,
				  const struct channel_inflight *inflight)
{
	struct wally_psbt *psbt_copy;

	channel->funding = inflight->funding->outpoint;
	channel->funding_sats = inflight->funding->total_funds;

	channel->our_funds = inflight->funding->our_funds;

	if (!amount_sat_add_sat_s64(&channel->our_funds, channel->our_funds,
				    inflight->funding->splice_amnt)) {

		channel_fail_permanent(channel,
				       REASON_LOCAL,
				       "Updaing channel view for splice causes"
				       " an invalid satoshi amount wrapping,"
				       " channel: %s, initial funds: %s, splice"
				       " banace change: %s",
				       type_to_string(tmpctx, struct channel_id,
						      &channel->cid),
				       type_to_string(tmpctx, struct amount_sat,
						      &channel->our_funds),
				       inflight->funding->splice_amnt);
	}

	/* Lease infos ! */
	channel->lease_expiry = inflight->lease_expiry;
	channel->push = inflight->lease_fee;
	tal_free(channel->lease_commit_sig);
	channel->lease_commit_sig
		= tal_dup_or_null(channel, secp256k1_ecdsa_signature, inflight->lease_commit_sig);
	channel->lease_chan_max_msat = inflight->lease_chan_max_msat;
	channel->lease_chan_max_ppt = inflight->lease_chan_max_ppt;

	tal_free(channel->blockheight_states);
	channel->blockheight_states = new_height_states(channel,
							channel->opener,
							&inflight->lease_blockheight_start);

	/* Make a 'clone' of this tx */
	psbt_copy = clone_psbt(channel, inflight->last_tx->psbt);
	channel_set_last_tx(channel,
			    bitcoin_tx_with_psbt(channel, psbt_copy),
			    &inflight->last_sig);

	/* Update the reserve */
	channel_update_reserve(channel,
			       &channel->channel_info.their_config,
			       inflight->funding->total_funds);

	wallet_channel_save(ld->wallet, channel);
}

static enum watch_result funding_depth_cb(struct lightningd *ld,
					  const struct bitcoin_txid *txid,
					  const struct bitcoin_tx *tx,
					  unsigned int depth,
					  struct channel *channel)
{
	/* This is stub channel, we don't activate anything! */
	if (is_stub_scid(channel->scid))
		return DELETE_WATCH;

	/* We only use this to watch the current funding tx */
	assert(bitcoin_txid_eq(txid, &channel->funding.txid));

	channel->depth = depth;

	log_debug(channel->log, "Funding tx %s depth %u of %u",
		  type_to_string(tmpctx, struct bitcoin_txid, txid),
		  depth, channel->minimum_depth);

	/* Reorged out? */
	if (depth == 0) {
		/* That's not entirely unexpected in early states */
		switch (channel->state) {
		case DUALOPEND_AWAITING_LOCKIN:
		case DUALOPEND_OPEN_INIT:
		case DUALOPEND_OPEN_COMMIT_READY:
		case DUALOPEND_OPEN_COMMITTED:
			/* Shouldn't be here! */
			channel_internal_error(channel,
					       "Bad %s state: %s",
					       __func__,
					       channel_state_name(channel));
			return DELETE_WATCH;
		case CHANNELD_AWAITING_LOCKIN:
			/* That's not entirely unexpected in early states */
			log_debug(channel->log, "Funding tx %s reorganized out!",
				  type_to_string(tmpctx, struct bitcoin_txid, txid));
			channel->scid = tal_free(channel->scid);
			return KEEP_WATCHING;

		/* But it's often Bad News in later states */
		case CHANNELD_AWAITING_SPLICE:
		case CHANNELD_NORMAL:
			/* If we opened, or it's zero-conf, we trust them anyway. */
			if (channel->opener == LOCAL
			    || channel->minimum_depth == 0) {
				const char *str;

				str = tal_fmt(tmpctx,
					      "Funding tx %s reorganized out, but %s...",
					      type_to_string(tmpctx, struct bitcoin_txid, txid),
					      channel->opener == LOCAL ? "we opened it" : "zeroconf anyway");

				/* Log even if not connected! */
				if (!channel->owner)
					log_info(channel->log, "%s", str);
				channel_fail_transient(channel, true, "%s", str);
				return KEEP_WATCHING;
			}
			/* fall thru */
		case AWAITING_UNILATERAL:
		case CHANNELD_SHUTTING_DOWN:
		case CLOSINGD_SIGEXCHANGE:
		case CLOSINGD_COMPLETE:
		case FUNDING_SPEND_SEEN:
		case ONCHAIN:
		case CLOSED:
			break;
		}
		channel_internal_error(channel,
				       "Funding transaction has been reorged out in state %s!",
				       channel_state_name(channel));
		return KEEP_WATCHING;
	}

	if (!depthcb_update_scid(channel, txid, &channel->funding))
		return DELETE_WATCH;

	switch (channel->state) {
	/* We should not be in the callback! */
	case DUALOPEND_AWAITING_LOCKIN:
	case DUALOPEND_OPEN_INIT:
	case DUALOPEND_OPEN_COMMIT_READY:
	case DUALOPEND_OPEN_COMMITTED:
		abort();

	case AWAITING_UNILATERAL:
	case CHANNELD_SHUTTING_DOWN:
	case CLOSINGD_SIGEXCHANGE:
	case CLOSINGD_COMPLETE:
	case FUNDING_SPEND_SEEN:
	case ONCHAIN:
	case CLOSED:
		/* If not awaiting lockin/announce, it doesn't care any more */
		log_debug(channel->log,
			  "Funding tx %s confirmed, but peer in state %s",
			  type_to_string(tmpctx, struct bitcoin_txid, txid),
			  channel_state_name(channel));
		return DELETE_WATCH;

	case CHANNELD_AWAITING_LOCKIN:
		if (depth >= channel->minimum_depth
		    && channel->remote_channel_ready) {
			lockin_complete(channel, CHANNELD_AWAITING_LOCKIN);
		}
		/* Fall thru */
	case CHANNELD_NORMAL:
	case CHANNELD_AWAITING_SPLICE:
		channeld_tell_depth(channel, txid, depth);
		if (depth < ANNOUNCE_MIN_DEPTH || depth < channel->minimum_depth)
			return KEEP_WATCHING;
		/* Normal state and past announce depth?  Stop bothering us! */
		return DELETE_WATCH;
	}
	abort();
}

static enum watch_result funding_spent(struct channel *channel,
				       const struct bitcoin_tx *tx,
				       size_t inputnum UNUSED,
				       const struct block *block)
{
	struct bitcoin_txid txid;
	struct channel_inflight *inflight;

	bitcoin_txid(tx, &txid);

	/* If we're doing a splice, we expect the funding transaction to be
	 * spent, so don't freak out and just keep watching in that case */
	list_for_each(&channel->inflights, inflight, list) {
		if (bitcoin_txid_eq(&txid,
				    &inflight->funding->outpoint.txid)) {
			/* splice_locked is a special flag that indicates this
			 * is a memory-only inflight acting as a race condition
			 * safeguard. When we see this, it is our responsability
			 * to clean up this memory-only inflight. */
			if (inflight->splice_locked_memonly) {
				tal_free(inflight);
				return DELETE_WATCH;
			}
			return KEEP_WATCHING;
		}
	}

	wallet_channeltxs_add(channel->peer->ld->wallet, channel,
			      WIRE_ONCHAIND_INIT, &txid, 0, block->height);

	return onchaind_funding_spent(channel, tx, block->height);
}

void channel_watch_wrong_funding(struct lightningd *ld, struct channel *channel)
{
	/* Watch the "wrong" funding too, in case we spend it. */
	if (channel->shutdown_wrong_funding) {
		watch_txo(channel, ld->topology, channel,
			  channel->shutdown_wrong_funding,
			  funding_spent);
	}
}

void channel_watch_funding(struct lightningd *ld, struct channel *channel)
{
	log_debug(channel->log, "Watching for funding txid: %s",
		type_to_string(tmpctx, struct bitcoin_txid, &channel->funding.txid));
	watch_txid(channel, ld->topology,
		   &channel->funding.txid, funding_depth_cb, channel);

	tal_free(channel->funding_spend_watch);
	channel->funding_spend_watch = watch_txo(channel, ld->topology, channel,
						 &channel->funding,
						 funding_spent);
	channel_watch_wrong_funding(ld, channel);
}

static void json_add_peer(struct lightningd *ld,
			  struct json_stream *response,
			  struct peer *p,
			  const enum log_level *ll)
{
	struct channel *channel;
	u32 num_channels;

	json_object_start(response, NULL);
	json_add_node_id(response, "id", &p->id);

	json_add_bool(response, "connected", p->connected == PEER_CONNECTED);
	num_channels = 0;
	list_for_each(&p->channels, channel, list)
		num_channels++;
	json_add_num(response, "num_channels", num_channels);

	if (p->connected == PEER_CONNECTED) {
		json_array_start(response, "netaddr");
		json_add_string(response, NULL,
				type_to_string(tmpctx,
					       struct wireaddr_internal,
					       &p->addr));
		json_array_end(response);
		/* If peer reports our IP remote_addr, add that here */
		if (p->remote_addr)
			json_add_string(response, "remote_addr",
					fmt_wireaddr(response, p->remote_addr));
	}

	/* Note: If !PEER_CONNECTED, peer may use different features on reconnect */
	json_add_hex_talarr(response, "features", p->their_features);

	if (ld->deprecated_apis) {
		json_array_start(response, "channels");
		json_add_uncommitted_channel(response, p->uncommitted_channel, NULL);

		list_for_each(&p->channels, channel, list) {
			if (channel_state_uncommitted(channel->state))
				json_add_unsaved_channel(response, channel, NULL);
			else
				json_add_channel(ld, response, NULL, channel, NULL);
		}
		json_array_end(response);
	}

	if (ll)
		json_add_log(response, ld->log_book, &p->id, *ll);
	json_object_end(response);
}

static struct command_result *json_listpeers(struct command *cmd,
					     const char *buffer,
					     const jsmntok_t *obj UNNEEDED,
					     const jsmntok_t *params)
{
	enum log_level *ll;
	struct node_id *specific_id;
	struct peer *peer;
	struct json_stream *response;

	if (!param(cmd, buffer, params,
		   p_opt("id", param_node_id, &specific_id),
		   p_opt("level", param_loglevel, &ll),
		   NULL))
		return command_param_failed();

	response = json_stream_success(cmd);
	json_array_start(response, "peers");
	if (specific_id) {
		peer = peer_by_id(cmd->ld, specific_id);
		if (peer)
			json_add_peer(cmd->ld, response, peer, ll);
	} else {
		struct peer_node_id_map_iter it;

		for (peer = peer_node_id_map_first(cmd->ld->peers, &it);
		     peer;
		     peer = peer_node_id_map_next(cmd->ld->peers, &it)) {
			json_add_peer(cmd->ld, response, peer, ll);
		}
	}
	json_array_end(response);

	return command_success(cmd, response);
}

static const struct json_command listpeers_command = {
	"listpeers",
	"network",
	json_listpeers,
	"Show current peers, if {level} is set, include logs for {id}"
};
/* Comment added to satisfice AUTODATA */
AUTODATA(json_command, &listpeers_command);

static void json_add_scb(struct command *cmd,
			 const char *fieldname,
			 struct json_stream *response,
			 struct channel *c)
{
	u8 *scb = tal_arr(cmd, u8, 0);

	towire_scb_chan(&scb, c->scb);
	json_add_hex_talarr(response, fieldname,
			    scb);
}

/* This will return a SCB for all the channels currently loaded
 * in the in-memory channel */
static struct command_result *json_staticbackup(struct command *cmd,
					     const char *buffer,
					     const jsmntok_t *obj UNNEEDED,
					     const jsmntok_t *params)
{
	struct json_stream *response;
	struct peer *peer;
	struct channel *channel;
	struct peer_node_id_map_iter it;

	if (!param(cmd, buffer, params, NULL))
		return command_param_failed();

	response = json_stream_success(cmd);

	json_array_start(response, "scb");
	for (peer = peer_node_id_map_first(cmd->ld->peers, &it);
	     peer;
	     peer = peer_node_id_map_next(cmd->ld->peers, &it)) {
		list_for_each(&peer->channels, channel, list){
			if (!channel->scb)
				continue;
			json_add_scb(cmd, NULL, response, channel);
		}
	}
	json_array_end(response);

	return command_success(cmd, response);
}

static const struct json_command staticbackup_command = {
	"staticbackup",
	"backup",
	json_staticbackup,
	"Returns SCB of all the channels currently present in the DB"
};
/* Comment added to satisfice AUTODATA */
AUTODATA(json_command, &staticbackup_command);

static void json_add_peerchannels(struct lightningd *ld,
				  struct json_stream *response,
				  const struct peer *peer)
{
	struct channel *channel;

	json_add_uncommitted_channel(response, peer->uncommitted_channel, peer);
	list_for_each(&peer->channels, channel, list) {
		if (channel_state_uncommitted(channel->state))
			json_add_unsaved_channel(response, channel, peer);
		else
			json_add_channel(ld, response, NULL, channel, peer);
	}
}

static struct command_result *json_listpeerchannels(struct command *cmd,
						    const char *buffer,
						    const jsmntok_t *obj UNNEEDED,
						    const jsmntok_t *params)
{
	struct node_id *peer_id;
	struct peer *peer;
	struct json_stream *response;

	/* FIME: filter by status */
	if (!param(cmd, buffer, params,
		   p_opt("id", param_node_id, &peer_id),
		   NULL))
		return command_param_failed();

	response = json_stream_success(cmd);
	json_array_start(response, "channels");

	if (peer_id) {
		peer = peer_by_id(cmd->ld, peer_id);
		if (peer)
			json_add_peerchannels(cmd->ld, response, peer);
	} else {
		struct peer_node_id_map_iter it;

		for (peer = peer_node_id_map_first(cmd->ld->peers, &it);
		     peer;
		     peer = peer_node_id_map_next(cmd->ld->peers, &it)) {
			json_add_peerchannels(cmd->ld, response, peer);
		}
	}

	json_array_end(response);

	return command_success(cmd, response);
}

static const struct json_command listpeerchannels_command = {
	"listpeerchannels",
	"network",
	json_listpeerchannels,
	"Show channels with direct peers."
};
AUTODATA(json_command, &listpeerchannels_command);

struct command_result *
command_find_channel(struct command *cmd,
		     const char *name,
		     const char *buffer, const jsmntok_t *tok,
		     struct channel **channel)
{
	struct lightningd *ld = cmd->ld;
	struct channel_id cid;
	struct short_channel_id scid;
	struct peer *peer;

	if (json_tok_channel_id(buffer, tok, &cid)) {
		struct peer_node_id_map_iter it;

		for (peer = peer_node_id_map_first(ld->peers, &it);
		     peer;
		     peer = peer_node_id_map_next(ld->peers, &it)) {
			list_for_each(&peer->channels, (*channel), list) {
				if (!channel_state_wants_peercomms((*channel)->state))
					continue;
				if (channel_id_eq(&(*channel)->cid, &cid))
					return NULL;
			}
		}
		return command_fail_badparam(cmd, name, buffer, tok,
					     "Channel id not found");
	} else if (json_to_short_channel_id(buffer, tok, &scid)) {
		*channel = any_channel_by_scid(ld, &scid, true);
		if (!*channel)
			return command_fail_badparam(cmd, name, buffer, tok,
						     "Short channel id not found");
		return NULL;
	} else {
		return command_fail_badparam(cmd, name, buffer, tok,
					     "should be a channel ID or short channel ID");
	}
}

static void setup_peer(struct peer *peer, u32 delay)
{
	struct channel *channel;
	struct channel_inflight *inflight;
	struct lightningd *ld = peer->ld;
	bool connect = false;

	list_for_each(&peer->channels, channel, list) {
		switch (channel->state) {
		case DUALOPEND_OPEN_INIT:
		case DUALOPEND_OPEN_COMMIT_READY:
		case DUALOPEND_OPEN_COMMITTED:
			/* Nothing to watch */
			continue;

		/* Normal cases where we watch funding */
		case CHANNELD_AWAITING_LOCKIN:
		case CHANNELD_NORMAL:
		case CHANNELD_SHUTTING_DOWN:
		case CLOSINGD_SIGEXCHANGE:
		/* We still want to watch spend, to tell onchaind: */
		case CLOSINGD_COMPLETE:
		case AWAITING_UNILATERAL:
		case FUNDING_SPEND_SEEN:
		case ONCHAIN:
		case CLOSED:
			channel_watch_funding(ld, channel);
			break;

		/* We need to watch all inflights which may open channel */
		case DUALOPEND_AWAITING_LOCKIN:
			list_for_each(&channel->inflights, inflight, list)
				watch_opening_inflight(ld, inflight);
			break;

		/* We need to watch all inflights which may splice */
		case CHANNELD_AWAITING_SPLICE:
			list_for_each(&channel->inflights, inflight, list)
				watch_splice_inflight(ld, inflight);
			break;
		}

		if (channel_state_wants_peercomms(channel->state))
			connect = true;
	}

	/* Make sure connectd knows to try reconnecting. */
	if (connect) {
		/* To delay, make it seem like we just connected. */
		if (delay > 0) {
			peer->reconnect_delay = delay;
			peer->last_connect_attempt = time_now();
		}
		try_reconnect(peer, peer, &peer->addr);
	}
}

void setup_peers(struct lightningd *ld)
{
	struct peer *p;
	/* Avoid thundering herd: after first five, delay by 1 second. */
	int delay = -5;
	struct peer_node_id_map_iter it;

	for (p = peer_node_id_map_first(ld->peers, &it);
	     p;
	     p = peer_node_id_map_next(ld->peers, &it)) {
		setup_peer(p, delay > 0 ? delay : 0);
		delay++;
	}
}

/* Pull peers, channels and HTLCs from db, and wire them up. */
struct htlc_in_map *load_channels_from_wallet(struct lightningd *ld)
{
	struct peer *peer;
	struct htlc_in_map *unconnected_htlcs_in = tal(ld, struct htlc_in_map);
	struct peer_node_id_map_iter it;

	/* Load channels from database */
	if (!wallet_init_channels(ld->wallet))
		fatal("Could not load channels from the database");

	/* First we load the incoming htlcs */
	for (peer = peer_node_id_map_first(ld->peers, &it);
	     peer;
	     peer = peer_node_id_map_next(ld->peers, &it)) {
		struct channel *channel;

		list_for_each(&peer->channels, channel, list) {
			if (!wallet_htlcs_load_in_for_channel(ld->wallet,
							      channel,
							      ld->htlcs_in)) {
				fatal("could not load htlcs for channel");
			}
		}
	}

	/* Make a copy of the htlc_map: entries removed as they're matched */
	htlc_in_map_copy(unconnected_htlcs_in, ld->htlcs_in);

	/* Now we load the outgoing HTLCs, so we can connect them. */
	for (peer = peer_node_id_map_first(ld->peers, &it);
	     peer;
	     peer = peer_node_id_map_next(ld->peers, &it)) {
		struct channel *channel;

		list_for_each(&peer->channels, channel, list) {
			if (!wallet_htlcs_load_out_for_channel(ld->wallet,
							       channel,
							       ld->htlcs_out,
							       unconnected_htlcs_in)) {
				fatal("could not load outgoing htlcs for channel");
			}
		}
	}

#ifdef COMPAT_V061
	fixup_htlcs_out(ld);
#endif /* COMPAT_V061 */

	return unconnected_htlcs_in;
}

static struct command_result *param_peer(struct command *cmd,
					 const char *name,
					 const char *buffer,
					 const jsmntok_t *tok,
					 struct peer **peer)
{
	struct node_id peerid;

	if (!json_to_node_id(buffer, tok, &peerid))
		return command_fail_badparam(cmd, name, buffer, tok,
					     "invalid peer id");
	*peer = peer_by_id(cmd->ld, &peerid);
	if (!*peer)
		return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
				    "Unknown peer '%.*s'",
				    tok->end - tok->start,
				    buffer + tok->start);
	return NULL;
}

static struct command_result *json_disconnect(struct command *cmd,
					      const char *buffer,
					      const jsmntok_t *obj UNNEEDED,
					      const jsmntok_t *params)
{
	struct disconnect_command *dc;
	struct peer *peer;
	struct channel *channel;
	bool *force;

	if (!param_check(cmd, buffer, params,
			 p_req("id", param_peer, &peer),
			 p_opt_def("force", param_bool, &force, false),
			 NULL))
		return command_param_failed();

	if (peer->connected == PEER_DISCONNECTED) {
		return command_fail(cmd, LIGHTNINGD, "Peer not connected");
	}

	channel = peer_any_channel(peer, channel_state_wants_peercomms, NULL);
	if (channel && !*force) {
		return command_fail(cmd, LIGHTNINGD,
				    "Peer has (at least one) channel in state %s",
				    channel_state_name(channel));
	}

	if (command_check_only(cmd))
		return command_check_done(cmd);

	force_peer_disconnect(cmd->ld, peer, "disconnect command");

	/* Connectd tells us when it's finally disconnected */
	dc = tal(cmd, struct disconnect_command);
	dc->cmd = cmd;
	dc->id = peer->id;
	list_add_tail(&cmd->ld->disconnect_commands, &dc->list);
	tal_add_destructor(dc, destroy_disconnect_command);

	return command_still_pending(cmd);
}

static const struct json_command disconnect_command = {
	"disconnect",
	"network",
	json_disconnect,
	"Disconnect from {id} that has previously been connected to using connect; with {force} set, even if it has a current channel"
};
AUTODATA(json_command, &disconnect_command);

static struct command_result *json_getinfo(struct command *cmd,
					   const char *buffer,
					   const jsmntok_t *obj UNNEEDED,
					   const jsmntok_t *params)
{
	struct json_stream *response;
	struct peer *peer;
	struct channel *channel;
	unsigned int pending_channels = 0, active_channels = 0,
		     inactive_channels = 0, num_peers = 0;
	size_t count_announceable;
	struct peer_node_id_map_iter it;

	if (!param(cmd, buffer, params, NULL))
		return command_param_failed();

	response = json_stream_success(cmd);
	json_add_node_id(response, "id", &cmd->ld->id);
	json_add_string(response, "alias", (const char *)cmd->ld->alias);
	json_add_hex_talarr(response, "color", cmd->ld->rgb);

	/* Add some peer and channel stats */
	for (peer = peer_node_id_map_first(cmd->ld->peers, &it);
	     peer;
	     peer = peer_node_id_map_next(cmd->ld->peers, &it)) {
		num_peers++;

		list_for_each(&peer->channels, channel, list) {
			switch (channel->state) {
			case CHANNELD_AWAITING_LOCKIN:
			case DUALOPEND_OPEN_INIT:
			case DUALOPEND_OPEN_COMMIT_READY:
			case DUALOPEND_OPEN_COMMITTED:
			case DUALOPEND_AWAITING_LOCKIN:
				pending_channels++;
				continue;
			case CHANNELD_AWAITING_SPLICE:
			case CHANNELD_SHUTTING_DOWN:
			case CHANNELD_NORMAL:
			case CLOSINGD_SIGEXCHANGE:
				active_channels++;
				continue;
			case CLOSINGD_COMPLETE:
			case AWAITING_UNILATERAL:
			case FUNDING_SPEND_SEEN:
			case ONCHAIN:
			case CLOSED:
				inactive_channels++;
				continue;
			}
			abort();
		}
	}
	json_add_num(response, "num_peers", num_peers);
	json_add_num(response, "num_pending_channels", pending_channels);
	json_add_num(response, "num_active_channels", active_channels);
	json_add_num(response, "num_inactive_channels", inactive_channels);

	/* Add network info */
	json_array_start(response, "address");
	if (cmd->ld->listen) {
		/* These are the addresses we're announcing */
		count_announceable = tal_count(cmd->ld->announceable);
		for (size_t i = 0; i < count_announceable; i++)
			json_add_address(response, NULL, cmd->ld->announceable+i);

		/* Add discovered IPs if we announce them.
		 * Also see `create_node_announcement` in `gossip_generation.c`. */
		if ((cmd->ld->config.ip_discovery == OPT_AUTOBOOL_AUTO && count_announceable == 0) ||
		     cmd->ld->config.ip_discovery == OPT_AUTOBOOL_TRUE) {
			if (cmd->ld->discovered_ip_v4 != NULL &&
					!wireaddr_arr_contains(
						cmd->ld->announceable,
						cmd->ld->discovered_ip_v4))
				json_add_address(response, NULL,
						 cmd->ld->discovered_ip_v4);
			if (cmd->ld->discovered_ip_v6 != NULL &&
					!wireaddr_arr_contains(
						cmd->ld->announceable,
						cmd->ld->discovered_ip_v6))
				json_add_address(response, NULL,
						 cmd->ld->discovered_ip_v6);
		}
		json_array_end(response);

		/* This is what we're actually bound to. */
		json_array_start(response, "binding");
		for (size_t i = 0; i < tal_count(cmd->ld->binding); i++)
			json_add_address_internal(response, NULL,
					cmd->ld->binding+i);
	}
	json_array_end(response);

	json_add_string(response, "version", version());
	/* If we're still syncing, put the height we're up to here, so
	 * they can see progress!  Otherwise use the height gossipd knows
	 * about, so tests work properly. */
	if (!topology_synced(cmd->ld->topology)) {
		json_add_num(response, "blockheight",
			     get_block_height(cmd->ld->topology));
	} else {
		json_add_num(response, "blockheight",
			     cmd->ld->gossip_blockheight);
	}
	json_add_string(response, "network", chainparams->network_name);
	json_add_amount_msat(response,
			     "fees_collected_msat",
			     wallet_total_forward_fees(cmd->ld->wallet));
	json_add_string(response, "lightning-dir", cmd->ld->config_netdir);

	if (!cmd->ld->topology->bitcoind->synced)
		json_add_string(response, "warning_bitcoind_sync",
				"Bitcoind is not up-to-date with network.");
	else if (!topology_synced(cmd->ld->topology))
		json_add_string(response, "warning_lightningd_sync",
				"Still loading latest blocks from bitcoind.");

	u8 **bits = cmd->ld->our_features->bits;
	json_object_start(response, "our_features");
	json_add_hex_talarr(response, "init",
			featurebits_or(cmd,
				       bits[INIT_FEATURE],
				       bits[GLOBAL_INIT_FEATURE]));
	json_add_hex_talarr(response, "node", bits[NODE_ANNOUNCE_FEATURE]);
	json_add_hex_talarr(response, "channel", bits[CHANNEL_FEATURE]);
	json_add_hex_talarr(response, "invoice", bits[BOLT11_FEATURE]);
	json_object_end(response);

	return command_success(cmd, response);
}

static const struct json_command getinfo_command = {
    "getinfo",
	"utility",
    json_getinfo,
    "Show information about this node"
};
AUTODATA(json_command, &getinfo_command);

/* Wait for at least a specific blockheight, then return, or time out.  */
struct waitblockheight_waiter {
	/* struct lightningd::waitblockheight_commands.  */
	struct list_node list;
	/* Command structure. This is the parent of the close command. */
	struct command *cmd;
	/* The block height being waited for.  */
	u32 block_height;
	/* Whether we have been removed from the list.  */
	bool removed;
};
/* Completes a pending waitblockheight.  */
static struct command_result *
waitblockheight_complete(struct command *cmd,
			 u32 block_height)
{
	struct json_stream *response;

	response = json_stream_success(cmd);
	json_add_num(response, "blockheight", block_height);
	return command_success(cmd, response);
}
/* Called when command is destroyed without being resolved.  */
static void
destroy_waitblockheight_waiter(struct waitblockheight_waiter *w)
{
	if (!w->removed)
		list_del(&w->list);
}
/* Called on timeout.  */
static void
timeout_waitblockheight_waiter(struct waitblockheight_waiter *w)
{
	list_del(&w->list);
	w->removed = true;
	tal_steal(tmpctx, w);
	was_pending(command_fail(w->cmd, WAIT_TIMEOUT,
				 "Timed out."));
}
/* Called by lightningd at each new block.  */
void waitblockheight_notify_new_block(struct lightningd *ld,
				      u32 block_height)
{
	struct waitblockheight_waiter *w, *n;
	char *to_delete = tal(NULL, char);

	/* Use safe since we could resolve commands and thus
	 * trigger removal of list elements.
	 */
	list_for_each_safe(&ld->waitblockheight_commands, w, n, list) {
		/* Skip commands that have not been reached yet.  */
		if (w->block_height > block_height)
			continue;

		list_del(&w->list);
		w->removed = true;
		tal_steal(to_delete, w);
		was_pending(waitblockheight_complete(w->cmd,
						     block_height));
	}
	tal_free(to_delete);
}
static struct command_result *json_waitblockheight(struct command *cmd,
						   const char *buffer,
						   const jsmntok_t *obj,
						   const jsmntok_t *params)
{
	unsigned int *target_block_height;
	u32 block_height;
	unsigned int *timeout;
	struct waitblockheight_waiter *w;

	if (!param(cmd, buffer, params,
		   p_req("blockheight", param_number, &target_block_height),
		   p_opt_def("timeout", param_number, &timeout, 60),
		   NULL))
		return command_param_failed();

	/* Check if already reached anyway.  */
	block_height = get_block_height(cmd->ld->topology);
	if (*target_block_height <= block_height)
		return waitblockheight_complete(cmd, block_height);

	/* Create a new waitblockheight command. */
	w = tal(cmd, struct waitblockheight_waiter);
	tal_add_destructor(w, &destroy_waitblockheight_waiter);
	list_add(&cmd->ld->waitblockheight_commands, &w->list);
	w->cmd = cmd;
	w->block_height = *target_block_height;
	w->removed = false;
	/* Install the timeout.  */
	(void) new_reltimer(cmd->ld->timers, w, time_from_sec(*timeout),
			    &timeout_waitblockheight_waiter, w);

	return command_still_pending(cmd);
}

static const struct json_command waitblockheight_command = {
	"waitblockheight",
	"utility",
	&json_waitblockheight,
	"Wait for the blockchain to reach {blockheight}, up to "
	"{timeout} seconds."
};
AUTODATA(json_command, &waitblockheight_command);

static bool channel_state_can_setchannel(enum channel_state state)
{
	switch (state) {
	case CHANNELD_NORMAL:
	case CHANNELD_AWAITING_SPLICE:
	case CHANNELD_AWAITING_LOCKIN:
	case DUALOPEND_AWAITING_LOCKIN:
		return true;
	case DUALOPEND_OPEN_INIT:
	case DUALOPEND_OPEN_COMMIT_READY:
	case DUALOPEND_OPEN_COMMITTED:
	case CLOSINGD_SIGEXCHANGE:
	case CHANNELD_SHUTTING_DOWN:
	case CLOSINGD_COMPLETE:
	case AWAITING_UNILATERAL:
	case FUNDING_SPEND_SEEN:
	case ONCHAIN:
	case CLOSED:
		return false;
	}
	abort();
}

static struct command_result *param_channel_or_all(struct command *cmd,
					     const char *name,
					     const char *buffer,
					     const jsmntok_t *tok,
					     struct channel ***channels)
{
	struct command_result *res;
	struct peer *peer;
	struct channel *channel;

	*channels = tal_arr(cmd, struct channel *, 0);

	/* early return the easy case */
	if (json_tok_streq(buffer, tok, "all")) {
		*channels = tal_free(*channels);
		return NULL;
	}

	/* Find channels by peer_id */
	peer = peer_from_json(cmd->ld, buffer, tok);
	if (peer) {
		list_for_each(&peer->channels, channel, list) {
			if (channel_state_can_setchannel(channel->state))
				tal_arr_expand(channels, channel);
		}
		if (tal_count(*channels) == 0)
			return command_fail(cmd, LIGHTNINGD,
					    "Could not find any active channels of peer with that id");
		return NULL;
	}

	/* Find channel by id or scid */
	res = command_find_channel(cmd, name, buffer, tok, &channel);
	if (res)
		return res;
	/* check channel is found and in valid state */
	if (!channel_state_can_setchannel(channel->state))
		return command_fail_badparam(cmd, name, buffer, tok,
					     tal_fmt(tmpctx, "Channel in state %s",
						     channel_state_name(channel)));
	tal_arr_expand(channels, channel);
	return NULL;
}

/* Fee base is a u32, but it's convenient to let them specify it using
 * msat etc. suffix. */
static struct command_result *param_msat_u32(struct command *cmd,
					     const char *name,
					     const char *buffer,
					     const jsmntok_t *tok,
					     u32 **num)
{
	struct amount_msat *msat;
	struct command_result *res;

	/* Parse just like an msat. */
	res = param_msat(cmd, name, buffer, tok, &msat);
	if (res)
		return res;

	*num = tal(cmd, u32);
	if (!amount_msat_to_u32(*msat, *num)) {
		return command_fail_badparam(cmd, name, buffer, tok,
					     "exceeds u32 max");
	}

	return NULL;
}

static void set_channel_config(struct command *cmd, struct channel *channel,
			       u32 *base,
			       u32 *ppm,
			       struct amount_msat *htlc_min,
			       struct amount_msat *htlc_max,
			       u32 delaysecs,
			       bool *ignore_fee_limits,
			       struct json_stream *response)
{
	bool warn_cannot_set_min = false, warn_cannot_set_max = false;

	/* We only need to defer values if we *increase* fees (or drop
	 * max, increase min); we always allow users to overpay fees. */
	if ((base && *base > channel->feerate_base)
	    || (ppm && *ppm > channel->feerate_ppm)
	    || (htlc_min
		&& amount_msat_greater(*htlc_min, channel->htlc_minimum_msat))
	    || (htlc_max
		&& amount_msat_less(*htlc_max, channel->htlc_maximum_msat))) {
		channel->old_feerate_timeout
			= timeabs_add(time_now(), time_from_sec(delaysecs));
		channel->old_feerate_base = channel->feerate_base;
		channel->old_feerate_ppm = channel->feerate_ppm;
		channel->old_htlc_minimum_msat = channel->htlc_minimum_msat;
		channel->old_htlc_maximum_msat = channel->htlc_maximum_msat;
	}

	/* set new values */
	if (base)
		channel->feerate_base = *base;
	if (ppm)
		channel->feerate_ppm = *ppm;
	if (htlc_min) {
		struct amount_msat actual_min;

		/* We can't send something they'll refuse: check that here. */
		actual_min = channel->channel_info.their_config.htlc_minimum;
		if (amount_msat_less(*htlc_min, actual_min)) {
			warn_cannot_set_min = true;
			channel->htlc_minimum_msat = actual_min;
		} else
			channel->htlc_minimum_msat = *htlc_min;
	}
	if (htlc_max) {
		struct amount_msat actual_max;

		/* Can't set it greater than actual capacity. */
		actual_max = htlc_max_possible_send(channel);
		if (amount_msat_greater(*htlc_max, actual_max)) {
			warn_cannot_set_max = true;
			channel->htlc_maximum_msat = actual_max;
		} else
			channel->htlc_maximum_msat = *htlc_max;
	}
	if (ignore_fee_limits)
		channel->ignore_fee_limits = *ignore_fee_limits;

	/* Tell channeld about the new acceptable feerates */
	if (channel->owner
	    && streq(channel->owner->name, "channeld")
	    && ignore_fee_limits) {
		channel_update_feerates(cmd->ld, channel);
	}

	/* Tell gossipd */
	/* FIXME: this always enables channel, even if not enabled! */
	tell_gossipd_local_channel_update(cmd->ld, channel, true);

	/* save values to database */
	wallet_channel_save(cmd->ld->wallet, channel);

	/* write JSON response entry */
	json_object_start(response, NULL);
	json_add_node_id(response, "peer_id", &channel->peer->id);
	json_add_string(response, "channel_id",
			type_to_string(tmpctx, struct channel_id, &channel->cid));
	if (channel->scid)
		json_add_short_channel_id(response, "short_channel_id", channel->scid);

	json_add_amount_msat(response, "fee_base_msat",
			     amount_msat(channel->feerate_base));
	json_add_u32(response, "fee_proportional_millionths",
		     channel->feerate_ppm);
	json_add_amount_msat(response,
			     "minimum_htlc_out_msat",
			     channel->htlc_minimum_msat);
	if (warn_cannot_set_min)
		json_add_string(response, "warning_htlcmin_too_low",
				"Set minimum_htlc_out_msat to minimum allowed by peer");
	json_add_amount_msat(response,
			     "maximum_htlc_out_msat",
			     channel->htlc_maximum_msat);
	json_add_bool(response, "ignore_fee_limits", channel->ignore_fee_limits);
	if (warn_cannot_set_max)
		json_add_string(response, "warning_htlcmax_too_high",
				"Set maximum_htlc_out_msat to maximum possible in channel");
	json_object_end(response);
}

static struct command_result *json_setchannel(struct command *cmd,
					      const char *buffer,
					      const jsmntok_t *obj UNNEEDED,
					      const jsmntok_t *params)
{
	struct json_stream *response;
	struct peer *peer;
	struct channel **channels;
	u32 *base, *ppm, *delaysecs;
	struct amount_msat *htlc_min, *htlc_max;
	bool *ignore_fee_limits;

	/* Parse the JSON command */
	if (!param_check(cmd, buffer, params,
			 p_req("id", param_channel_or_all, &channels),
			 p_opt("feebase", param_msat_u32, &base),
			 p_opt("feeppm", param_number, &ppm),
			 p_opt("htlcmin", param_msat, &htlc_min),
			 p_opt("htlcmax", param_msat, &htlc_max),
			 p_opt_def("enforcedelay", param_number, &delaysecs, 600),
			 p_opt("ignorefeelimits", param_bool, &ignore_fee_limits),
			 NULL))
		return command_param_failed();

	/* Prevent obviously incorrect things! */
	if (htlc_min && htlc_max
	    && amount_msat_less(*htlc_max, *htlc_min)) {
		return command_fail(cmd, LIGHTNINGD,
				    "htlcmax cannot be less than htlcmin");
	}

	if (command_check_only(cmd))
		return command_check_done(cmd);

	/* Open JSON response object for later iteration */
	response = json_stream_success(cmd);
	json_array_start(response, "channels");

	/* If the users requested 'all' channels we need to iterate */
	if (channels == NULL) {
		struct peer_node_id_map_iter it;

		for (peer = peer_node_id_map_first(cmd->ld->peers, &it);
		     peer;
		     peer = peer_node_id_map_next(cmd->ld->peers, &it)) {
			struct channel *channel;
			list_for_each(&peer->channels, channel, list) {
				if (!channel_state_can_setchannel(channel->state))
					continue;
				set_channel_config(cmd, channel, base, ppm,
						   htlc_min, htlc_max,
						   *delaysecs, ignore_fee_limits,
						   response);
			}
		}
	/* single peer should be updated */
	} else {
		for (size_t i = 0; i < tal_count(channels); i++) {
			set_channel_config(cmd, channels[i], base, ppm,
					   htlc_min, htlc_max,
					   *delaysecs, ignore_fee_limits,
					   response);
		}
	}

	/* Close and return response */
	json_array_end(response);
	return command_success(cmd, response);
}

static const struct json_command setchannel_command = {
	"setchannel",
	"channels",
	json_setchannel,
	"Sets fees and/or htlc_max for channel with {id} "
	"(either peer ID, channel ID, short channel ID or 'all'). "
	"If {feebase}, {feeppm} or {htlcmax} is missing, it is unchanged."
	"{base} can also be defined in other units, for example '1sat'. "
	"If {id} is 'all', the fees will be applied for all channels. "
};
AUTODATA(json_command, &setchannel_command);

/* dev hack, don't use for real interfaces, which have to handle channel ids, or multiple channels */
static struct command_result *param_dev_channel(struct command *cmd,
						const char *name,
						const char *buffer,
						const jsmntok_t *tok,
						struct channel **channel)
{
	struct peer *peer;
	struct command_result *res;
	bool more_than_one;

	res = param_peer(cmd, name, buffer, tok, &peer);
	if (res)
		return res;

	*channel = peer_any_channel(peer, channel_state_wants_peercomms, &more_than_one);
	if (!*channel)
		return command_fail_badparam(cmd, name, buffer, tok,
					     "No channel with that peer");

	if (more_than_one)
		return command_fail_badparam(cmd, name, buffer, tok,
					     "More than one channel with that peer");

	return NULL;
}

static struct command_result *json_sign_last_tx(struct command *cmd,
						const char *buffer,
						const jsmntok_t *obj UNNEEDED,
						const jsmntok_t *params)
{
	struct json_stream *response;
	struct channel *channel;
	struct bitcoin_tx *tx;

	if (!param(cmd, buffer, params,
		   p_req("id", param_dev_channel, &channel),
		   NULL))
		return command_param_failed();

	response = json_stream_success(cmd);
	log_debug(channel->log, "dev-sign-last-tx: signing tx with %zu outputs",
		  channel->last_tx->wtx->num_outputs);

	tx = sign_last_tx(cmd, channel, channel->last_tx, &channel->last_sig);
	json_add_tx(response, "tx", tx);

	/* If we've got inflights, return them */
	if (!list_empty(&channel->inflights)) {
		struct channel_inflight *inflight;

		json_array_start(response, "inflights");
		list_for_each(&channel->inflights, inflight, list) {
			tx = sign_last_tx(cmd, channel, inflight->last_tx,
					  &inflight->last_sig);
			json_object_start(response, NULL);
			json_add_txid(response, "funding_txid",
				      &inflight->funding->outpoint.txid);
			json_add_tx(response, "tx", tx);
			json_object_end(response);
		}
		json_array_end(response);
	}

	return command_success(cmd, response);
}

static const struct json_command dev_sign_last_tx = {
	"dev-sign-last-tx",
	"developer",
	json_sign_last_tx,
	"Sign and show the last commitment transaction with peer {id}",
	.dev_only = true,
};
AUTODATA(json_command, &dev_sign_last_tx);

static struct command_result *json_dev_fail(struct command *cmd,
					    const char *buffer,
					    const jsmntok_t *obj UNNEEDED,
					    const jsmntok_t *params)
{
	struct channel *channel;

	if (!param(cmd, buffer, params,
		   p_req("id", param_dev_channel, &channel),
		   NULL))
		return command_param_failed();

	channel_fail_permanent(channel,
			       REASON_USER,
			       "Failing due to dev-fail command");
	return command_success(cmd, json_stream_success(cmd));
}

static const struct json_command dev_fail_command = {
	"dev-fail",
	"developer",
	json_dev_fail,
	"Fail with peer {id}",
	.dev_only = true,
};
AUTODATA(json_command, &dev_fail_command);

static void dev_reenable_commit_finished(struct subd *channeld UNUSED,
					 const u8 *resp UNUSED,
					 const int *fds UNUSED,
					 struct command *cmd)
{
	was_pending(command_success(cmd, json_stream_success(cmd)));
}

static struct command_result *json_dev_reenable_commit(struct command *cmd,
						       const char *buffer,
						       const jsmntok_t *obj UNNEEDED,
						       const jsmntok_t *params)
{
	u8 *msg;
	struct channel *channel;

	if (!param_check(cmd, buffer, params,
			 p_req("id", param_dev_channel, &channel),
			 NULL))
		return command_param_failed();

	if (!channel->owner) {
		return command_fail(cmd, LIGHTNINGD,
				    "Peer has no owner");
	}

	if (!streq(channel->owner->name, "channeld")) {
		return command_fail(cmd, LIGHTNINGD,
				    "Peer owned by %s", channel->owner->name);
	}

	if (command_check_only(cmd))
		return command_check_done(cmd);

	msg = towire_channeld_dev_reenable_commit(channel);
	subd_req(channel, channel->owner, take(msg), -1, 0,
		 dev_reenable_commit_finished, cmd);
	return command_still_pending(cmd);
}

static const struct json_command dev_reenable_commit = {
	"dev-reenable-commit",
	"developer",
	json_dev_reenable_commit,
	"Re-enable the commit timer on peer {id}",
	.dev_only = true,
};
AUTODATA(json_command, &dev_reenable_commit);

struct dev_forget_channel_cmd {
	struct short_channel_id scid;
	struct channel *channel;
	bool force;
	struct command *cmd;
};

static void process_dev_forget_channel(struct bitcoind *bitcoind UNUSED,
				       const struct bitcoin_tx_output *txout,
				       void *arg)
{
	struct json_stream *response;
	struct dev_forget_channel_cmd *forget = arg;
	if (txout != NULL && !forget->force) {
		was_pending(command_fail(forget->cmd, LIGHTNINGD,
			     "Cowardly refusing to forget channel with an "
			     "unspent funding output, if you know what "
			     "you're doing you can override with "
			     "`force=true`, otherwise consider `close` or "
			     "`dev-fail`! If you force and the channel "
			     "confirms we will not track the funds in the "
			     "channel"));
		return;
	}
	response = json_stream_success(forget->cmd);
	json_add_bool(response, "forced", forget->force);
	json_add_bool(response, "funding_unspent", txout != NULL);
	json_add_txid(response, "funding_txid", &forget->channel->funding.txid);

	/* Set error so we don't try to reconnect. */
	forget->channel->error = towire_errorfmt(forget->channel,
						 &forget->channel->cid,
						 "dev_forget_channel");
	delete_channel(forget->channel);

	was_pending(command_success(forget->cmd, response));
}

static struct command_result *json_dev_forget_channel(struct command *cmd,
						      const char *buffer,
						      const jsmntok_t *obj UNNEEDED,
						      const jsmntok_t *params)
{
	struct peer *peer;
	struct channel *channel;
	struct short_channel_id *scid;
	struct channel_id *find_cid;
	struct dev_forget_channel_cmd *forget;
	bool *force;

	if (!param_check(cmd, buffer, params,
			 p_req("id", param_peer, &peer),
			 p_opt("short_channel_id", param_short_channel_id, &scid),
			 p_opt("channel_id", param_channel_id, &find_cid),
			 p_opt_def("force", param_bool, &force, false),
			 NULL))
		return command_param_failed();

	forget = tal(cmd, struct dev_forget_channel_cmd);
	forget->cmd = cmd;
	forget->force = *force;

	forget->channel = NULL;
	list_for_each(&peer->channels, channel, list) {
		/* Check for channel id first */
		if (find_cid) {
			if (!channel_id_eq(find_cid, &channel->cid))
				continue;
		}
		if (scid) {
			if (!channel->scid)
				continue;
			if (!short_channel_id_eq(channel->scid, scid))
				continue;
		}
		if (forget->channel) {
			return command_fail(cmd, LIGHTNINGD,
					    "Multiple channels:"
					    " please specify short_channel_id");
		}
		forget->channel = channel;
	}
	if (!forget->channel) {
		return command_fail(cmd, LIGHTNINGD,
				    "No channels matching that peer_id%s",
					scid ? " and that short_channel_id" : "");
	}

	if (channel_has_htlc_out(forget->channel) ||
	    channel_has_htlc_in(forget->channel)) {
		return command_fail(cmd, LIGHTNINGD,
				    "This channel has HTLCs attached and it is "
				    "not safe to forget it. Please use `close` "
				    "or `dev-fail` instead.");
	}

	if (command_check_only(cmd))
		return command_check_done(cmd);

	if (!channel_state_uncommitted(forget->channel->state))
		bitcoind_getutxout(cmd->ld->topology->bitcoind,
				   &forget->channel->funding,
				   process_dev_forget_channel, forget);
	return command_still_pending(cmd);
}

static const struct json_command dev_forget_channel_command = {
	"dev-forget-channel",
	"developer",
	json_dev_forget_channel,
	"Forget the channel with peer {id}, ignore UTXO check with {force}='true'.",
	.verbose = "Forget the channel with peer {id}. Checks if the channel is still active by checking its funding transaction. Check can be ignored by setting {force} to 'true'",
	.dev_only = true,
};
AUTODATA(json_command, &dev_forget_channel_command);

static void channeld_memleak_req_done(struct subd *channeld,
				      const u8 *msg, const int *fds UNUSED,
				      struct leak_detect *leaks)
{
	bool found_leak;

	if (!fromwire_channeld_dev_memleak_reply(msg, &found_leak))
		fatal("Bad channel_dev_memleak");

	if (found_leak)
		report_subd_memleak(leaks, channeld);
}

static void onchaind_memleak_req_done(struct subd *onchaind,
				      const u8 *msg, const int *fds UNUSED,
				      struct leak_detect *leaks)
{
	bool found_leak;

	if (!fromwire_onchaind_dev_memleak_reply(msg, &found_leak))
		fatal("Bad onchaind_dev_memleak");

	if (found_leak)
		report_subd_memleak(leaks, onchaind);
}

static void openingd_memleak_req_done(struct subd *open_daemon,
				     const u8 *msg, const int *fds UNUSED,
				     struct leak_detect *leaks)
{
	bool found_leak;

	if (!fromwire_openingd_dev_memleak_reply(msg, &found_leak))
		fatal("Bad opening_dev_memleak");

	if (found_leak)
		report_subd_memleak(leaks, open_daemon);
}

static void dualopend_memleak_req_done(struct subd *dualopend,
				     const u8 *msg, const int *fds UNUSED,
				     struct leak_detect *leaks)
{
	bool found_leak;

	if (!fromwire_dualopend_dev_memleak_reply(msg, &found_leak))
		fatal("Bad dualopend_dev_memleak");

	if (found_leak)
		report_subd_memleak(leaks, dualopend);
}

void peer_dev_memleak(struct lightningd *ld, struct leak_detect *leaks)
{
	struct peer *p;
	struct peer_node_id_map_iter it;

	for (p = peer_node_id_map_first(ld->peers, &it);
	     p;
	     p = peer_node_id_map_next(ld->peers, &it)) {
		struct channel *c;
		if (p->uncommitted_channel && p->uncommitted_channel->open_daemon) {
			struct subd *openingd = p->uncommitted_channel->open_daemon;
			start_leak_request(subd_req(openingd, openingd,
						    take(towire_openingd_dev_memleak(NULL)),
						    -1, 0, openingd_memleak_req_done, leaks),
					   leaks);
		}

		list_for_each(&p->channels, c, list) {
			if (!c->owner)
				continue;
			if (streq(c->owner->name, "channeld")) {
				start_leak_request(subd_req(c, c->owner,
					 take(towire_channeld_dev_memleak(NULL)),
					 -1, 0, channeld_memleak_req_done, leaks),
					leaks);
			} else if (streq(c->owner->name, "onchaind")) {
				start_leak_request(subd_req(c, c->owner,
					 take(towire_onchaind_dev_memleak(NULL)),
					 -1, 0, onchaind_memleak_req_done, leaks),
					leaks);
			} else if (streq(c->owner->name, "dualopend")) {
				start_leak_request(subd_req(c, c->owner,
					 take(towire_dualopend_dev_memleak(NULL)),
					 -1, 0, dualopend_memleak_req_done, leaks),
					leaks);
			}
		}
	}
}
