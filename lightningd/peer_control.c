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
#include <common/json_helpers.h>
#include <common/json_tok.h>
#include <common/jsonrpc_errors.h>
#include <common/key_derive.h>
#include <common/param.h>
#include <common/per_peer_state.h>
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
#include <hsmd/hsmd_wiregen.h>
#include <inttypes.h>
#include <lightningd/bitcoind.h>
#include <lightningd/chaintopology.h>
#include <lightningd/channel.h>
#include <lightningd/channel_control.h>
#include <lightningd/closing_control.h>
#include <lightningd/connect_control.h>
#include <lightningd/dual_open_control.h>
#include <lightningd/hsm_control.h>
#include <lightningd/json.h>
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
#include <lightningd/peer_htlcs.h>
#include <lightningd/plugin_hook.h>
#include <lightningd/subd.h>
#include <limits.h>
#include <onchaind/onchaind_wiregen.h>
#include <stdlib.h>
#include <unistd.h>
#include <wally_bip32.h>
#include <wire/common_wiregen.h>
#include <wire/onion_wire.h>
#include <wire/wire_sync.h>

static void destroy_peer(struct peer *peer)
{
	list_del_from(&peer->ld->peers, &peer->list);
}

static void peer_update_features(struct peer *peer,
				 const u8 *their_features TAKES)
{
	tal_free(peer->their_features);
	peer->their_features = tal_dup_talarr(peer, u8, their_features);
}

struct peer *new_peer(struct lightningd *ld, u64 dbid,
		      const struct node_id *id,
		      const struct wireaddr_internal *addr,
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
	peer->their_features = NULL;
	list_head_init(&peer->channels);
	peer->direction = node_id_idx(&peer->ld->id, &peer->id);
#if DEVELOPER
	peer->ignore_htlcs = false;
#endif

	list_add_tail(&ld->peers, &peer->list);
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
		wallet_peer_delete(peer->ld->wallet, peer->dbid);
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
			wallet_peer_delete(peer->ld->wallet, peer->dbid);
			peer->dbid = 0;
		}
		return;
	}
	delete_peer(peer);
}

struct peer *find_peer_by_dbid(struct lightningd *ld, u64 dbid)
{
	struct peer *p;

	list_for_each(&ld->peers, p, list)
		if (p->dbid == dbid)
			return p;
	return NULL;
}

struct peer *peer_by_id(struct lightningd *ld, const struct node_id *id)
{
	struct peer *p;

	list_for_each(&ld->peers, p, list)
		if (node_id_eq(&p->id, id))
			return p;
	return NULL;
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

	if (!bip32_pubkey(ld->wallet->bip32_base, &shutdownkey, keyidx))
		return NULL;

	return scriptpubkey_p2wpkh(ctx, &shutdownkey);
}

static void sign_last_tx(struct channel *channel,
			 struct bitcoin_tx *last_tx,
			 struct bitcoin_signature *last_sig)
{
	struct lightningd *ld = channel->peer->ld;
	struct bitcoin_signature sig;
	u8 *msg, **witness;

	assert(!last_tx->wtx->inputs[0].witness);
	msg = towire_hsmd_sign_commitment_tx(tmpctx,
					     &channel->peer->id,
					     channel->dbid,
					     last_tx,
					     &channel->channel_info
					     .remote_fundingkey);

	if (!wire_sync_write(ld->hsm_fd, take(msg)))
		fatal("Could not write to HSM: %s", strerror(errno));

	msg = wire_sync_read(tmpctx, ld->hsm_fd);
	if (!fromwire_hsmd_sign_commitment_tx_reply(msg, &sig))
		fatal("HSM gave bad sign_commitment_tx_reply %s",
		      tal_hex(tmpctx, msg));

	witness =
	    bitcoin_witness_2of2(last_tx, last_sig,
				 &sig, &channel->channel_info.remote_fundingkey,
				 &channel->local_funding_pubkey);

	bitcoin_tx_input_set_witness(last_tx, 0, take(witness));
}

static void remove_sig(struct bitcoin_tx *signed_tx)
{
	bitcoin_tx_input_set_witness(signed_tx, 0, NULL);
}

static bool invalid_last_tx(const struct bitcoin_tx *tx)
{
	/* This problem goes back further, but was discovered just before the
	 * 0.7.1 release. */
#ifdef COMPAT_V070
	/* Old bug had commitment txs with no outputs; bitcoin_txid asserts. */
	return tx->wtx->num_outputs == 0;
#else
	return false;
#endif
}

static void sign_and_send_last(struct lightningd *ld,
			       struct channel *channel,
			       struct bitcoin_tx *last_tx,
			       struct bitcoin_signature *last_sig)
{
	struct bitcoin_txid txid;

	sign_last_tx(channel, last_tx, last_sig);
	bitcoin_txid(last_tx, &txid);
	wallet_transaction_add(ld->wallet, last_tx->wtx, 0, 0);
	wallet_transaction_annotate(ld->wallet, &txid,
				    channel->last_tx_type,
				    channel->dbid);

	/* Keep broadcasting until we say stop (can fail due to dup,
	 * if they beat us to the broadcast). */
	broadcast_tx(ld->topology, channel, last_tx, NULL);

	remove_sig(last_tx);
}

void drop_to_chain(struct lightningd *ld, struct channel *channel,
		   bool cooperative)
{
	struct channel_inflight *inflight;
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
	} else if (invalid_last_tx(channel->last_tx)) {
		log_broken(channel->log,
			   "Cannot broadcast our commitment tx:"
			   " it's invalid! (ancient channel?)");
	} else {
		/* We need to drop *every* commitment transaction to chain */
		if (!cooperative && !list_empty(&channel->inflights)) {
			list_for_each(&channel->inflights, inflight, list)
				sign_and_send_last(ld, channel,
						   inflight->last_tx,
						   &inflight->last_sig);
		} else
			sign_and_send_last(ld, channel, channel->last_tx,
					   &channel->last_sig);
	}

	resolve_close_command(ld, channel, cooperative);
}

void channel_errmsg(struct channel *channel,
		    struct per_peer_state *pps,
		    const struct channel_id *channel_id UNUSED,
		    const char *desc,
		    bool warning,
		    const u8 *err_for_them)
{
	notify_disconnect(channel->peer->ld, &channel->peer->id);

	/* Clean up any in-progress open attempts */
	channel_cleanup_commands(channel, desc);

	if (channel_unsaved(channel)) {
		log_info(channel->log, "%s", "Unsaved peer failed."
			 " Disconnecting and deleting channel.");
		delete_channel(channel);
		return;
	}

	/* No per_peer_state means a subd crash or disconnection. */
	if (!pps) {
		/* If the channel is unsaved, we forget it */
		channel_fail_reconnect(channel, "%s: %s",
				       channel->owner->name, desc);
		return;
	}

	/* Do we have an error to send? */
	if (err_for_them && !channel->error && !warning)
		channel->error = tal_dup_talarr(channel, u8, err_for_them);

	/* Other implementations chose to ignore errors early on.  Not
	 * surprisingly, they now spew out spurious errors frequently,
	 * and we would close the channel on them.  We now support warnings
	 * for this case. */
	if (warning) {
		channel_fail_reconnect_later(channel, "%s WARNING: %s",
					     channel->owner->name, desc);
		return;
	}

	/* BOLT #1:
	 *
	 * A sending node:
	 *...
	 *   - when `channel_id` is 0:
	 *    - MUST fail all channels with the receiving node.
	 *    - MUST close the connection.
	 */
	/* FIXME: Close if it's an all-channels error sent or rcvd */

	/* BOLT #1:
	 *
	 * A sending node:
	 *  - when sending `error`:
	 *    - MUST fail the channel referred to by the error message.
	 *...
	 * The receiving node:
	 *  - upon receiving `error`:
	 *    - MUST fail the channel referred to by the error message,
	 *      if that channel is with the sending node.
	 */

	/* We should immediately forget the channel if we receive error during
	 * CHANNELD_AWAITING_LOCKIN if we are fundee. */
	if (!err_for_them && channel->opener == REMOTE
	    && channel->state == CHANNELD_AWAITING_LOCKIN)
		channel_fail_forget(channel, "%s: %s ERROR %s",
				    channel->owner->name,
				    err_for_them ? "sent" : "received", desc);
	else
		channel_fail_permanent(channel,
				       err_for_them ? REASON_LOCAL : REASON_PROTOCOL,
				       "%s: %s ERROR %s",
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
	for (hin = htlc_in_map_first(&ld->htlcs_in, &ini);
	     hin;
	     hin = htlc_in_map_next(&ld->htlcs_in, &ini)) {
		if (hin->key.channel != channel)
			continue;

		json_object_start(response, NULL);
		json_add_string(response, "direction", "in");
		json_add_u64(response, "id", hin->key.id);
		json_add_amount_msat_compat(response, hin->msat,
					    "msatoshi", "amount_msat");
		json_add_u32(response, "expiry", hin->cltv_expiry);
		json_add_sha256(response, "payment_hash", &hin->payment_hash);
		json_add_string(response, "state",
				htlc_state_name(hin->hstate));
		if (htlc_is_trimmed(REMOTE, hin->msat, local_feerate,
				    channel->our_config.dust_limit, LOCAL,
				    channel_has(channel, OPT_ANCHOR_OUTPUTS)))
			json_add_bool(response, "local_trimmed", true);
		if (hin->status != NULL)
			json_add_string(response, "status", hin->status);
		json_object_end(response);
	}

	for (hout = htlc_out_map_first(&ld->htlcs_out, &outi);
	     hout;
	     hout = htlc_out_map_next(&ld->htlcs_out, &outi)) {
		if (hout->key.channel != channel)
			continue;

		json_object_start(response, NULL);
		json_add_string(response, "direction", "out");
		json_add_u64(response, "id", hout->key.id);
		json_add_amount_msat_compat(response, hout->msat,
					    "msatoshi", "amount_msat");
		json_add_u64(response, "expiry", hout->cltv_expiry);
		json_add_sha256(response, "payment_hash", &hout->payment_hash);
		json_add_string(response, "state",
				htlc_state_name(hout->hstate));
		if (htlc_is_trimmed(LOCAL, hout->msat, local_feerate,
				    channel->our_config.dust_limit, LOCAL,
				    channel_has(channel, OPT_ANCHOR_OUTPUTS)))
			json_add_bool(response, "local_trimmed", true);
		json_object_end(response);
	}
	json_array_end(response);
}

/* We do this replication manually because it's an array. */
static void json_add_sat_only(struct json_stream *result,
			      const char *fieldname,
			      struct amount_sat sat)
{
	struct amount_msat msat;

	if (amount_sat_to_msat(&msat, sat))
		json_add_string(result, fieldname,
				type_to_string(tmpctx, struct amount_msat, &msat));
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

	if (side == LOCAL)
		dust_limit = channel->our_config.dust_limit;
	if (side == REMOTE)
		dust_limit = channel->channel_info.their_config.dust_limit;

	/* Assume we tried to add "amount" */
	if (!htlc_is_trimmed(side, amount, feerate, dust_limit, side,
			     option_anchor_outputs))
		num_untrimmed_htlcs++;

	for (hin = htlc_in_map_first(&ld->htlcs_in, &ini);
	     hin;
	     hin = htlc_in_map_next(&ld->htlcs_in, &ini)) {
		if (hin->key.channel != channel)
			continue;
		if (!htlc_is_trimmed(!side, hin->msat, feerate, dust_limit,
				     side, option_anchor_outputs))
			num_untrimmed_htlcs++;
	}
	for (hout = htlc_out_map_first(&ld->htlcs_out, &outi);
	     hout;
	     hout = htlc_out_map_next(&ld->htlcs_out, &outi)) {
		if (hout->key.channel != channel)
			continue;
		if (!htlc_is_trimmed(side, hout->msat, feerate, dust_limit,
				     side, option_anchor_outputs))
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
				 option_anchor_outputs);

	if (option_anchor_outputs) {
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

	for (hout = htlc_out_map_first(&ld->htlcs_out, &outi);
	     hout;
	     hout = htlc_out_map_next(&ld->htlcs_out, &outi)) {
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

	for (hin = htlc_in_map_first(&ld->htlcs_in, &ini);
	     hin;
	     hin = htlc_in_map_next(&ld->htlcs_in, &ini)) {
		if (hin->key.channel != channel)
			continue;
		if (!amount_msat_sub(amount, *amount, hin->msat))
			*amount = AMOUNT_MSAT(0);
	}
}

static struct amount_msat channel_amount_spendable(const struct channel *channel)
{
	struct amount_msat spendable;

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

	/* We can't offer an HTLC over the max payment threshold either. */
	if (amount_msat_greater(spendable, chainparams->max_payment))
		spendable = chainparams->max_payment;

	return spendable;
}

struct amount_msat channel_amount_receivable(const struct channel *channel)
{
	struct amount_msat their_msat, receivable;

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

	/* They can't offer an HTLC over the max payment threshold either. */
	if (amount_msat_greater(receivable, chainparams->max_payment))
		receivable = chainparams->max_payment;

	return receivable;
}

static void json_add_channel(struct lightningd *ld,
			     struct json_stream *response, const char *key,
			     const struct channel *channel)
{
	struct channel_stats channel_stats;
	struct amount_msat funding_msat, peer_msats, our_msats;
	struct amount_sat peer_funded_sats;
	struct peer *p = channel->peer;
	struct state_change_entry *state_changes;
	u32 feerate;

	json_object_start(response, key);
	json_add_string(response, "state", channel_state_name(channel));
	if (channel->last_tx && !invalid_last_tx(channel->last_tx)) {
		struct bitcoin_txid txid;
		bitcoin_txid(channel->last_tx, &txid);

		json_add_txid(response, "scratch_txid", &txid);
		if (deprecated_apis)
			json_add_amount_sat_only(response, "last_tx_fee",
						 bitcoin_tx_compute_fee(channel->last_tx));
		json_add_amount_sat_only(response, "last_tx_fee_msat",
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

	if (channel->scid) {
		json_add_short_channel_id(response, "short_channel_id",
					  channel->scid);
		json_add_num(response, "direction",
			     node_id_idx(&ld->id, &channel->peer->id));
	}

	json_add_string(response, "channel_id",
			type_to_string(tmpctx, struct channel_id, &channel->cid));
	json_add_txid(response, "funding_txid", &channel->funding.txid);

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
			json_add_amount_sat_only(response,
						 "total_funding_msat",
						 inflight->funding->total_funds);
			json_add_amount_sat_only(response,
						 "our_funding_msat",
						 inflight->funding->our_funds);
			/* Add the expected commitment tx id also */
			bitcoin_txid(inflight->last_tx, &txid);
			json_add_txid(response, "scratch_txid", &txid);
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
	else if (deprecated_apis)
		json_add_null(response, "closer");

	json_array_start(response, "features");
	if (channel_has(channel, OPT_STATIC_REMOTEKEY))
		json_add_string(response, NULL, "option_static_remotekey");
	if (channel_has(channel, OPT_ANCHOR_OUTPUTS))
		json_add_string(response, NULL, "option_anchor_outputs");
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
	if (!amount_sat_to_msat(&peer_msats, peer_funded_sats)) {
		log_broken(channel->log,
			   "Overflow converting peer sats %s to msat",
			   type_to_string(tmpctx, struct amount_sat,
					  &peer_funded_sats));
		peer_msats = AMOUNT_MSAT(0);
	}
	if (!amount_sat_to_msat(&our_msats, channel->our_funds)) {
		log_broken(channel->log,
			   "Overflow converting peer sats %s to msat",
			   type_to_string(tmpctx, struct amount_sat,
					  &channel->our_funds));
		our_msats = AMOUNT_MSAT(0);
	}

	if (deprecated_apis) {
		json_object_start(response, "funding_allocation_msat");
		json_add_u64(response, node_id_to_hexstr(tmpctx, &p->id),
			     peer_msats.millisatoshis); /* Raw: JSON field */
		json_add_u64(response, node_id_to_hexstr(tmpctx, &ld->id),
			     our_msats.millisatoshis); /* Raw: JSON field */
		json_object_end(response);

		json_object_start(response, "funding_msat");
		json_add_sat_only(response,
				  node_id_to_hexstr(tmpctx, &p->id),
				  peer_funded_sats);
		json_add_sat_only(response,
				  node_id_to_hexstr(tmpctx, &ld->id),
				  channel->our_funds);
		json_object_end(response);
	}

	json_object_start(response, "funding");
	json_add_sat_only(response, "local_msat", channel->our_funds);
	json_add_sat_only(response, "remote_msat", peer_funded_sats);
	json_object_end(response);

	if (!amount_sat_to_msat(&funding_msat, channel->funding_sats)) {
		log_broken(channel->log,
			   "Overflow converting funding %s",
			   type_to_string(tmpctx, struct amount_sat,
					  &channel->funding_sats));
		funding_msat = AMOUNT_MSAT(0);
	}
	json_add_amount_msat_compat(response, channel->our_msat,
				    "msatoshi_to_us", "to_us_msat");
	json_add_amount_msat_compat(response, channel->msat_to_us_min,
				    "msatoshi_to_us_min", "min_to_us_msat");
	json_add_amount_msat_compat(response, channel->msat_to_us_max,
				    "msatoshi_to_us_max", "max_to_us_msat");
	json_add_amount_msat_compat(response, funding_msat,
				    "msatoshi_total", "total_msat");

	/* routing fees */
	json_add_amount_msat_only(response, "fee_base_msat",
				  amount_msat(channel->feerate_base));
	json_add_u32(response, "fee_proportional_millionths",
		     channel->feerate_ppm);

	/* channel config */
	json_add_amount_sat_compat(response,
				   channel->our_config.dust_limit,
				   "dust_limit_satoshis", "dust_limit_msat");
	json_add_amount_msat_compat(response,
				    channel->our_config.max_htlc_value_in_flight,
				    "max_htlc_value_in_flight_msat",
				    "max_total_htlc_in_msat");

	/* The `channel_reserve_satoshis` is imposed on
	 * the *other* side (see `channel_reserve_msat`
	 * function in, it uses `!side` to flip sides).
	 * So our configuration `channel_reserve_satoshis`
	 * is imposed on their side, while their
	 * configuration `channel_reserve_satoshis` is
	 * imposed on ours. */
	json_add_amount_sat_compat(response,
				   channel->our_config.channel_reserve,
				   "their_channel_reserve_satoshis",
				   "their_reserve_msat");
	json_add_amount_sat_compat(response,
				   channel->channel_info.their_config.channel_reserve,
				   "our_channel_reserve_satoshis",
				   "our_reserve_msat");

	/* append spendable to JSON output */
	json_add_amount_msat_compat(response,
				    channel_amount_spendable(channel),
				    "spendable_msatoshi", "spendable_msat");

	/* append receivable to JSON output */
	json_add_amount_msat_compat(response,
				    channel_amount_receivable(channel),
				    "receivable_msatoshi", "receivable_msat");

	json_add_amount_msat_compat(response,
				    channel->our_config.htlc_minimum,
				    "htlc_minimum_msat",
				    "minimum_htlc_in_msat");

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
				 &state_changes[i].timestamp);
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
	json_add_amount_msat_compat(response,
				    channel_stats.in_msatoshi_offered,
				    "in_msatoshi_offered",
				    "in_offered_msat");
	json_add_u64(response, "in_payments_fulfilled",
		     channel_stats.in_payments_fulfilled);
	json_add_amount_msat_compat(response,
				    channel_stats.in_msatoshi_fulfilled,
				    "in_msatoshi_fulfilled",
				    "in_fulfilled_msat");
	json_add_u64(response, "out_payments_offered",
		     channel_stats.out_payments_offered);
	json_add_amount_msat_compat(response,
				    channel_stats.out_msatoshi_offered,
				    "out_msatoshi_offered",
				    "out_offered_msat");
	json_add_u64(response, "out_payments_fulfilled",
		     channel_stats.out_payments_fulfilled);
	json_add_amount_msat_compat(response,
				    channel_stats.out_msatoshi_fulfilled,
				    "out_msatoshi_fulfilled",
				    "out_fulfilled_msat");

	json_add_htlcs(ld, response, channel);
	json_object_end(response);
}

struct peer_connected_hook_payload {
	struct lightningd *ld;
	struct channel *channel;
	struct wireaddr_internal addr;
	bool incoming;
	struct peer *peer;
	struct per_peer_state *pps;
	u8 *error;
};

static void
peer_connected_serialize(struct peer_connected_hook_payload *payload,
			 struct json_stream *stream, struct plugin *plugin)
{
	const struct peer *p = payload->peer;
	json_object_start(stream, "peer");
	json_add_node_id(stream, "id", &p->id);
	json_add_string(stream, "direction", payload->incoming ? "in" : "out");
	json_add_string(
	    stream, "addr",
	    type_to_string(stream, struct wireaddr_internal, &payload->addr));
	json_add_hex_talarr(stream, "features", p->their_features);
	json_object_end(stream); /* .peer */
}

static void peer_connected_hook_final(struct peer_connected_hook_payload *payload STEALS)
{
	struct lightningd *ld = payload->ld;
	struct channel *channel = payload->channel;
	struct wireaddr_internal addr = payload->addr;
	struct peer *peer = payload->peer;
	u8 *error;

	/* Whatever happens, we free payload (it's currently a child
	 * of the peer, which may be freed if we fail to start
	 * subd). */
	tal_steal(tmpctx, payload);

	/* Check for specific errors of a hook */
	if (payload->error) {
		error = payload->error;
		goto send_error;
	}

	if (channel) {
		log_debug(channel->log, "Peer has reconnected, state %s",
			  channel_state_name(channel));

		/* If we have a canned error, deliver it now. */
		if (channel->error) {
			error = channel->error;
			goto send_error;
		}

#if DEVELOPER
		if (dev_disconnect_permanent(ld)) {
			channel_fail_permanent(channel, REASON_LOCAL,
					       "dev_disconnect permfail");
			error = channel->error;
			goto send_error;
		}
#endif

		switch (channel->state) {
		case ONCHAIN:
		case FUNDING_SPEND_SEEN:
		case CLOSINGD_COMPLETE:
			/* Channel is supposed to be active!*/
			abort();
		case CLOSED:
			/* Channel should not have been loaded */
			abort();

		/* We consider this "active" but we only send an error */
		case AWAITING_UNILATERAL: {
			/* channel->error is not saved in db, so this can
			 * happen if we restart. */
			error = towire_errorfmt(tmpctx, &channel->cid,
						"Awaiting unilateral close");
			goto send_error;
		}
		case DUALOPEND_OPEN_INIT:
		case DUALOPEND_AWAITING_LOCKIN:
			assert(!channel->owner);
			channel->peer->addr = addr;
			channel->peer->connected_incoming = payload->incoming;
			peer_restart_dualopend(peer, payload->pps, channel);
			return;
		case CHANNELD_AWAITING_LOCKIN:
		case CHANNELD_NORMAL:
		case CHANNELD_SHUTTING_DOWN:
		case CLOSINGD_SIGEXCHANGE:
			assert(!channel->owner);
			channel->peer->addr = addr;
			channel->peer->connected_incoming = payload->incoming;
			peer_start_channeld(channel, payload->pps, NULL, true,
					    NULL);
			return;
		}
		abort();
	}

	notify_connect(ld, &peer->id, payload->incoming, &addr);

	if (feature_negotiated(ld->our_features,
			       peer->their_features,
			       OPT_DUAL_FUND)) {
		if (channel && !list_empty(&channel->inflights)) {
			assert(!channel->owner);
			assert(channel->state == DUALOPEND_OPEN_INIT
			       || channel->state == DUALOPEND_AWAITING_LOCKIN
			       || channel->state == AWAITING_UNILATERAL);
			channel->peer->addr = addr;
			channel->peer->connected_incoming = payload->incoming;
			peer_restart_dualopend(peer, payload->pps, channel);
		} else
			peer_start_dualopend(peer, payload->pps);
	} else
		peer_start_openingd(peer, payload->pps);
	return;

send_error:
	log_debug(ld->log, "Telling connectd to send error %s",
		  tal_hex(tmpctx, error));
	/* Get connectd to send error and close. */
	subd_send_msg(ld->connectd,
		      take(towire_connectd_peer_final_msg(NULL, &peer->id,
							  payload->pps, error)));
	subd_send_fd(ld->connectd, payload->pps->peer_fd);
	subd_send_fd(ld->connectd, payload->pps->gossip_fd);
	subd_send_fd(ld->connectd, payload->pps->gossip_store_fd);
	/* Don't close those fds! */
	payload->pps->peer_fd
		= payload->pps->gossip_fd
		= payload->pps->gossip_store_fd
		= -1;
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

REGISTER_PLUGIN_HOOK(peer_connected,
		     peer_connected_hook_deserialize,
		     peer_connected_hook_final,
		     peer_connected_serialize,
		     struct peer_connected_hook_payload *);

/* Connectd tells us a peer has connected: it never hands us duplicates, since
 * it holds them until we say peer_died. */
void peer_connected(struct lightningd *ld, const u8 *msg,
		    int peer_fd, int gossip_fd, int gossip_store_fd)
{
	struct node_id id;
	u8 *their_features;
	struct peer *peer;
	struct peer_connected_hook_payload *hook_payload;

	hook_payload = tal(NULL, struct peer_connected_hook_payload);
	hook_payload->ld = ld;
	hook_payload->error = NULL;
	if (!fromwire_connectd_peer_connected(hook_payload, msg,
					      &id, &hook_payload->addr,
					      &hook_payload->incoming,
					      &hook_payload->pps,
					      &their_features))
		fatal("Connectd gave bad CONNECT_PEER_CONNECTED message %s",
		      tal_hex(msg, msg));

	per_peer_state_set_fds(hook_payload->pps,
			       peer_fd, gossip_fd, gossip_store_fd);

	/* If we're already dealing with this peer, hand off to correct
	 * subdaemon.  Otherwise, we'll hand to openingd to wait there. */
	peer = peer_by_id(ld, &id);
	if (!peer)
		peer = new_peer(ld, 0, &id, &hook_payload->addr,
				hook_payload->incoming);

	tal_steal(peer, hook_payload);
	hook_payload->peer = peer;

	peer_update_features(peer, their_features);

	/* Complete any outstanding connect commands. */
	connect_succeeded(ld, peer, hook_payload->incoming, &hook_payload->addr);

	/* Can't be opening, since we wouldn't have sent peer_disconnected. */
	assert(!peer->uncommitted_channel);
	hook_payload->channel = peer_active_channel(peer);

	/* It might be v2 opening, though, since we hang onto these */
	if (!hook_payload->channel)
		hook_payload->channel = peer_unsaved_channel(peer);

	plugin_hook_call_peer_connected(ld, hook_payload);
}

static bool check_funding_details(const struct bitcoin_tx *tx,
				  const u8 *wscript,
				  struct amount_sat funding,
				  u32 funding_outnum)
{
	struct amount_asset asset =
	    bitcoin_tx_output_get_amount(tx, funding_outnum);

	if (!amount_asset_is_main(&asset))
		return false;

	if (funding_outnum >= tx->wtx->num_outputs)
		return false;

	if (!amount_sat_eq(amount_asset_to_sat(&asset), funding))
		return false;

	return scripteq(scriptpubkey_p2wsh(tmpctx, wscript),
			bitcoin_tx_output_get_script(tmpctx, tx,
						     funding_outnum));
}


/* FIXME: Unify our watch code so we get notified by txout, instead, like
 * the wallet code does. */
static bool check_funding_tx(const struct bitcoin_tx *tx,
			     const struct channel *channel)
{
	struct channel_inflight *inflight;
	const u8 *wscript;
	wscript = bitcoin_redeem_2of2(tmpctx,
				      &channel->local_funding_pubkey,
				      &channel->channel_info.remote_fundingkey);

	/* Since we've enabled "RBF" for funding transactions,
	 * it's possible that it's one of "inflights".
	 * Worth noting that this check was added to prevent
	 * a peer from sending us a 'bogus' transaction id (that didn't
	 * actually contain the funding output). As of v2 (where
	 * RBF is introduced), this isn't a problem so much as
	 * both sides have full access to the funding transaction */
	if (check_funding_details(tx, wscript, channel->funding_sats,
				  channel->funding.n))
		return true;

	list_for_each(&channel->inflights, inflight, list) {
		if (check_funding_details(tx, wscript,
					  inflight->funding->total_funds,
					  inflight->funding->outpoint.n))
			return true;
	}
	return false;
}

static void update_channel_from_inflight(struct lightningd *ld,
					 struct channel *channel,
					 struct channel_inflight *inflight)
{
	struct wally_psbt *psbt_copy;

	channel->funding = inflight->funding->outpoint;
	channel->funding_sats = inflight->funding->total_funds;
	channel->our_funds = inflight->funding->our_funds;

	/* Lease infos ! */
	channel->lease_expiry = inflight->lease_expiry;
	tal_free(channel->lease_commit_sig);
	channel->lease_commit_sig
		= tal_steal(channel, inflight->lease_commit_sig);
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
			    &inflight->last_sig,
			    TX_CHANNEL_UNILATERAL);

	/* Update the reserve */
	channel_update_reserve(channel,
			       &channel->channel_info.their_config,
			       inflight->funding->total_funds);

	wallet_channel_save(ld->wallet, channel);
}

static enum watch_result funding_depth_cb(struct lightningd *ld,
					   struct channel *channel,
					   const struct bitcoin_txid *txid,
					   const struct bitcoin_tx *tx,
					   unsigned int depth)
{
	const char *txidstr;
	struct short_channel_id scid;

	/* Sanity check */
	if (!check_funding_tx(tx, channel)) {
		channel_internal_error(channel, "Bad tx %s: %s",
				       type_to_string(tmpctx,
						      struct bitcoin_txid, txid),
				       type_to_string(tmpctx,
						      struct bitcoin_tx, tx));
		return DELETE_WATCH;
	}

	txidstr = type_to_string(tmpctx, struct bitcoin_txid, txid);
	log_debug(channel->log, "Funding tx %s depth %u of %u",
		  txidstr, depth, channel->minimum_depth);
	tal_free(txidstr);

	bool min_depth_reached = depth >= channel->minimum_depth;

	/* Reorg can change scid, so always update/save scid when possible (depth=0
	 * means the stale block with our funding tx was removed) */
	if ((min_depth_reached && !channel->scid) || (depth && channel->scid)) {
		struct txlocator *loc;
		struct channel_inflight *inf;

		/* Update the channel's info to the correct tx, if needed to
		 * It's possible an 'inflight' has reached depth */
		if (!list_empty(&channel->inflights)) {
			inf = channel_inflight_find(channel, txid);
			if (!inf) {
				channel_fail_permanent(channel, REASON_LOCAL,
					"Txid %s for channel"
					" not found in inflights. (peer %s)",
					type_to_string(tmpctx,
						       struct bitcoin_txid,
						       txid),
					type_to_string(tmpctx,
						       struct node_id,
						       &channel->peer->id));
				return DELETE_WATCH;
			}
			update_channel_from_inflight(ld, channel, inf);
		}

		wallet_annotate_txout(ld->wallet, &channel->funding,
				      TX_CHANNEL_FUNDING, channel->dbid);
		loc = wallet_transaction_locate(tmpctx, ld->wallet, txid);
		if (!mk_short_channel_id(&scid,
					 loc->blkheight, loc->index,
					 channel->funding.n)) {
			channel_fail_permanent(channel,
					       REASON_LOCAL,
					       "Invalid funding scid %u:%u:%u",
					       loc->blkheight, loc->index,
					       channel->funding.n);
			return DELETE_WATCH;
		}

		/* If we restart, we could already have peer->scid from database */
		if (!channel->scid) {
			channel->scid = tal(channel, struct short_channel_id);
			*channel->scid = scid;
			wallet_channel_save(ld->wallet, channel);

		} else if (!short_channel_id_eq(channel->scid, &scid)) {
			/* This normally restarts channeld, initialized with updated scid
			 * and also adds it (at least our halve_chan) to rtable. */
			channel_fail_reconnect(channel,
					       "short_channel_id changed to %s (was %s)",
					       short_channel_id_to_str(tmpctx, &scid),
					       short_channel_id_to_str(tmpctx, channel->scid));

			*channel->scid = scid;
			wallet_channel_save(ld->wallet, channel);
			return KEEP_WATCHING;
		}
	}

	/* Try to tell subdaemon */
	if (!channel_tell_depth(ld, channel, txid, depth))
		return KEEP_WATCHING;

	if (!min_depth_reached)
		return KEEP_WATCHING;

	/* We keep telling it depth/scid until we get to announce depth. */
	if (depth < ANNOUNCE_MIN_DEPTH)
		return KEEP_WATCHING;

	return DELETE_WATCH;
}

static enum watch_result funding_spent(struct channel *channel,
				       const struct bitcoin_tx *tx,
				       size_t inputnum UNUSED,
				       const struct block *block)
{
	struct bitcoin_txid txid;
	bitcoin_txid(tx, &txid);

	wallet_channeltxs_add(channel->peer->ld->wallet, channel,
			      WIRE_ONCHAIND_INIT, &txid, 0, block->height);
	return onchaind_funding_spent(channel, tx, block->height, false);
}

void channel_watch_wrong_funding(struct lightningd *ld, struct channel *channel)
{
	/* Watch the "wrong" funding too, in case we spend it. */
	if (channel->shutdown_wrong_funding) {
		/* FIXME: Remove arg from cb? */
		watch_txo(channel, ld->topology, channel,
			  channel->shutdown_wrong_funding,
			  funding_spent);
	}
}

void channel_watch_funding(struct lightningd *ld, struct channel *channel)
{
	/* FIXME: Remove arg from cb? */
	watch_txid(channel, ld->topology, channel,
		   &channel->funding.txid, funding_depth_cb);
	watch_txo(channel, ld->topology, channel,
		  &channel->funding,
		  funding_spent);
	channel_watch_wrong_funding(ld, channel);
}

static void channel_watch_inflight(struct lightningd *ld,
				   struct channel *channel,
				   struct channel_inflight *inflight)
{
	/* FIXME: Remove arg from cb? */
	watch_txid(channel, ld->topology, channel,
		   &inflight->funding->outpoint.txid, funding_depth_cb);
	watch_txo(channel, ld->topology, channel,
		  &inflight->funding->outpoint,
		  funding_spent);
}

static void json_add_peer(struct lightningd *ld,
			  struct json_stream *response,
			  struct peer *p,
			  const enum log_level *ll)
{
	bool connected;
	struct channel *channel;

	json_object_start(response, NULL);
	json_add_node_id(response, "id", &p->id);

	/* Channel is also connected if uncommitted channel */
	if (p->uncommitted_channel)
		connected = true;
	else {
		channel = peer_active_channel(p);
		if (!channel)
			channel = peer_unsaved_channel(p);
		connected = channel && channel->connected;
	}
	json_add_bool(response, "connected", connected);

	/* If it's not connected, features are unreliable: we don't
	 * store them in the database, and they would only reflect
	 * their features *last* time they connected. */
	if (connected) {
		json_array_start(response, "netaddr");
		json_add_string(response, NULL,
				type_to_string(tmpctx,
					       struct wireaddr_internal,
					       &p->addr));
		json_array_end(response);
		json_add_hex_talarr(response, "features", p->their_features);
	}

	json_array_start(response, "channels");
	json_add_uncommitted_channel(response, p->uncommitted_channel);

	list_for_each(&p->channels, channel, list) {
		if (channel_unsaved(channel))
			json_add_unsaved_channel(response, channel);
		else
			json_add_channel(ld, response, NULL, channel);
	}
	json_array_end(response);

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
		list_for_each(&cmd->ld->peers, peer, list)
			json_add_peer(cmd->ld, response, peer, ll);
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

struct command_result *
command_find_channel(struct command *cmd,
		     const char *buffer, const jsmntok_t *tok,
		     struct channel **channel)
{
	struct lightningd *ld = cmd->ld;
	struct channel_id cid;
	struct short_channel_id scid;
	struct peer *peer;

	if (json_tok_channel_id(buffer, tok, &cid)) {
		list_for_each(&ld->peers, peer, list) {
			*channel = peer_active_channel(peer);
			if (!*channel)
				continue;
			if (channel_id_eq(&(*channel)->cid, &cid))
				return NULL;
		}
		return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
				    "Channel ID not found: '%.*s'",
				    tok->end - tok->start,
				    buffer + tok->start);
	} else if (json_to_short_channel_id(buffer, tok, &scid)) {
		*channel = active_channel_by_scid(ld, &scid);
		if (*channel)
			return NULL;

		return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
				    "Short channel ID not found: '%.*s'",
				    tok->end - tok->start,
				    buffer + tok->start);
	} else {
		return command_fail_badparam(cmd, "id", buffer, tok,
					     "should be a channel ID or short channel ID");
	}
}

static void activate_peer(struct peer *peer, u32 delay)
{
	u8 *msg;
	struct channel *channel;
	struct channel_inflight *inflight;
	struct lightningd *ld = peer->ld;

	/* We can only have one active channel: make sure connectd
	 * knows to try reconnecting. */
	channel = peer_active_channel(peer);
	if (channel && ld->reconnect) {
		if (delay > 0) {
			channel_set_billboard(channel, false,
					      tal_fmt(tmpctx,
						      "Will attempt reconnect "
						      "in %u seconds",
						      delay));
			delay_then_reconnect(channel, delay,
					     peer->connected_incoming
					     ? NULL
					     : &peer->addr);
		} else {
			msg = towire_connectd_connect_to_peer(NULL,
							      &peer->id, 0,
							      peer->connected_incoming
							      ? NULL
							      : &peer->addr);
			subd_send_msg(ld->connectd, take(msg));
			channel_set_billboard(channel, false,
					      "Attempting to reconnect");
		}
	}

	list_for_each(&peer->channels, channel, list) {
		if (channel_unsaved(channel))
			continue;
		/* Watching lockin may be unnecessary, but it's harmless. */
		channel_watch_funding(ld, channel);

		/* Also watch any inflight txs */
		list_for_each(&channel->inflights, inflight, list) {
			/* Don't double watch the txid that's also in
			 * channel->funding_txid */
			if (bitcoin_txid_eq(&channel->funding.txid,
					    &inflight->funding->outpoint.txid))
				continue;

			channel_watch_inflight(ld, channel, inflight);
		}
	}
}

void activate_peers(struct lightningd *ld)
{
	struct peer *p;
	/* Avoid thundering herd: after first five, delay by 1 second. */
	int delay = -5;

	list_for_each(&ld->peers, p, list) {
		activate_peer(p, delay > 0 ? delay : 0);
		delay++;
	}
}

/* Pull peers, channels and HTLCs from db, and wire them up. */
struct htlc_in_map *load_channels_from_wallet(struct lightningd *ld)
{
	struct peer *peer;
	struct htlc_in_map *unconnected_htlcs_in = tal(ld, struct htlc_in_map);

	/* Load channels from database */
	if (!wallet_init_channels(ld->wallet))
		fatal("Could not load channels from the database");

	/* First we load the incoming htlcs */
	list_for_each(&ld->peers, peer, list) {
		struct channel *channel;

		list_for_each(&peer->channels, channel, list) {
			if (!wallet_htlcs_load_in_for_channel(ld->wallet,
							      channel,
							      &ld->htlcs_in)) {
				fatal("could not load htlcs for channel");
			}
		}
	}

	/* Make a copy of the htlc_map: entries removed as they're matched */
	htlc_in_map_copy(unconnected_htlcs_in, &ld->htlcs_in);

	/* Now we load the outgoing HTLCs, so we can connect them. */
	list_for_each(&ld->peers, peer, list) {
		struct channel *channel;

		list_for_each(&peer->channels, channel, list) {
			if (!wallet_htlcs_load_out_for_channel(ld->wallet,
							       channel,
							       &ld->htlcs_out,
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

static struct command_result *json_disconnect(struct command *cmd,
					      const char *buffer,
					      const jsmntok_t *obj UNNEEDED,
					      const jsmntok_t *params)
{
	struct node_id *id;
	struct peer *peer;
	struct channel *channel;
	bool *force;

	if (!param(cmd, buffer, params,
		   p_req("id", param_node_id, &id),
		   p_opt_def("force", param_bool, &force, false),
		   NULL))
		return command_param_failed();

	peer = peer_by_id(cmd->ld, id);
	if (!peer) {
		return command_fail(cmd, LIGHTNINGD, "Peer not connected");
	}
	channel = peer_active_channel(peer);
	if (channel) {
		if (*force) {
			channel_fail_reconnect(channel,
					       "disconnect command force=true");
			return command_success(cmd, json_stream_success(cmd));
		}
		return command_fail(cmd, LIGHTNINGD, "Peer is in state %s",
				    channel_state_name(channel));
	}
	channel = peer_unsaved_channel(peer);
	if (channel) {
		channel_unsaved_close_conn(channel, "disconnect command");
		return command_success(cmd, json_stream_success(cmd));
	}
	if (!peer->uncommitted_channel) {
		return command_fail(cmd, LIGHTNINGD, "Peer not connected");
	}
	kill_uncommitted_channel(peer->uncommitted_channel,
				 "disconnect command");
	return command_success(cmd, json_stream_success(cmd));
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

    if (!param(cmd, buffer, params, NULL))
        return command_param_failed();

    response = json_stream_success(cmd);
    json_add_node_id(response, "id", &cmd->ld->id);
    json_add_string(response, "alias", (const char *)cmd->ld->alias);
    json_add_hex_talarr(response, "color", cmd->ld->rgb);

    /* Add some peer and channel stats */
    list_for_each(&cmd->ld->peers, peer, list) {
        num_peers++;

        list_for_each(&peer->channels, channel, list) {
            if (channel->state == CHANNELD_AWAITING_LOCKIN
		|| channel->state == DUALOPEND_AWAITING_LOCKIN
		|| channel->state == DUALOPEND_OPEN_INIT) {
                pending_channels++;
            } else if (channel_active(channel)) {
                active_channels++;
            } else {
                inactive_channels++;
            }
        }
    }
    json_add_num(response, "num_peers", num_peers);
    json_add_num(response, "num_pending_channels", pending_channels);
    json_add_num(response, "num_active_channels", active_channels);
    json_add_num(response, "num_inactive_channels", inactive_channels);

    /* Add network info */
    if (cmd->ld->listen) {
        /* These are the addresses we're announcing */
        json_array_start(response, "address");
        for (size_t i = 0; i < tal_count(cmd->ld->announcable); i++)
            json_add_address(response, NULL, cmd->ld->announcable+i);
        json_array_end(response);

        /* This is what we're actually bound to. */
        json_array_start(response, "binding");
        for (size_t i = 0; i < tal_count(cmd->ld->binding); i++)
            json_add_address_internal(response, NULL,
                          cmd->ld->binding+i);
        json_array_end(response);
    }
    json_add_string(response, "version", version());
    json_add_num(response, "blockheight", get_block_height(cmd->ld->topology));
    json_add_string(response, "network", chainparams->network_name);
    json_add_amount_msat_compat(response,
				wallet_total_forward_fees(cmd->ld->wallet),
				"msatoshi_fees_collected",
				"fees_collected_msat");
    json_add_string(response, "lightning-dir", cmd->ld->config_netdir);

    if (!cmd->ld->topology->bitcoind->synced)
	    json_add_string(response, "warning_bitcoind_sync",
			    "Bitcoind is not up-to-date with network.");
    else if (!topology_synced(cmd->ld->topology))
	    json_add_string(response, "warning_lightningd_sync",
			    "Still loading latest blocks from bitcoind.");

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

static struct command_result *param_channel_or_all(struct command *cmd,
					     const char *name,
					     const char *buffer,
					     const jsmntok_t *tok,
					     struct channel **channel)
{
	struct command_result *res;
	struct peer *peer;

	/* early return the easy case */
	if (json_tok_streq(buffer, tok, "all")) {
		*channel = NULL;
		return NULL;
	}

	/* Find channel by peer_id */
	peer = peer_from_json(cmd->ld, buffer, tok);
	if (peer) {
		*channel = peer_active_channel(peer);
		if (!*channel)
			return command_fail(cmd, LIGHTNINGD,
					"Could not find active channel of peer with that id");
		return NULL;

	/* Find channel by id or scid */
	} else {
		res = command_find_channel(cmd, buffer, tok, channel);
		if (res)
			return res;
		/* check channel is found and in valid state */
		if (!*channel)
			return command_fail(cmd, LIGHTNINGD,
					"Could not find channel with that id");
		return NULL;
	}
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

static void set_channel_fees(struct command *cmd, struct channel *channel,
			     u32 base, u32 ppm, u32 delaysecs,
			     struct json_stream *response)
{
	/* We only need to defer values if we *increase* them; we always
	 * allow users to overpay fees. */
	if (base > channel->feerate_base || ppm > channel->feerate_ppm) {
		channel->old_feerate_timeout
			= timeabs_add(time_now(), time_from_sec(delaysecs));
		channel->old_feerate_base = channel->feerate_base;
		channel->old_feerate_ppm = channel->feerate_ppm;
	}

	/* set new values */
	channel->feerate_base = base;
	channel->feerate_ppm = ppm;

	/* tell channeld to make a send_channel_update */
	if (channel->owner && streq(channel->owner->name, "channeld"))
		subd_send_msg(channel->owner,
				take(towire_channeld_specific_feerates(NULL, base, ppm)));

	/* save values to database */
	wallet_channel_save(cmd->ld->wallet, channel);

	/* write JSON response entry */
	json_object_start(response, NULL);
	json_add_node_id(response, "peer_id", &channel->peer->id);
	json_add_string(response, "channel_id",
			type_to_string(tmpctx, struct channel_id, &channel->cid));
	if (channel->scid)
		json_add_short_channel_id(response, "short_channel_id", channel->scid);
	json_object_end(response);
}

static struct command_result *json_setchannelfee(struct command *cmd,
					 const char *buffer,
					 const jsmntok_t *obj UNNEEDED,
					 const jsmntok_t *params)
{
	struct json_stream *response;
	struct peer *peer;
	struct channel *channel;
	u32 *base, *ppm, *delaysecs;

	/* Parse the JSON command */
	if (!param(cmd, buffer, params,
		   p_req("id", param_channel_or_all, &channel),
		   p_opt_def("base", param_msat_u32,
			     &base, cmd->ld->config.fee_base),
		   p_opt_def("ppm", param_number, &ppm,
			     cmd->ld->config.fee_per_satoshi),
		   p_opt_def("enforcedelay", param_number, &delaysecs, 600),
		   NULL))
		return command_param_failed();

	if (channel
	    && channel->state != CHANNELD_NORMAL
	    && channel->state != CHANNELD_AWAITING_LOCKIN
	    && channel->state != DUALOPEND_AWAITING_LOCKIN)
		return command_fail(cmd, LIGHTNINGD,
				    "Channel is in state %s", channel_state_name(channel));

	/* Open JSON response object for later iteration */
	response = json_stream_success(cmd);
	json_add_num(response, "base", *base);
	json_add_num(response, "ppm", *ppm);
	json_array_start(response, "channels");

	/* If the users requested 'all' channels we need to iterate */
	if (channel == NULL) {
		list_for_each(&cmd->ld->peers, peer, list) {
			channel = peer_active_channel(peer);
			if (!channel)
				continue;
			if (channel->state != CHANNELD_NORMAL &&
			    channel->state != CHANNELD_AWAITING_LOCKIN &&
			    channel->state != DUALOPEND_AWAITING_LOCKIN)
				continue;
			set_channel_fees(cmd, channel, *base, *ppm, *delaysecs,
					 response);
		}

	/* single channel should be updated */
	} else {
		set_channel_fees(cmd, channel, *base, *ppm, *delaysecs,
				 response);
	}

	/* Close and return response */
	json_array_end(response);
	return command_success(cmd, response);
}

static const struct json_command setchannelfee_command = {
	"setchannelfee",
	"channels",
	json_setchannelfee,
	"Sets specific routing fees for channel with {id} "
	"(either peer ID, channel ID, short channel ID or 'all'). "
	"Routing fees are defined by a fixed {base} (msat) "
	"and a {ppm} (proportional per millionth) value. "
	"If values for {base} or {ppm} are left out, defaults will be used. "
	"{base} can also be defined in other units, for example '1sat'. "
	"If {id} is 'all', the fees will be applied for all channels. "
};
AUTODATA(json_command, &setchannelfee_command);

#if DEVELOPER
static struct command_result *json_sign_last_tx(struct command *cmd,
						const char *buffer,
						const jsmntok_t *obj UNNEEDED,
						const jsmntok_t *params)
{
	struct node_id *peerid;
	struct peer *peer;
	struct json_stream *response;
	struct channel *channel;

	if (!param(cmd, buffer, params,
		   p_req("id", param_node_id, &peerid),
		   NULL))
		return command_param_failed();

	peer = peer_by_id(cmd->ld, peerid);
	if (!peer) {
		return command_fail(cmd, LIGHTNINGD,
				    "Could not find peer with that id");
	}
	channel = peer_active_channel(peer);
	if (!channel) {
		return command_fail(cmd, LIGHTNINGD,
				    "Could not find active channel");
	}

	response = json_stream_success(cmd);
	log_debug(channel->log, "dev-sign-last-tx: signing tx with %zu outputs",
		  channel->last_tx->wtx->num_outputs);

	sign_last_tx(channel, channel->last_tx, &channel->last_sig);
	json_add_tx(response, "tx", channel->last_tx);
	remove_sig(channel->last_tx);

	/* If we've got inflights, return them */
	if (!list_empty(&channel->inflights)) {
		struct channel_inflight *inflight;

		json_array_start(response, "inflights");
		list_for_each(&channel->inflights, inflight, list) {
			sign_last_tx(channel, inflight->last_tx,
				     &inflight->last_sig);
			json_object_start(response, NULL);
			json_add_txid(response, "funding_txid",
				      &inflight->funding->outpoint.txid);
			remove_sig(inflight->last_tx);
			json_add_tx(response, "tx", channel->last_tx);
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
	"Sign and show the last commitment transaction with peer {id}"
};
AUTODATA(json_command, &dev_sign_last_tx);

static struct command_result *json_dev_fail(struct command *cmd,
					    const char *buffer,
					    const jsmntok_t *obj UNNEEDED,
					    const jsmntok_t *params)
{
	struct node_id *peerid;
	struct peer *peer;
	struct channel *channel;

	if (!param(cmd, buffer, params,
		   p_req("id", param_node_id, &peerid),
		   NULL))
		return command_param_failed();

	peer = peer_by_id(cmd->ld, peerid);
	if (!peer) {
		return command_fail(cmd, LIGHTNINGD,
				    "Could not find peer with that id");
	}

	channel = peer_active_channel(peer);
	if (!channel) {
		return command_fail(cmd, LIGHTNINGD,
				    "Could not find active channel with peer");
	}

	channel_fail_permanent(channel,
			       REASON_USER,
			       "Failing due to dev-fail command");
	return command_success(cmd, json_stream_success(cmd));
}

static const struct json_command dev_fail_command = {
	"dev-fail",
	"developer",
	json_dev_fail,
	"Fail with peer {id}"
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
	struct node_id *peerid;
	struct peer *peer;
	u8 *msg;
	struct channel *channel;

	if (!param(cmd, buffer, params,
		   p_req("id", param_node_id, &peerid),
		   NULL))
		return command_param_failed();

	peer = peer_by_id(cmd->ld, peerid);
	if (!peer) {
		return command_fail(cmd, LIGHTNINGD,
				    "Could not find peer with that id");
	}

	channel = peer_active_channel(peer);
	if (!channel) {
		return command_fail(cmd, LIGHTNINGD,
				    "Peer has no active channel");
	}
	if (!channel->owner) {
		return command_fail(cmd, LIGHTNINGD,
				    "Peer has no owner");
	}

	if (!streq(channel->owner->name, "channeld")) {
		return command_fail(cmd, LIGHTNINGD,
				    "Peer owned by %s", channel->owner->name);
	}

	msg = towire_channeld_dev_reenable_commit(channel);
	subd_req(peer, channel->owner, take(msg), -1, 0,
		 dev_reenable_commit_finished, cmd);
	return command_still_pending(cmd);
}

static const struct json_command dev_reenable_commit = {
	"dev-reenable-commit",
	"developer",
	json_dev_reenable_commit,
	"Re-enable the commit timer on peer {id}"
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
	struct node_id *peerid;
	struct peer *peer;
	struct channel *channel;
	struct short_channel_id *scid;
	struct channel_id *find_cid;
	struct dev_forget_channel_cmd *forget = tal(cmd, struct dev_forget_channel_cmd);
	forget->cmd = cmd;

	bool *force;
	if (!param(cmd, buffer, params,
		   p_req("id", param_node_id, &peerid),
		   p_opt("short_channel_id", param_short_channel_id, &scid),
		   p_opt("channel_id", param_channel_id, &find_cid),
		   p_opt_def("force", param_bool, &force, false),
		   NULL))
		return command_param_failed();

	forget->force = *force;
	peer = peer_by_id(cmd->ld, peerid);
	if (!peer) {
		return command_fail(cmd, LIGHTNINGD,
				    "Could not find channel with that peer");
	}

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

	if (!channel_unsaved(forget->channel))
		bitcoind_getutxout(cmd->ld->topology->bitcoind,
				   &forget->channel->funding,
				   process_dev_forget_channel, forget);
	return command_still_pending(cmd);
}

static const struct json_command dev_forget_channel_command = {
	"dev-forget-channel",
	"developer",
	json_dev_forget_channel,
	"Forget the channel with peer {id}, ignore UTXO check with {force}='true'.", false,
	"Forget the channel with peer {id}. Checks if the channel is still active by checking its funding transaction. Check can be ignored by setting {force} to 'true'"
};
AUTODATA(json_command, &dev_forget_channel_command);

static void subd_died_forget_memleak(struct subd *openingd, struct command *cmd)
{
	/* FIXME: We ignore the remaining per-peer daemons in this case. */
	peer_memleak_done(cmd, NULL);
}

/* Mutual recursion */
static void peer_memleak_req_next(struct command *cmd, struct channel *prev);
static void peer_memleak_req_done(struct subd *subd, bool found_leak,
				  struct command *cmd)
{
	struct channel *c = subd->channel;

	if (found_leak)
		peer_memleak_done(cmd, subd);
	else
		peer_memleak_req_next(cmd, c);
}

static void channeld_memleak_req_done(struct subd *channeld,
				      const u8 *msg, const int *fds UNUSED,
				      struct command *cmd)
{
	bool found_leak;

	tal_del_destructor2(channeld, subd_died_forget_memleak, cmd);
	if (!fromwire_channeld_dev_memleak_reply(msg, &found_leak)) {
		was_pending(command_fail(cmd, LIGHTNINGD,
					 "Bad channel_dev_memleak"));
		return;
	}
	peer_memleak_req_done(channeld, found_leak, cmd);
}

static void onchaind_memleak_req_done(struct subd *onchaind,
				      const u8 *msg, const int *fds UNUSED,
				      struct command *cmd)
{
	bool found_leak;

	tal_del_destructor2(onchaind, subd_died_forget_memleak, cmd);
	if (!fromwire_onchaind_dev_memleak_reply(msg, &found_leak)) {
		was_pending(command_fail(cmd, LIGHTNINGD,
					 "Bad onchain_dev_memleak"));
		return;
	}
	peer_memleak_req_done(onchaind, found_leak, cmd);
}

static void peer_memleak_req_next(struct command *cmd, struct channel *prev)
{
	struct peer *p;

	list_for_each(&cmd->ld->peers, p, list) {
		struct channel *c;

		list_for_each(&p->channels, c, list) {
			if (c == prev) {
				prev = NULL;
				continue;
			}

			if (!c->owner)
				continue;

			if (prev != NULL)
				continue;

			/* Note: closingd and dualopend do their own
			 * checking automatically */
			if (channel_unsaved(c))
				continue;

			if (streq(c->owner->name, "channeld")) {
				subd_req(c, c->owner,
					 take(towire_channeld_dev_memleak(NULL)),
					 -1, 0, channeld_memleak_req_done, cmd);
				tal_add_destructor2(c->owner,
						    subd_died_forget_memleak,
						    cmd);
				return;
			}
			if (streq(c->owner->name, "onchaind")) {
				subd_req(c, c->owner,
					 take(towire_onchaind_dev_memleak(NULL)),
					 -1, 0, onchaind_memleak_req_done, cmd);
				tal_add_destructor2(c->owner,
						    subd_died_forget_memleak,
						    cmd);
				return;
			}
		}
	}
	peer_memleak_done(cmd, NULL);
}

void peer_dev_memleak(struct command *cmd)
{
	peer_memleak_req_next(cmd, NULL);
}

#endif /* DEVELOPER */

struct custommsg_payload {
	struct node_id peer_id;
	const u8 *msg;
};

static bool custommsg_cb(struct custommsg_payload *payload,
			 const char *buffer, const jsmntok_t *toks)
{
	const jsmntok_t *t_res;

	if (!toks || !buffer)
		return true;

	t_res = json_get_member(buffer, toks, "result");

	/* fail */
	if (!t_res || !json_tok_streq(buffer, t_res, "continue"))
		fatal("Plugin returned an invalid response to the "
		      "custommsg hook: %s", buffer);

	/* call next hook */
	return true;
}

static void custommsg_final(struct custommsg_payload *payload STEALS)
{
	tal_steal(tmpctx, payload);
}

static void custommsg_payload_serialize(struct custommsg_payload *payload,
					struct json_stream *stream,
					struct plugin *plugin)
{
	json_add_hex_talarr(stream, "payload", payload->msg);
	json_add_node_id(stream, "peer_id", &payload->peer_id);
}

REGISTER_PLUGIN_HOOK(custommsg,
		     custommsg_cb,
		     custommsg_final,
		     custommsg_payload_serialize,
		     struct custommsg_payload *);

void handle_custommsg_in(struct lightningd *ld, const struct node_id *peer_id,
			 const u8 *msg)
{
	struct custommsg_payload *p = tal(NULL, struct custommsg_payload);
	u8 *custommsg;

	if (!fromwire_custommsg_in(NULL, msg, &custommsg)) {
		log_broken(ld->log, "Malformed custommsg from peer %s: %s",
			   type_to_string(tmpctx, struct node_id, peer_id),
			   tal_hex(tmpctx, msg));
		return;
	}

	p->peer_id = *peer_id;
	p->msg = tal_steal(p, custommsg);
	plugin_hook_call_custommsg(ld, p);
}

static struct command_result *json_sendcustommsg(struct command *cmd,
						 const char *buffer,
						 const jsmntok_t *obj UNNEEDED,
						 const jsmntok_t *params)
{
	struct json_stream *response;
	struct node_id *dest;
	struct peer *peer;
	struct subd *owner;
	u8 *msg;
	int type;

	if (!param(cmd, buffer, params,
		   p_req("node_id", param_node_id, &dest),
		   p_req("msg", param_bin_from_hex, &msg),
		   NULL))
		return command_param_failed();

	type = fromwire_peektype(msg);
	if (peer_wire_is_defined(type)) {
		return command_fail(
		    cmd, JSONRPC2_INVALID_REQUEST,
		    "Cannot send messages of type %d (%s). It is not possible "
		    "to send messages that have a type managed internally "
		    "since that might cause issues with the internal state "
		    "tracking.",
		    type, peer_wire_name(type));
	}

	if (type % 2 == 0) {
		return command_fail(
		    cmd, JSONRPC2_INVALID_REQUEST,
		    "Cannot send even-typed %d custom message. Currently "
		    "custom messages are limited to odd-numbered message "
		    "types, as even-numbered types might result in "
		    "disconnections.",
		    type);
	}

	peer = peer_by_id(cmd->ld, dest);
	if (!peer) {
		return command_fail(cmd, JSONRPC2_INVALID_REQUEST,
				    "No such peer: %s",
				    type_to_string(cmd, struct node_id, dest));
	}

	owner = peer_get_owning_subd(peer);
	if (owner == NULL) {
		return command_fail(cmd, JSONRPC2_INVALID_REQUEST,
				    "Peer is not connected: %s",
				    type_to_string(cmd, struct node_id, dest));
	}

	/* Only a couple of subdaemons have the ability to send custom
	 * messages. We whitelist those, and error if the current owner is not
	 * in the whitelist. The reason is that some subdaemons do not handle
	 * spontaneous messages from the master well (I'm looking at you
	 * `closingd`...). */
	if (!streq(owner->name, "channeld") &&
	    !streq(owner->name, "openingd")) {
		return command_fail(cmd, JSONRPC2_INVALID_REQUEST,
				    "Peer is currently owned by %s which does "
				    "not support injecting custom messages.",
				    owner->name);
	}

	subd_send_msg(owner, take(towire_custommsg_out(cmd, msg)));

	response = json_stream_success(cmd);
	json_add_string(response, "status",
			tal_fmt(cmd,
				"Message sent to subdaemon %s for delivery",
				owner->name));

	return command_success(cmd, response);
}

static const struct json_command sendcustommsg_command = {
    "sendcustommsg",
    "utility",
    json_sendcustommsg,
    "Send a custom message to the peer with the given {node_id}",
    .verbose = "sendcustommsg node_id hexcustommsg",
};

AUTODATA(json_command, &sendcustommsg_command);

#ifdef COMPAT_V0100
#ifdef DEVELOPER
static const struct json_command dev_sendcustommsg_command = {
    "dev-sendcustommsg",
    "utility",
    json_sendcustommsg,
    "Send a custom message to the peer with the given {node_id}",
    .verbose = "dev-sendcustommsg node_id hexcustommsg",
};

AUTODATA(json_command, &dev_sendcustommsg_command);
#endif  /* DEVELOPER */
#endif /* COMPAT_V0100 */
