#include "lightningd.h"
#include "peer_control.h"
#include "subd.h"
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
#include <common/status.h>
#include <common/timeout.h>
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
#include <lightningd/channel_control.h>
#include <lightningd/closing_control.h>
#include <lightningd/connect_control.h>
#include <lightningd/hsm_control.h>
#include <lightningd/json.h>
#include <lightningd/jsonrpc.h>
#include <lightningd/log.h>
#include <lightningd/memdump.h>
#include <lightningd/notification.h>
#include <lightningd/onchain_control.h>
#include <lightningd/opening_control.h>
#include <lightningd/options.h>
#include <lightningd/peer_htlcs.h>
#include <lightningd/plugin_hook.h>
#include <limits.h>
#include <stdlib.h>
#include <unistd.h>
#include <wally_bip32.h>
#include <wire/common_wiregen.h>
#include <wire/onion_wire.h>
#include <wire/wire_sync.h>

struct close_command {
	/* Inside struct lightningd close_commands. */
	struct list_node list;
	/* Command structure. This is the parent of the close command. */
	struct command *cmd;
	/* Channel being closed. */
	struct channel *channel;
	/* Should we force the close on timeout? */
	bool force;
};

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
		      const struct wireaddr_internal *addr)
{
	/* We are owned by our channels, and freed manually by destroy_channel */
	struct peer *peer = tal(NULL, struct peer);

	peer->ld = ld;
	peer->dbid = dbid;
	peer->id = *id;
	peer->uncommitted_channel = NULL;
	peer->addr = *addr;
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

static void sign_last_tx(struct channel *channel)
{
	struct lightningd *ld = channel->peer->ld;
	struct bitcoin_signature sig;
	u8 *msg, **witness;

	assert(!channel->last_tx->wtx->inputs[0].witness);
	msg = towire_hsmd_sign_commitment_tx(tmpctx,
					    &channel->peer->id,
					    channel->dbid,
					    channel->last_tx,
					    &channel->channel_info
					    .remote_fundingkey);

	if (!wire_sync_write(ld->hsm_fd, take(msg)))
		fatal("Could not write to HSM: %s", strerror(errno));

	msg = wire_sync_read(tmpctx, ld->hsm_fd);
	if (!fromwire_hsmd_sign_commitment_tx_reply(msg, &sig))
		fatal("HSM gave bad sign_commitment_tx_reply %s",
		      tal_hex(tmpctx, msg));

	witness =
	    bitcoin_witness_2of2(channel->last_tx, &channel->last_sig,
				 &sig, &channel->channel_info.remote_fundingkey,
				 &channel->local_funding_pubkey);

	bitcoin_tx_input_set_witness(channel->last_tx, 0, take(witness));
}

static void remove_sig(struct bitcoin_tx *signed_tx)
{
	bitcoin_tx_input_set_witness(signed_tx, 0, NULL);
}

/* Resolve a single close command. */
static void
resolve_one_close_command(struct close_command *cc, bool cooperative)
{
	struct json_stream *result = json_stream_success(cc->cmd);
	struct bitcoin_txid txid;

	bitcoin_txid(cc->channel->last_tx, &txid);

	json_add_tx(result, "tx", cc->channel->last_tx);
	json_add_txid(result, "txid", &txid);
	if (cooperative)
		json_add_string(result, "type", "mutual");
	else
		json_add_string(result, "type", "unilateral");

	was_pending(command_success(cc->cmd, result));
}

/* Resolve a close command for a channel that will be closed soon. */
static void
resolve_close_command(struct lightningd *ld, struct channel *channel,
		      bool cooperative)
{
	struct close_command *cc;
	struct close_command *n;

	list_for_each_safe (&ld->close_commands, cc, n, list) {
		if (cc->channel != channel)
			continue;
		resolve_one_close_command(cc, cooperative);
	}
}

/* Destroy the close command structure in reaction to the
 * channel being destroyed. */
static void
destroy_close_command_on_channel_destroy(struct channel *_ UNUSED,
					 struct close_command *cc)
{
	/* The cc has the command as parent, so resolving the
	 * command destroys the cc and triggers destroy_close_command.
	 * Clear the cc->channel first so that we will not try to
	 * remove a destructor. */
	cc->channel = NULL;
	was_pending(command_fail(cc->cmd, LIGHTNINGD,
				 "Channel forgotten before proper close."));
}

/* Destroy the close command structure. */
static void
destroy_close_command(struct close_command *cc)
{
	list_del(&cc->list);
	/* If destroy_close_command_on_channel_destroy was
	 * triggered beforehand, it will have cleared
	 * the channel field, preventing us from removing it
	 * from an already-destroyed channel. */
	if (!cc->channel)
		return;
	tal_del_destructor2(cc->channel,
			    &destroy_close_command_on_channel_destroy,
			    cc);
}

/* Handle timeout. */
static void
close_command_timeout(struct close_command *cc)
{
	if (cc->force)
		/* This will trigger drop_to_chain, which will trigger
		 * resolution of the command and destruction of the
		 * close_command. */
		channel_fail_permanent(cc->channel,
				       "Forcibly closed by 'close' command timeout");
	else
		/* Fail the command directly, which will resolve the
		 * command and destroy the close_command. */
		was_pending(command_fail(cc->cmd, LIGHTNINGD,
					 "Channel close negotiation not finished "
					 "before timeout"));
}

/* Construct a close command structure and add to ld. */
static void
register_close_command(struct lightningd *ld,
		       struct command *cmd,
		       struct channel *channel,
		       unsigned int *timeout,
		       bool force)
{
	struct close_command *cc;
	assert(channel);

	cc = tal(cmd, struct close_command);
	list_add_tail(&ld->close_commands, &cc->list);
	cc->cmd = cmd;
	cc->channel = channel;
	cc->force = force;
	tal_add_destructor(cc, &destroy_close_command);
	tal_add_destructor2(channel,
			    &destroy_close_command_on_channel_destroy,
			    cc);
	log_debug(ld->log, "close_command: force = %u, timeout = %i",
		  force, timeout ? *timeout : -1);
	if (timeout)
		new_reltimer(ld->timers, cc, time_from_sec(*timeout),
			     &close_command_timeout, cc);
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

void drop_to_chain(struct lightningd *ld, struct channel *channel,
		   bool cooperative)
{
	struct bitcoin_txid txid;
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
		sign_last_tx(channel);
		bitcoin_txid(channel->last_tx, &txid);
		wallet_transaction_add(ld->wallet, channel->last_tx->wtx, 0, 0);
		wallet_transaction_annotate(ld->wallet, &txid, channel->last_tx_type, channel->dbid);

		/* Keep broadcasting until we say stop (can fail due to dup,
		 * if they beat us to the broadcast). */
		broadcast_tx(ld->topology, channel, channel->last_tx, NULL);

		remove_sig(channel->last_tx);
	}

	resolve_close_command(ld, channel, cooperative);
}

void channel_errmsg(struct channel *channel,
		    struct per_peer_state *pps,
		    const struct channel_id *channel_id UNUSED,
		    const char *desc,
		    bool soft_error,
		    const u8 *err_for_them)
{
	notify_disconnect(channel->peer->ld, &channel->peer->id);

	/* No per_peer_state means a subd crash or disconnection. */
	if (!pps) {
		channel_fail_reconnect(channel, "%s: %s",
				       channel->owner->name, desc);
		return;
	}

	/* Do we have an error to send? */
	if (err_for_them && !channel->error)
		channel->error = tal_dup_talarr(channel, u8, err_for_them);

	/* Other implementations chose to ignore errors early on.  Not
	 * surprisingly, they now spew out spurious errors frequently,
	 * and we would close the channel on them. */
	if (soft_error) {
		channel_fail_reconnect_later(channel, "%s: (ignoring) %s",
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
		channel_fail_permanent(channel, "%s: %s ERROR %s",
				       channel->owner->name,
				       err_for_them ? "sent" : "received", desc);
}

struct peer_connected_hook_payload {
	struct lightningd *ld;
	struct channel *channel;
	struct wireaddr_internal addr;
	struct peer *peer;
	struct per_peer_state *pps;
};

static void json_add_htlcs(struct lightningd *ld,
			   struct json_stream *response,
			   const struct channel *channel)
{
	/* FIXME: make per-channel htlc maps! */
	const struct htlc_in *hin;
	struct htlc_in_map_iter ini;
	const struct htlc_out *hout;
	struct htlc_out_map_iter outi;
	u32 local_feerate = get_feerate(channel->channel_info.fee_states,
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
		json_add_u64(response, "expiry", hin->cltv_expiry);
		json_add_sha256(response, "payment_hash", &hin->payment_hash);
		json_add_string(response, "state",
				htlc_state_name(hin->hstate));
		if (htlc_is_trimmed(REMOTE, hin->msat, local_feerate,
				    channel->our_config.dust_limit, LOCAL,
				    channel->option_anchor_outputs))
			json_add_bool(response, "local_trimmed", true);
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
				    channel->option_anchor_outputs))
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
	u32 feerate = get_feerate(channel->channel_info.fee_states,
				  channel->opener, side);
	struct amount_sat dust_limit;
	struct amount_sat fee;

	if (side == LOCAL)
		dust_limit = channel->our_config.dust_limit;
	if (side == REMOTE)
		dust_limit = channel->channel_info.their_config.dust_limit;

	/* Assume we tried to add "amount" */
	if (!htlc_is_trimmed(side, amount, feerate, dust_limit, side,
			     channel->option_anchor_outputs))
		num_untrimmed_htlcs++;

	for (hin = htlc_in_map_first(&ld->htlcs_in, &ini);
	     hin;
	     hin = htlc_in_map_next(&ld->htlcs_in, &ini)) {
		if (hin->key.channel != channel)
			continue;
		if (!htlc_is_trimmed(!side, hin->msat, feerate, dust_limit,
				     side,
				     channel->option_anchor_outputs))
			num_untrimmed_htlcs++;
	}
	for (hout = htlc_out_map_first(&ld->htlcs_out, &outi);
	     hout;
	     hout = htlc_out_map_next(&ld->htlcs_out, &outi)) {
		if (hout->key.channel != channel)
			continue;
		if (!htlc_is_trimmed(side, hout->msat, feerate, dust_limit,
				     side,
				     channel->option_anchor_outputs))
			num_untrimmed_htlcs++;
	}

	/*
	 * BOLT-f5490f17d17ff49dc26ee459432b3c9db4fda8a9 #2:
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
				 channel->option_anchor_outputs);

	if (channel->option_anchor_outputs) {
		/* BOLT-a12da24dd0102c170365124782b46d9710950ac1:
		 * If `option_anchor_outputs` applies to the commitment
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
	if (!amount_sat_sub_msat(&their_msat, channel->funding, channel->our_msat))
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
	struct channel_id cid;
	struct channel_stats channel_stats;
	struct amount_msat funding_msat;
	struct peer *p = channel->peer;

	json_object_start(response, key);
	json_add_string(response, "state", channel_state_name(channel));
	if (channel->last_tx && !invalid_last_tx(channel->last_tx)) {
		struct bitcoin_txid txid;
		bitcoin_txid(channel->last_tx, &txid);

		json_add_txid(response, "scratch_txid", &txid);
	}
	if (channel->owner)
		json_add_string(response, "owner", channel->owner->name);

	if (channel->scid) {
		json_add_short_channel_id(response, "short_channel_id",
					  channel->scid);
		json_add_num(response, "direction",
			     node_id_idx(&ld->id, &channel->peer->id));
	}

	derive_channel_id(&cid, &channel->funding_txid,
			  channel->funding_outnum);
	json_add_string(response, "channel_id",
			type_to_string(tmpctx, struct channel_id, &cid));
	json_add_txid(response, "funding_txid", &channel->funding_txid);

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

	json_array_start(response, "features");
	if (channel->option_static_remotekey)
		json_add_string(response, NULL, "option_static_remotekey");
	if (channel->option_anchor_outputs)
		json_add_string(response, NULL, "option_anchor_outputs");
	json_array_end(response);

	// FIXME @conscott : Modify this when dual-funded channels
	// are implemented
	json_object_start(response, "funding_allocation_msat");
	if (channel->opener == LOCAL) {
		json_add_u64(response, node_id_to_hexstr(tmpctx, &p->id), 0);
		json_add_u64(response, node_id_to_hexstr(tmpctx, &ld->id),
			     channel->funding.satoshis * 1000); /* Raw: raw JSON field */
	} else {
		json_add_u64(response, node_id_to_hexstr(tmpctx, &ld->id), 0);
		json_add_u64(response, node_id_to_hexstr(tmpctx, &p->id),
			     channel->funding.satoshis * 1000); /* Raw: raw JSON field */
	}
	json_object_end(response);

	json_object_start(response, "funding_msat");
	if (channel->opener == LOCAL) {
		json_add_sat_only(response,
				  node_id_to_hexstr(tmpctx, &p->id),
				  AMOUNT_SAT(0));
		json_add_sat_only(response,
				  node_id_to_hexstr(tmpctx, &ld->id),
				  channel->funding);
	} else {
		json_add_sat_only(response,
				  node_id_to_hexstr(tmpctx, &ld->id),
				  AMOUNT_SAT(0));
		json_add_sat_only(response,
				  node_id_to_hexstr(tmpctx, &p->id),
				  channel->funding);
	}
	json_object_end(response);

	if (!amount_sat_to_msat(&funding_msat, channel->funding)) {
		log_broken(channel->log,
			   "Overflow converting funding %s",
			   type_to_string(tmpctx, struct amount_sat,
					  &channel->funding));
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

static void
peer_connected_serialize(struct peer_connected_hook_payload *payload,
			 struct json_stream *stream)
{
	const struct peer *p = payload->peer;
	json_object_start(stream, "peer");
	json_add_node_id(stream, "id", &p->id);
	json_add_string(
	    stream, "addr",
	    type_to_string(stream, struct wireaddr_internal, &payload->addr));
	json_add_hex_talarr(stream, "features", p->their_features);
	json_object_end(stream); /* .peer */
}

static void
peer_connected_hook_cb(struct peer_connected_hook_payload *payload STEALS,
		       const char *buffer,
		       const jsmntok_t *toks)
{
	struct lightningd *ld = payload->ld;
	struct channel *channel = payload->channel;
	struct wireaddr_internal addr = payload->addr;
	struct peer *peer = payload->peer;
	u8 *error;

	/* If we had a hook, interpret result. */
	if (buffer) {
		const jsmntok_t *resulttok;

		resulttok = json_get_member(buffer, toks, "result");
		if (!resulttok) {
			fatal("Plugin returned an invalid response to the connected "
			      "hook: %s", buffer);
		}

		if (json_tok_streq(buffer, resulttok, "disconnect")) {
			const jsmntok_t *m = json_get_member(buffer, toks,
							     "error_message");
			if (m) {
				error = towire_errorfmt(tmpctx, NULL,
							"%.*s",
							m->end - m->start,
							buffer + m->start);
				goto send_error;
			}
			tal_free(payload);
			return;
		} else if (!json_tok_streq(buffer, resulttok, "continue"))
			fatal("Plugin returned an invalid response to the connected "
			      "hook: %s", buffer);
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
			channel_fail_permanent(channel,
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
			struct channel_id cid;
			derive_channel_id(&cid,
					  &channel->funding_txid,
					  channel->funding_outnum);
			/* channel->error is not saved in db, so this can
			 * happen if we restart. */
			error = towire_errorfmt(tmpctx, &cid,
						"Awaiting unilateral close");
			goto send_error;
		}

		case CHANNELD_AWAITING_LOCKIN:
		case CHANNELD_NORMAL:
		case CHANNELD_SHUTTING_DOWN:
			assert(!channel->owner);

			channel->peer->addr = addr;
			peer_start_channeld(channel, payload->pps, NULL,
					    true);
			tal_free(payload);
			return;

		case CLOSINGD_SIGEXCHANGE:
			assert(!channel->owner);

			channel->peer->addr = addr;
			peer_start_closingd(channel, payload->pps,
					    true, NULL);
			tal_free(payload);
			return;
		}
		abort();
	}

	notify_connect(ld, &peer->id, &addr);

	/* No err, all good. */
	error = NULL;

send_error:
	peer_start_openingd(peer, payload->pps, error);
	tal_free(payload);
}

REGISTER_SINGLE_PLUGIN_HOOK(peer_connected,
			    peer_connected_hook_cb,
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
	if (!fromwire_connectd_peer_connected(hook_payload, msg,
					     &id, &hook_payload->addr,
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
		peer = new_peer(ld, 0, &id, &hook_payload->addr);

	tal_steal(peer, hook_payload);
	hook_payload->peer = peer;

	peer_update_features(peer, their_features);

	/* Complete any outstanding connect commands. */
	connect_succeeded(ld, peer);

	/* Can't be opening, since we wouldn't have sent peer_disconnected. */
	assert(!peer->uncommitted_channel);
	hook_payload->channel = peer_active_channel(peer);

	plugin_hook_call_peer_connected(ld, hook_payload);
}

/* FIXME: Unify our watch code so we get notified by txout, instead, like
 * the wallet code does. */
static bool check_funding_tx(const struct bitcoin_tx *tx,
			     const struct channel *channel)
{
	u8 *wscript;
	struct amount_asset asset =
	    bitcoin_tx_output_get_amount(tx, channel->funding_outnum);

	if (!amount_asset_is_main(&asset))
		return false;

	if (channel->funding_outnum >= tx->wtx->num_outputs)
		return false;

	if (!amount_sat_eq(amount_asset_to_sat(&asset), channel->funding))
		return false;

	wscript = bitcoin_redeem_2of2(tmpctx,
				      &channel->local_funding_pubkey,
				      &channel->channel_info.remote_fundingkey);
	return scripteq(scriptpubkey_p2wsh(tmpctx, wscript),
			bitcoin_tx_output_get_script(tmpctx, tx,
						     channel->funding_outnum));
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

		wallet_annotate_txout(ld->wallet, txid, channel->funding_outnum,
				      TX_CHANNEL_FUNDING, channel->dbid);
		loc = wallet_transaction_locate(tmpctx, ld->wallet, txid);
		if (!mk_short_channel_id(&scid,
					 loc->blkheight, loc->index,
					 channel->funding_outnum)) {
			channel_fail_permanent(channel, "Invalid funding scid %u:%u:%u",
					       loc->blkheight, loc->index,
					       channel->funding_outnum);
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

void channel_watch_funding(struct lightningd *ld, struct channel *channel)
{
	/* FIXME: Remove arg from cb? */
	watch_txid(channel, ld->topology, channel,
		   &channel->funding_txid, funding_depth_cb);
	watch_txo(channel, ld->topology, channel,
		  &channel->funding_txid, channel->funding_outnum,
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
		connected = channel && channel->connected;
	}
	json_add_bool(response, "connected", connected);

	/* If it's not connected, features are unreliable: we don't
	 * store them in the database, and they would only reflect
	 * their features *last* time they connected. */
	if (connected) {
		json_array_start(response, "netaddr");
		json_add_string(response, NULL,
				type_to_string(response,
					       struct wireaddr_internal,
					       &p->addr));
		json_array_end(response);
		json_add_hex_talarr(response, "features", p->their_features);
	}

	json_array_start(response, "channels");
	json_add_uncommitted_channel(response, p->uncommitted_channel);

	list_for_each(&p->channels, channel, list)
		json_add_channel(ld, response, NULL, channel);
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
AUTODATA(json_command, &listpeers_command);

static struct command_result *
command_find_channel(struct command *cmd,
		     const char *buffer, const jsmntok_t *tok,
		     struct channel **channel)
{
	struct lightningd *ld = cmd->ld;
	struct channel_id cid;
	struct channel_id channel_cid;
	struct short_channel_id scid;
	struct peer *peer;

	if (json_tok_channel_id(buffer, tok, &cid)) {
		list_for_each(&ld->peers, peer, list) {
			*channel = peer_active_channel(peer);
			if (!*channel)
				continue;
			derive_channel_id(&channel_cid,
					  &(*channel)->funding_txid,
					  (*channel)->funding_outnum);
			if (channel_id_eq(&channel_cid, &cid))
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

static struct command_result *json_close(struct command *cmd,
					 const char *buffer,
					 const jsmntok_t *obj UNNEEDED,
					 const jsmntok_t *params)
{
	const jsmntok_t *idtok;
	struct peer *peer;
	struct channel *channel COMPILER_WANTS_INIT("gcc 7.3.0 fails, 8.3 OK");
	unsigned int *timeout = NULL;
	bool force = true;
	bool do_timeout;
	const u8 *close_to_script = NULL;
	bool close_script_set;
	const char *fee_negotiation_step_str;
	char* end;

	if (!param(cmd, buffer, params,
		   p_req("id", param_tok, &idtok),
		   p_opt_def("unilateraltimeout", param_number, &timeout,
			     48 * 3600),
		   p_opt("destination", param_bitcoin_address, &close_to_script),
		   p_opt("fee_negotiation_step", param_string,
			 &fee_negotiation_step_str),
		   NULL))
		return command_param_failed();

	do_timeout = (*timeout != 0);

	peer = peer_from_json(cmd->ld, buffer, idtok);
	if (peer)
		channel = peer_active_channel(peer);
	else {
		struct command_result *res;
		res = command_find_channel(cmd, buffer, idtok, &channel);
		if (res)
			return res;
	}

	if (!channel && peer) {
		struct uncommitted_channel *uc = peer->uncommitted_channel;
		if (uc) {
			/* Easy case: peer can simply be forgotten. */
			kill_uncommitted_channel(uc, "close command called");

			return command_success(cmd, json_stream_success(cmd));
		}
		return command_fail(cmd, LIGHTNINGD,
				    "Peer has no active channel");
	}


	/* If we've set a local shutdown script for this peer, and it's not the
	 * default upfront script, try to close to a different channel.
	 * Error is an operator error */
	if (close_to_script && channel->shutdown_scriptpubkey[LOCAL]
			&& !memeq(close_to_script,
				  tal_count(close_to_script),
				  channel->shutdown_scriptpubkey[LOCAL],
				  tal_count(channel->shutdown_scriptpubkey[LOCAL]))) {
		u8 *default_close_to = p2wpkh_for_keyidx(tmpctx, cmd->ld,
							 channel->final_key_idx);
		if (!memeq(default_close_to, tal_count(default_close_to),
			   channel->shutdown_scriptpubkey[LOCAL],
			   tal_count(channel->shutdown_scriptpubkey[LOCAL]))) {
			return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
					    "Destination address %s does not match "
					    "previous shutdown script %s",
					    tal_hex(tmpctx, channel->shutdown_scriptpubkey[LOCAL]),
					    tal_hex(tmpctx, close_to_script));
		} else {
			channel->shutdown_scriptpubkey[LOCAL] =
				tal_free(channel->shutdown_scriptpubkey[LOCAL]);
			channel->shutdown_scriptpubkey[LOCAL] =
				tal_steal(channel, close_to_script);
			close_script_set = true;
		}
	} else if (close_to_script && !channel->shutdown_scriptpubkey[LOCAL]) {
		channel->shutdown_scriptpubkey[LOCAL]
			= tal_steal(channel, cast_const(u8 *, close_to_script));
		close_script_set = true;
	} else if (!channel->shutdown_scriptpubkey[LOCAL]) {
		channel->shutdown_scriptpubkey[LOCAL]
			= p2wpkh_for_keyidx(channel, cmd->ld, channel->final_key_idx);
		/* We don't save the default to disk */
		close_script_set = false;
	} else
		close_script_set = false;

	if (fee_negotiation_step_str == NULL) {
		channel->closing_fee_negotiation_step = 50;
		channel->closing_fee_negotiation_step_unit =
		    CLOSING_FEE_NEGOTIATION_STEP_UNIT_PERCENTAGE;
	} else {
		channel->closing_fee_negotiation_step =
		    strtoull(fee_negotiation_step_str, &end, 10);

		if (channel->closing_fee_negotiation_step == 0)
			return command_fail(
			    cmd, JSONRPC2_INVALID_PARAMS,
			    "Wrong value given for fee_negotiation_step: "
			    "\"%s\", must be positive",
			    fee_negotiation_step_str);
		else if (*end == '%') {
			if (channel->closing_fee_negotiation_step > 100)
				return command_fail(
				    cmd, JSONRPC2_INVALID_PARAMS,
				    "Wrong value given for "
				    "fee_negotiation_step: \"%s\", the "
				    "percentage should be between 1 and 100",
				    fee_negotiation_step_str);
			channel->closing_fee_negotiation_step_unit =
			    CLOSING_FEE_NEGOTIATION_STEP_UNIT_PERCENTAGE;
		} else if (*end == '\0')
			channel->closing_fee_negotiation_step_unit =
			    CLOSING_FEE_NEGOTIATION_STEP_UNIT_SATOSHI;
		else
			return command_fail(
			    cmd, JSONRPC2_INVALID_PARAMS,
			    "Wrong value given for fee_negotiation_step: "
			    "\"%s\", should be an integer or an integer "
			    "followed by %%",
			    fee_negotiation_step_str);
	}

	/* Normal case.
	 * We allow states shutting down and sigexchange; a previous
	 * close command may have timed out, and this current command
	 * will continue waiting for the effects of the previous
	 * close command. */

	/* If normal or locking in, transition to shutting down
	 * state.
	 * (if already shutting down or sigexchange, just keep
	 * waiting) */
	switch (channel->state) {
		case CHANNELD_NORMAL:
		case CHANNELD_AWAITING_LOCKIN:
			channel_set_state(channel,
					  channel->state, CHANNELD_SHUTTING_DOWN);
			/* fallthrough */
		case CHANNELD_SHUTTING_DOWN:
			if (channel->owner)
				subd_send_msg(channel->owner,
					      take(towire_channeld_send_shutdown(NULL,
						   channel->shutdown_scriptpubkey[LOCAL])));
			break;
		case CLOSINGD_SIGEXCHANGE:
			break;
		default:
			return command_fail(cmd, LIGHTNINGD, "Channel is in state %s",
					    channel_state_name(channel));
	}

	/* Register this command for later handling. */
	register_close_command(cmd->ld, cmd, channel,
			       do_timeout ? timeout : NULL, force);

	/* If we set `channel->shutdown_scriptpubkey[LOCAL]`, save it. */
	if (close_script_set)
		wallet_channel_save(cmd->ld->wallet, channel);

	/* Wait until close drops down to chain. */
	return command_still_pending(cmd);
}

/* Magic marker: remove at your own peril! */
static const struct json_command close_command = {
	"close",
	"channels",
	json_close,
	"Close the channel with {id} "
	"(either peer ID, channel ID, or short channel ID). "
	"Force a unilateral close after {unilateraltimeout} seconds (default 48h). "
	"If {destination} address is provided, will be used as output address."
};
AUTODATA(json_command, &close_command);

static void activate_peer(struct peer *peer, u32 delay)
{
	u8 *msg;
	struct channel *channel;
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
			delay_then_reconnect(channel, delay, &peer->addr);
		} else {
			msg = towire_connectd_connect_to_peer(NULL,
								&peer->id, 0,
								&peer->addr);
			subd_send_msg(ld->connectd, take(msg));
			channel_set_billboard(channel, false,
					      "Attempting to reconnect");
		}
	}

	list_for_each(&peer->channels, channel, list) {
		/* Watching lockin may be unnecessary, but it's harmless. */
		channel_watch_funding(ld, channel);
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
            if (channel->state == CHANNELD_AWAITING_LOCKIN) {
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
	was_pending(command_fail(w->cmd, LIGHTNINGD,
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
		u32 base, u32 ppm, struct json_stream *response)
{
	struct channel_id cid;

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
	derive_channel_id(&cid, &channel->funding_txid, channel->funding_outnum);
	json_object_start(response, NULL);
	json_add_node_id(response, "peer_id", &channel->peer->id);
	json_add_string(response, "channel_id",
			type_to_string(tmpctx, struct channel_id, &cid));
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
	u32 *base, *ppm;

	/* Parse the JSON command */
	if (!param(cmd, buffer, params,
		   p_req("id", param_channel_or_all, &channel),
		   p_opt_def("base", param_msat_u32,
			     &base, cmd->ld->config.fee_base),
		   p_opt_def("ppm", param_number, &ppm,
			     cmd->ld->config.fee_per_satoshi),
		   NULL))
		return command_param_failed();

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
			    channel->state != CHANNELD_AWAITING_LOCKIN)
				continue;
			set_channel_fees(cmd, channel, *base, *ppm, response);
		}

	/* single channel should be updated */
	} else {
		if (channel->state != CHANNELD_NORMAL &&
			channel->state != CHANNELD_AWAITING_LOCKIN)
			return command_fail(cmd, LIGHTNINGD,
					"Channel is in state %s", channel_state_name(channel));
		set_channel_fees(cmd, channel, *base, *ppm, response);
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

	sign_last_tx(channel);
	json_add_tx(response, "tx", channel->last_tx);
	remove_sig(channel->last_tx);

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

	channel_fail_permanent(channel, "Failing due to dev-fail command");
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
	json_add_txid(response, "funding_txid", &forget->channel->funding_txid);

	/* Set error so we don't try to reconnect. */
	forget->channel->error = towire_errorfmt(forget->channel, NULL,
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
	struct channel_id *find_cid, cid;
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
			derive_channel_id(&cid, &channel->funding_txid,
					  channel->funding_outnum);

			if (!channel_id_eq(find_cid, &cid))
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

	bitcoind_getutxout(cmd->ld->topology->bitcoind,
			   &forget->channel->funding_txid,
			   forget->channel->funding_outnum,
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

			/* Note: closingd does its own checking automatically */
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

struct custommsg_payload {
	struct node_id peer_id;
	const u8 *msg;
};

static void custommsg_callback(struct custommsg_payload *payload STEALS,
			       const char *buffer, const jsmntok_t *toks)
{
	tal_free(payload);
}

static void custommsg_payload_serialize(struct custommsg_payload *payload,
					struct json_stream *stream)
{
	json_add_hex_talarr(stream, "message", payload->msg);
	json_add_node_id(stream, "peer_id", &payload->peer_id);
}

REGISTER_SINGLE_PLUGIN_HOOK(custommsg,
			    custommsg_callback,
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
    "dev-sendcustommsg",
    "utility",
    json_sendcustommsg,
    "Send a custom message to the peer with the given {node_id}",
    .verbose = "dev-sendcustommsg node_id hexcustommsg",
};

AUTODATA(json_command, &sendcustommsg_command);

#endif /* DEVELOPER */

