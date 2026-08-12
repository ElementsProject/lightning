/* Main simple-close daemon: implements option_simple_close (BOLT #2).
 * Runs after channeld signals shutdown_complete, replacing closingd
 * when option_simple_close is negotiated. */
#include "config.h"
#include <bitcoin/pubkey.h>
#include <bitcoin/script.h>
#include <bitcoin/signature.h>
#include <ccan/cast/cast.h>
#include <ccan/mem/mem.h>
#include <ccan/tal/str/str.h>
#include <closingd/simpleclosed_wiregen.h>
#include <common/close_tx.h>
#include <common/memleak.h>
#include <common/peer_billboard.h>
#include <common/peer_failed.h>
#include <common/peer_io.h>
#include <common/per_peer_state.h>
#include <common/read_peer_msg.h>
#include <common/shutdown_scriptpubkey.h>
#include <common/status.h>
#include <common/subdaemon.h>
#include <common/utils.h>
#include <errno.h>
#include <hsmd/hsmd_wiregen.h>
#include <inttypes.h>
#include <stdio.h>
#include <unistd.h>
#include <wally_script.h>
#include <wire/peer_wire.h>
#include <wire/wire_sync.h>

/* stdin == requests from master, 3 == peer fd, 4 == hsmd fd */
#define REQ_FD STDIN_FILENO
#define PEER_FD 3
#define HSM_FD 4

/* Approx weight of a simple-close tx with both outputs (vbytes * 4 for weight).
 * Input: 41vb, witness: ~222wu/4=55.5vb, outputs: ~65vb each, overhead: 11vb
 * Total ~236 vbytes = ~704 weight + witness ~222 = ~926wu, round to 900. */
#define SIMPLE_CLOSE_WEIGHT 900

static const u8 *hsm_req(const tal_t *ctx, const u8 *req TAKES)
{
	u8 *msg;
	if (!wire_sync_write(HSM_FD, req))
		status_failed(STATUS_FAIL_HSM_IO,
			"Writing to HSM: %s",
			strerror(errno));
	msg = wire_sync_read(ctx, HSM_FD);
	if (!msg)
		status_failed(STATUS_FAIL_HSM_IO,
			"Reading from HSM: %s",
			strerror(errno));
	return msg;
}

static struct per_peer_state *pps;

/* Tell master we got peer's closing_sig for our tx; block for txid reply. */
static struct bitcoin_txid master_got_sig(struct bitcoin_tx *tx,
					  const struct bitcoin_signature *sig)
{
	struct bitcoin_txid txid;
	u8 *msg;

	msg = towire_simpleclosed_got_sig(tmpctx, tx, sig);
	if (!wire_sync_write(REQ_FD, take(msg)))
		status_failed(STATUS_FAIL_MASTER_IO,
			"Writing got_sig: %s",
			strerror(errno));

	msg = wire_sync_read(tmpctx, REQ_FD);
	if (!msg)
		status_failed(STATUS_FAIL_MASTER_IO,
			"Reading got_sig_reply: %s",
			strerror(errno));
	if (!fromwire_simpleclosed_got_sig_reply(msg, &txid))
		status_failed(STATUS_FAIL_MASTER_IO,
			"Bad got_sig_reply: %s",
			tal_hex(tmpctx, msg));
	return txid;
}

/* Build one closing tx variant.  closer_script or closee_script may be NULL
 * to omit that output. */
static struct bitcoin_tx *make_close_tx(const tal_t *ctx,
					u32 *local_wallet_index,
					const struct ext_key *local_wallet_ext_key,
					const u8 *closer_script,
					const u8 *closee_script,
					const u8 *funding_wscript,
					const struct bitcoin_outpoint *funding,
					struct amount_sat funding_sats,
					struct amount_sat closer_amount,
					struct amount_sat closee_amount,
					u32 locktime)
{
	return create_simple_close_tx(ctx, local_wallet_index, local_wallet_ext_key,
		closer_script, closee_script, funding_wscript, funding, funding_sats,
		closer_amount, closee_amount, locktime);
}

/* Sign a simple close tx via HSM; returns bitcoin_signature. */
static struct bitcoin_signature sign_tx(const tal_t *ctx,
					struct bitcoin_tx *tx,
					const struct pubkey *remote_fundingkey)
{
	struct bitcoin_signature sig;
	const u8 *msg;

	msg = hsm_req(tmpctx,
		take(towire_hsmd_sign_mutual_close_tx(NULL, tx, remote_fundingkey)));
	if (!fromwire_hsmd_sign_tx_reply(msg, &sig))
		status_failed(STATUS_FAIL_HSM_IO,
			"Bad sign_mutual_close_tx reply %s",
			tal_hex(tmpctx, msg));
	return sig;
}

/* Build and send closing_complete as the closer.
 * Returns the TLVs we sent (so we can validate the closing_sig reply).
 * Also writes the computed fee into *fee_out. */
static struct tlv_closing_tlvs *send_closing_complete(
					const struct channel_id *channel_id,
					const struct bitcoin_outpoint *funding,
					struct amount_sat funding_sats,
					const struct pubkey *local_fundingkey,
					const struct pubkey *remote_fundingkey,
					u32 *local_wallet_index,
					const struct ext_key *local_wallet_ext_key,
					struct amount_sat local_sat,
					struct amount_sat remote_sat,
					struct amount_sat dust_limit,
					u32 feerate_perkw,
					const u8 *local_script,
					const u8 *remote_script,
					u32 locktime,
					struct amount_sat *fee_out)
{
	const u8 *funding_wscript;
	struct amount_sat fee, closer_amount, closee_amount;
	bool is_lesser, closee_dust, closer_dust;
	struct bitcoin_tx *tx_both, *tx_closer_only, *tx_closee_only;
	struct bitcoin_signature sig;
	struct tlv_closing_tlvs *tlvs;
	u8 *msg;

	funding_wscript = bitcoin_redeem_2of2(tmpctx,
		local_fundingkey, remote_fundingkey);

	/* Fee: feerate * weight / 1000, capped at our balance. */
	fee = amount_sat((u64)feerate_perkw * SIMPLE_CLOSE_WEIGHT / 1000);
	if (amount_sat_greater(fee, local_sat))
		fee = local_sat; /* Can't pay more than we have */

	if (!amount_sat_sub(&closer_amount, local_sat, fee))
		closer_amount = AMOUNT_SAT(0);
	closee_amount = remote_sat;

	is_lesser = amount_sat_less(local_sat, remote_sat);
	closee_dust = amount_sat_less(closee_amount, dust_limit)
		      && !is_valid_op_return(remote_script, tal_bytelen(remote_script));
	closer_dust = amount_sat_less(closer_amount, dust_limit)
		      && !is_valid_op_return(local_script, tal_bytelen(local_script));

	tlvs = tlv_closing_tlvs_new(tmpctx);

	/* BOLT #2:
	 * The sender of `closing_complete` (aka. "the closer"):
	 * ...
	 * - If the local outstanding balance (in millisatoshi) is less than the remote outstanding balance:
	 *   - MUST NOT set `closer_output_only`.
	 */
	if (is_lesser) {
		/* BOLT #2:
		 * ...
		 *   - MUST set `closee_output_only` if the local output amount is dust.
		 *   - MAY set `closee_output_only` if it considers the local output amount uneconomical AND its `closer_scriptpubkey` is not `OP_RETURN`.
		 */
		if (closer_dust) {
			/* Our output is dust: sign tx with only closee output */
			tx_closee_only = make_close_tx(tmpctx, NULL, NULL, NULL,
				remote_script, funding_wscript, funding, funding_sats,
				AMOUNT_SAT(0), closee_amount, locktime);
			if (tx_closee_only) {
				sig = sign_tx(tmpctx, tx_closee_only, remote_fundingkey);
				tlvs->closee_output_only = tal(tlvs, secp256k1_ecdsa_signature);
				*tlvs->closee_output_only = sig.s;
			}
		} else {
			/* Both outputs present; closee can use this. */
			tx_both = make_close_tx(tmpctx, local_wallet_index,
				local_wallet_ext_key, local_script, remote_script,
				funding_wscript, funding, funding_sats, closer_amount,
				closee_amount, locktime);
			if (tx_both) {
				sig = sign_tx(tmpctx, tx_both, remote_fundingkey);
				tlvs->closer_and_closee_outputs = tal(tlvs,
					secp256k1_ecdsa_signature);
				*tlvs->closer_and_closee_outputs = sig.s;
			}
		}
	} else {
		/* BOLT #2:
		* - Otherwise (not lesser amount, cannot remove its own output):
		*   - MUST NOT set `closee_output_only`.
		*   - If it considers the local output amount uneconomical:
		*     - MAY send a `closer_scriptpubkey` that is a valid `OP_RETURN` script.
		*     - If it does, the output value MUST be set to zero so that all funds go to fees, as specified in [BOLT #3]...
		*/
		tx_closer_only = make_close_tx(tmpctx, local_wallet_index,
			local_wallet_ext_key, local_script, NULL, funding_wscript, funding,
			funding_sats, closer_amount, AMOUNT_SAT(0), locktime);
		if (tx_closer_only) {
			sig = sign_tx(tmpctx, tx_closer_only, remote_fundingkey);
			tlvs->closer_output_only = tal(tlvs, secp256k1_ecdsa_signature);
			*tlvs->closer_output_only = sig.s;
		}

		/* BOLT #2:
		 *   - If the closee's output amount is dust:
		 *     - MUST set `closer_output_only`.
		 *     - MUST NOT set `closer_and_closee_outputs`.
		 *   - Otherwise:
		 *     - MUST set both `closer_output_only` and `closer_and_closee_outputs`.
		 */
		if (!closee_dust) {
			/* Also sign the both-outputs variant. */
			tx_both = make_close_tx(tmpctx, local_wallet_index,
				local_wallet_ext_key, local_script, remote_script,
				funding_wscript, funding, funding_sats, closer_amount,
				closee_amount, locktime);
			if (tx_both) {
				sig = sign_tx(tmpctx, tx_both, remote_fundingkey);
				tlvs->closer_and_closee_outputs = tal(tlvs,
					secp256k1_ecdsa_signature);
				*tlvs->closer_and_closee_outputs = sig.s;
			}
		}
	}

	/* Sanity: must have at least one sig to send. */
	if (!tlvs->closer_output_only && !tlvs->closee_output_only
	    && !tlvs->closer_and_closee_outputs)
		status_failed(STATUS_FAIL_INTERNAL_ERROR,
			"No valid closing tx variant could be built "
			"(local=%s remote=%s fee=%s dust=%s)",
			fmt_amount_sat(tmpctx, local_sat),
			fmt_amount_sat(tmpctx, remote_sat),
			fmt_amount_sat(tmpctx, fee),
			fmt_amount_sat(tmpctx, dust_limit));

	msg = towire_closing_complete(tmpctx, channel_id, local_script,
		remote_script, fee, locktime, tlvs);
	peer_write(pps, take(msg));

	*fee_out = fee;
	status_debug("Sent closing_complete: closer=%s closee=%s fee=%s",
		fmt_amount_sat(tmpctx, closer_amount),
		fmt_amount_sat(tmpctx, closee_amount),
		fmt_amount_sat(tmpctx, fee));
	return tlvs;
}

static struct bitcoin_signature check_their_sig(
	const secp256k1_ecdsa_signature *raw_sig,
	const struct bitcoin_tx *tx,
	const u8 *funding_wscript,
	const struct pubkey *remote_fundingkey,
	const struct channel_id *their_cid,
	const char *whatfield)
{
	struct bitcoin_signature sig;
	sig.sighash_type = SIGHASH_ALL;
	sig.s = *raw_sig;
	if (!check_tx_sig(tx, 0, NULL, funding_wscript, remote_fundingkey, &sig))
		peer_failed_warn(pps, their_cid,
			"Bad %s sig: tx=%s funding_wscript=%s fundingkey=%s",
			whatfield,
			fmt_bitcoin_tx(tmpctx, tx),
			tal_hex(tmpctx, funding_wscript),
			fmt_pubkey(tmpctx, remote_fundingkey));
	return sig;
}

static secp256k1_ecdsa_signature *our_sig(const tal_t *ctx,
					   struct bitcoin_tx *tx,
					   const struct pubkey *remote_fundingkey,
					   struct bitcoin_signature *sig_out,
					   const char *whatfield)
{
	secp256k1_ecdsa_signature *result;
	*sig_out = sign_tx(tmpctx, tx, remote_fundingkey);
	result = tal(ctx, secp256k1_ecdsa_signature);
	*result = sig_out->s;
	status_debug("Signed %s: tx=%s", whatfield, fmt_bitcoin_tx(tmpctx, tx));
	return result;
}

/* As closee: receive peer's closing_complete, sign the right variant,
 * send closing_sig, and broadcast.  Returns the tx we signed. */
static struct bitcoin_tx *handle_closing_complete(
					const struct bitcoin_outpoint *funding,
					struct amount_sat funding_sats,
					const struct pubkey *local_fundingkey,
					const struct pubkey *remote_fundingkey,
					u32 *local_wallet_index,
					const struct ext_key *local_wallet_ext_key,
					struct amount_sat local_sat,
					struct amount_sat dust_limit,
					const u8 *our_last_script,
					const u8 *msg,
					struct amount_sat *their_fee_out)
{
	struct channel_id their_cid = {};
	u8 *closer_script, *closee_script;
	struct amount_sat fee_sat;
	u32 locktime;
	struct tlv_closing_tlvs *tlvs;
	struct tlv_closing_tlvs *reply_tlvs;
	struct bitcoin_tx *chosen_tx;
	struct bitcoin_signature sig;
	struct amount_sat closer_amount, closee_amount;
	const u8 *funding_wscript;
	u8 *reply;
	bool anysegwit = true, option_simple_close = true;
	struct amount_sat remote_sat;

	if (!fromwire_closing_complete(tmpctx, msg, &their_cid, &closer_script,
			&closee_script, &fee_sat, &locktime, &tlvs))
		peer_failed_warn(pps, &their_cid,
				 "Bad closing_complete: %s",
				 tal_hex(tmpctx, msg));

	*their_fee_out = fee_sat;

	/* BOLT #2:
	 * The receiver of `closing_complete` (aka. "the closee"):
	 * ...
	 * - If `closee_scriptpubkey` does not match the last script it sent (from `closing_complete` or from the initial `shutdown`):
	 *   - SHOULD ignore `closing_complete`.
	 *   - SHOULD send a `warning`.
	 *   - SHOULD close the connection.
	 */
	if (!scripteq(closee_script, our_last_script)) {
		peer_failed_warn(pps, &their_cid,
			"closing_complete closee_script %s != our script %s: "
			"reconnect to resync",
			tal_hex(tmpctx, closee_script),
			tal_hex(tmpctx, our_last_script));
	}

	/* BOLT #2:
	 * The receiver of `closing_complete` (aka. "the closee"):
	 * ...
	 * - If `closer_scriptpubkey` is invalid (as detailed in the [`shutdown` requirements](#closing-initiation-shutdown)):
	 *   - SHOULD ignore `closing_complete`.
	 *   - SHOULD send a `warning`.
	 *   - SHOULD close the connection.
	 */
	if (!valid_shutdown_scriptpubkey(closer_script, anysegwit, false,
			option_simple_close))
		peer_failed_warn(pps, &their_cid,
			"Invalid closer_scriptpubkey in closing_complete: %s",
			tal_hex(tmpctx, closer_script));

	funding_wscript = bitcoin_redeem_2of2(tmpctx, local_fundingkey,
		remote_fundingkey);

	/* Compute amounts: closer pays fee, closee gets remote_sat. */
	if (!amount_sat_sub(&remote_sat, funding_sats, local_sat))
		remote_sat = AMOUNT_SAT(0);

	/* BOLT #2:
	 * The receiver of `closing_complete` (aka. "the closee"):
	 * - If `fee_satoshis` is greater than the closer's outstanding balance:
	 *   - MUST either send a `warning` and close the connection, or send an `error` and fail the channel.
	 */
	if (is_valid_op_return(closer_script, tal_bytelen(closer_script)))
		closer_amount = AMOUNT_SAT(0);
	else if (!amount_sat_sub(&closer_amount, remote_sat, fee_sat))
		peer_failed_warn(pps, &their_cid, "Closer fee %s exceeds their balance %s",
			fmt_amount_sat(tmpctx, fee_sat),
			fmt_amount_sat(tmpctx, remote_sat));

	if (is_valid_op_return(closee_script, tal_bytelen(closee_script)))
		closee_amount = AMOUNT_SAT(0);
	else
		closee_amount = local_sat;

	bool our_output_dust = amount_sat_less(closee_amount, dust_limit)
		&& !is_valid_op_return(closee_script, tal_bytelen(closee_script));

	reply_tlvs = tlv_closing_tlvs_new(tmpctx);

	struct bitcoin_signature their_sig;

	/* BOLT #2:
	 * The receiver of `closing_complete` (aka. "the closee"):
	 * ...
	 * - Select a signature for validation:
	 *   - If the local output amount is dust:
	 *     - MUST use `closer_output_only`.
	 *   - Otherwise, if it considers the local output amount uneconomical AND its `closee_scriptpubkey` is not `OP_RETURN`:
	 *     - MUST use `closer_output_only`.
	 *   - Otherwise, if `closer_and_closee_outputs` is present:
	 *     - MUST use `closer_and_closee_outputs`.
	 *   - Otherwise:
	 *     - MUST use `closee_output_only`.
	 * - If the selected signature field does not exist:
	 *   - MUST either send a `warning` and close the connection, or send an `error` and fail the channel.
	 * - If the signature field is not valid for the corresponding closing transaction specified in [BOLT #3]...:
	 *   - MUST either send a `warning` and close the connection, or send an `error` and fail the channel.
	 */
	if (our_output_dust) {
		if (!tlvs->closer_output_only)
			peer_failed_warn(pps, &their_cid,
					 "Our output is dust but no "
					 "closer_output_only sig provided");
		chosen_tx = make_close_tx(tmpctx, local_wallet_index,
			local_wallet_ext_key, closer_script, NULL, funding_wscript,
			funding, funding_sats, closer_amount, AMOUNT_SAT(0), locktime);
		reply_tlvs->closer_output_only = our_sig(reply_tlvs, chosen_tx,
			remote_fundingkey, &sig, "closer_output_only");
		their_sig = check_their_sig(tlvs->closer_output_only, chosen_tx,
			funding_wscript, remote_fundingkey, &their_cid,
			"closer_output_only");
	} else if (tlvs->closer_and_closee_outputs) {
		chosen_tx = make_close_tx(tmpctx, local_wallet_index,
			local_wallet_ext_key, closer_script, closee_script,
			funding_wscript, funding, funding_sats, closer_amount,
			closee_amount, locktime);
		reply_tlvs->closer_and_closee_outputs = our_sig(reply_tlvs, chosen_tx,
			remote_fundingkey, &sig, "closer_and_closee_outputs");
		their_sig = check_their_sig(tlvs->closer_and_closee_outputs, chosen_tx,
			funding_wscript, remote_fundingkey, &their_cid,
			"closer_and_closee_outputs");
	} else {
		if (!tlvs->closee_output_only)
			peer_failed_warn(pps, &their_cid, "No valid sig variant in "
				"closing_complete");
		chosen_tx = make_close_tx(tmpctx, local_wallet_index,
			local_wallet_ext_key, NULL, closee_script, funding_wscript,
			funding, funding_sats, AMOUNT_SAT(0), closee_amount, locktime);
		reply_tlvs->closee_output_only = our_sig(reply_tlvs, chosen_tx,
			remote_fundingkey, &sig, "closee_output_only");
		their_sig = check_their_sig(tlvs->closee_output_only, chosen_tx,
			funding_wscript, remote_fundingkey, &their_cid,
			"closee_output_only");
	}

	/* BOLT #2:
	 * The receiver of `closing_complete` (aka. "the closee"):
	 * ...
	 * - MUST send `closing_sig` with a single valid signature in the same TLV field as the `closing_complete`.
	 */
	reply = towire_closing_sig(tmpctx, &their_cid, closer_script,
		closee_script, fee_sat, locktime, reply_tlvs);
	peer_write(pps, take(reply));

	status_debug("Sent closing_sig (as closee), notifying master");

	/* Tell master to validate, store, and handle broadcast. */
	wire_sync_write(REQ_FD,
			take(towire_simpleclosed_closee_broadcast(NULL,
					chosen_tx, &their_sig)));
	return chosen_tx;
}

/* As closer: validate the closing_sig we got back.
 * Returns the closing tx; writes peer's sig to *their_sig_out. */
static struct bitcoin_tx *handle_closing_sig(
				const struct bitcoin_outpoint *funding,
				struct amount_sat funding_sats,
				const struct pubkey *local_fundingkey,
				const struct pubkey *remote_fundingkey,
				u32 *local_wallet_index,
				const struct ext_key *local_wallet_ext_key,
				struct amount_sat local_sat,
				struct amount_sat remote_sat,
				struct amount_sat dust_limit,
				const u8 *sent_closer_script,
				const u8 *sent_closee_script,
				struct amount_sat sent_fee,
				u32 sent_locktime,
				const struct tlv_closing_tlvs *sent_tlvs,
				const u8 *msg,
				struct bitcoin_signature *their_sig_out)
{
	struct channel_id their_cid = {};
	u8 *closer_script, *closee_script;
	struct amount_sat fee_sat;
	u32 locktime;
	struct tlv_closing_tlvs *tlvs;
	const u8 *funding_wscript;
	struct amount_sat closer_amount, closee_amount;

	if (!fromwire_closing_sig(tmpctx, msg, &their_cid,&closer_script,
			&closee_script, &fee_sat, &locktime, &tlvs))
		peer_failed_warn(pps, &their_cid,
			"Bad closing_sig: %s",
			tal_hex(tmpctx, msg));

	/* BOLT #2:
	 * The receiver of `closing_sig`:
	 *   - If `closer_scriptpubkey`, `closee_scriptpubkey`, `fee_satoshis` or `locktime` don't match what was sent in `closing_complete`:
	 *     - MUST either send a `warning` and close the connection, or send an `error` and fail the channel.
	 */
	if (!scripteq(closer_script, sent_closer_script)
	    || !scripteq(closee_script, sent_closee_script)
	    || !amount_sat_eq(fee_sat, sent_fee)
	    || locktime != sent_locktime)
		peer_failed_warn(pps, &their_cid, "closing_sig fields don't match our "
			"closing_complete (script/fee/locktime mismatch)");

	/* BOLT #2:
	 * The receiver of `closing_sig`:
	 * ...
	 * - If `tlvs` does not contain exactly one signature:
	 *   - MUST either send a `warning` and close the connection, or send an `error` and fail the channel.
	 */
	int nsigs = (tlvs->closer_output_only ? 1 : 0)
		+ (tlvs->closee_output_only ? 1 : 0)
		+ (tlvs->closer_and_closee_outputs ? 1 : 0);
	if (nsigs != 1)
		peer_failed_warn(pps, &their_cid,
			"closing_sig must have exactly one sig, got %d",
			nsigs);

	if (tlvs->closer_output_only && !sent_tlvs->closer_output_only)
		peer_failed_warn(pps, &their_cid,
			"closing_sig closer_output_only not in our "
			"closing_complete");
	if (tlvs->closee_output_only && !sent_tlvs->closee_output_only)
		peer_failed_warn(pps, &their_cid,
			"closing_sig closee_output_only not in our "
			"closing_complete");
	if (tlvs->closer_and_closee_outputs
	    && !sent_tlvs->closer_and_closee_outputs)
		peer_failed_warn(pps, &their_cid,
			"closing_sig closer_and_closee_outputs not in "
			"our closing_complete");

	funding_wscript = bitcoin_redeem_2of2(tmpctx, local_fundingkey,
		remote_fundingkey);

	if (is_valid_op_return(closer_script, tal_bytelen(closer_script)))
		closer_amount = AMOUNT_SAT(0);
	else if (!amount_sat_sub(&closer_amount, local_sat, fee_sat))
		closer_amount = AMOUNT_SAT(0);

	if (is_valid_op_return(closee_script, tal_bytelen(closee_script)))
		closee_amount = AMOUNT_SAT(0);
	else
		closee_amount = remote_sat;

	/* Reconstruct the tx that was signed. */
	struct bitcoin_tx *signed_tx;
	struct bitcoin_signature their_sig;
	their_sig.sighash_type = SIGHASH_ALL;

	if (tlvs->closer_output_only) {
		their_sig.s = *tlvs->closer_output_only;
		signed_tx = make_close_tx(tmpctx, local_wallet_index,
			local_wallet_ext_key, closer_script, NULL, funding_wscript,
			funding, funding_sats, closer_amount, AMOUNT_SAT(0), locktime);
	} else if (tlvs->closee_output_only) {
		their_sig.s = *tlvs->closee_output_only;
		signed_tx = make_close_tx(tmpctx, NULL, NULL, NULL, closee_script,
			funding_wscript, funding, funding_sats, AMOUNT_SAT(0),
			closee_amount, locktime);
	} else {
		their_sig.s = *tlvs->closer_and_closee_outputs;
		signed_tx = make_close_tx(tmpctx, local_wallet_index,
			local_wallet_ext_key, closer_script, closee_script,
			funding_wscript, funding, funding_sats, closer_amount,
			closee_amount, locktime);
	}

	/* BOLT #2:
	 * The receiver of `closing_sig`:
	 * ...
	 * - If the signature field is not valid for the corresponding closing transaction specified in [BOLT #3]...:
	 *   - MUST either send a `warning` and close the connection, or send an `error` and fail the channel.
	 */
	if (!check_tx_sig(signed_tx, 0, NULL, funding_wscript,
			remote_fundingkey, &their_sig))
		peer_failed_warn(pps, &their_cid,
			"Bad signature in closing_sig: tx=%s funding_wscript=%s fundingkey=%s",
			fmt_bitcoin_tx(tmpctx, signed_tx),
			tal_hex(tmpctx, funding_wscript),
			fmt_pubkey(tmpctx, remote_fundingkey));

	status_debug("closing_sig verified OK, sending to master");
	*their_sig_out = their_sig;
	return signed_tx;
}

int main(int argc, char *argv[])
{
	setup_locale();

	const tal_t *ctx = tal(NULL, char);
	u8 *msg;
	struct pubkey local_fundingkey, remote_fundingkey;
	struct bitcoin_outpoint funding;
	struct amount_sat funding_sats, local_sat, remote_sat, dust_limit;
	u32 feerate_perkw;
	u32 *local_wallet_index;
	struct ext_key *local_wallet_ext_key;
	u8 *local_script, *remote_script;
	struct channel_id channel_id;
	enum side opener;
	bool got_peer_complete, got_our_sig;
	struct tlv_closing_tlvs *sent_tlvs;
	u8 *sent_closer_script, *sent_closee_script;
	struct amount_sat sent_fee, their_fee;
	u32 sent_locktime = 0;

	subdaemon_setup(argc, argv);

	status_setup_sync(REQ_FD);

	msg = wire_sync_read(tmpctx, REQ_FD);
	if (!fromwire_simpleclosed_init(ctx, msg, &chainparams, &channel_id,
			&funding, &funding_sats, &local_fundingkey, &remote_fundingkey,
			&local_sat, &remote_sat, &dust_limit, &feerate_perkw,
			&local_wallet_index, &local_wallet_ext_key, &local_script,
			&remote_script, &opener))
		status_failed(STATUS_FAIL_MASTER_IO,
			"Bad simpleclosed_init: %s",
			tal_hex(tmpctx, msg));

	/* stdin == requests, 3 == peer, 4 = hsmd */
	pps = notleak(new_per_peer_state(ctx));
	per_peer_state_set_fd(pps, PEER_FD);

	status_debug("Simple close starting: local=%s remote=%s",
		fmt_amount_sat(tmpctx, local_sat),
		fmt_amount_sat(tmpctx, remote_sat));

	/* Send our own closing_complete as the closer. */
	sent_closer_script = local_script;
	sent_closee_script = remote_script;
	sent_locktime = 0; /* nLockTime = 0 for initial proposal */

	sent_tlvs = send_closing_complete(&channel_id, &funding, funding_sats,
		&local_fundingkey, &remote_fundingkey, local_wallet_index,
		local_wallet_ext_key, local_sat, remote_sat, dust_limit,
		feerate_perkw, local_script, remote_script, sent_locktime,
		&sent_fee);
	/* sent_tlvs is allocated on tmpctx inside send_closing_complete; steal
	 * it onto ctx so it survives clean_tmpctx() calls in the exchange loop. */
	tal_steal(ctx, sent_tlvs);

	/* Exchange loop: wait for peer's closing_complete and our closing_sig. */
	got_peer_complete = false;
	got_our_sig = false;

	while (!got_peer_complete || !got_our_sig) {
		clean_tmpctx();
		msg = peer_read(tmpctx, pps);

		switch (fromwire_peektype(msg)) {
		case WIRE_CLOSING_COMPLETE:
			/* Peer sends us their closing_complete: we are the closee. */
			if (got_peer_complete) {
				status_debug("Got another closing_complete "
					"(peer bumping fee): re-signing");
			}
			handle_closing_complete(&funding, funding_sats,
				&local_fundingkey, &remote_fundingkey, local_wallet_index,
				local_wallet_ext_key, local_sat, dust_limit, local_script,
				msg, &their_fee);
			got_peer_complete = true;
			break;

		case WIRE_CLOSING_SIG: {
			/* Peer replies to our closing_complete: we are the closer. */
			struct bitcoin_tx *closing_tx;
			struct bitcoin_txid txid;
			struct bitcoin_signature their_sig;

			closing_tx = handle_closing_sig(&funding,
				funding_sats, &local_fundingkey, &remote_fundingkey,
				local_wallet_index, local_wallet_ext_key, local_sat,
				remote_sat, dust_limit, sent_closer_script, sent_closee_script,
				sent_fee, sent_locktime, sent_tlvs, msg, &their_sig);
			txid = master_got_sig(closing_tx, &their_sig);
			status_debug("Closer tx stored by master: %s",
				fmt_bitcoin_txid(tmpctx, &txid));
			got_our_sig = true;
			break;
		}

		case WIRE_CLOSING_SIGNED:
			/* Peer is still running legacy close — shouldn't happen
			 * if option_simple_close was negotiated. */
			peer_failed_warn(pps, &channel_id,
				"Got legacy closing_signed but "
				"option_simple_close was negotiated");
			break;

		/* These are all swallowed by connectd */
		case WIRE_PROTOCOL_BATCH_ELEMENT:
        case WIRE_CHANNEL_ANNOUNCEMENT:
        case WIRE_CHANNEL_UPDATE:
        case WIRE_NODE_ANNOUNCEMENT:
        case WIRE_QUERY_SHORT_CHANNEL_IDS:
        case WIRE_QUERY_CHANNEL_RANGE:
        case WIRE_REPLY_CHANNEL_RANGE:
        case WIRE_GOSSIP_TIMESTAMP_FILTER:
        case WIRE_REPLY_SHORT_CHANNEL_IDS_END:
        case WIRE_PING:
        case WIRE_PONG:
        case WIRE_WARNING:
        case WIRE_ERROR:
        case WIRE_ONION_MESSAGE:
        case WIRE_PEER_STORAGE:
        case WIRE_PEER_STORAGE_RETRIEVAL:
			/* Ignore unknown messages (e.g. gossip). */
			status_debug("Ignoring message type %d in simple close",
				fromwire_peektype(msg));
			break;

		/* These are unexpected messages. Warn the peer */
        case WIRE_INIT:
		case WIRE_TX_ADD_INPUT:
        case WIRE_TX_ADD_OUTPUT:
        case WIRE_TX_REMOVE_INPUT:
        case WIRE_TX_REMOVE_OUTPUT:
        case WIRE_TX_COMPLETE:
        case WIRE_TX_SIGNATURES:
        case WIRE_TX_INIT_RBF:
        case WIRE_TX_ACK_RBF:
        case WIRE_TX_ABORT:
        case WIRE_OPEN_CHANNEL:
        case WIRE_ACCEPT_CHANNEL:
        case WIRE_FUNDING_CREATED:
        case WIRE_FUNDING_SIGNED:
        case WIRE_CHANNEL_READY:
        case WIRE_OPEN_CHANNEL2:
        case WIRE_ACCEPT_CHANNEL2:
        case WIRE_STFU:
        case WIRE_SPLICE_INIT:
        case WIRE_SPLICE_ACK:
        case WIRE_SPLICE_LOCKED:
        case WIRE_SHUTDOWN:
        case WIRE_UPDATE_ADD_HTLC:
        case WIRE_UPDATE_FULFILL_HTLC:
        case WIRE_UPDATE_FAIL_HTLC:
        case WIRE_UPDATE_FAIL_MALFORMED_HTLC:
        case WIRE_START_BATCH:
        case WIRE_COMMITMENT_SIGNED:
        case WIRE_REVOKE_AND_ACK:
        case WIRE_UPDATE_FEE:
        case WIRE_UPDATE_BLOCKHEIGHT:
        case WIRE_CHANNEL_REESTABLISH:
        case WIRE_ANNOUNCEMENT_SIGNATURES:
			peer_failed_warn(pps, &channel_id,
				"Peer sent unexpected message %u (%s)",
			 	fromwire_peektype(msg),
				peer_wire_name(fromwire_peektype(msg)));
			break;
		}
	}

	/* Decide whether to ask master to delay broadcasting our closer tx.
	 * If our output (closer pays the full fee) is less than the peer's
	 * output AND our proposed fee is lower than theirs, their tx has a
	 * better chance of being mined first — give it an hour head-start.
	 * Skip when closer_amount is zero: our output is dust and will be
	 * omitted regardless, so there is nothing to protect by waiting. */
	struct amount_sat closer_amount;
	if (!amount_sat_sub(&closer_amount, local_sat, sent_fee))
		closer_amount = AMOUNT_SAT(0);
	bool delay_broadcast = amount_sat_greater(closer_amount, AMOUNT_SAT(0))
		&& amount_sat_less(closer_amount, remote_sat)
		&& amount_sat_less(sent_fee, their_fee);
	if (delay_broadcast)
		status_debug("Simple close: requesting delayed broadcast"
			" (our output %s < peer %s, our fee %s < their fee %s)",
			fmt_amount_sat(tmpctx, closer_amount),
			fmt_amount_sat(tmpctx, remote_sat),
			fmt_amount_sat(tmpctx, sent_fee),
			fmt_amount_sat(tmpctx, their_fee));

	wire_sync_write(REQ_FD, take(towire_simpleclosed_complete(NULL, delay_broadcast)));
	tal_free(ctx);
	daemon_shutdown();
}
