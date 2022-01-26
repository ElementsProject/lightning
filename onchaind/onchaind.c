#include "config.h"
#include <bitcoin/feerate.h>
#include <bitcoin/script.h>
#include <ccan/asort/asort.h>
#include <ccan/mem/mem.h>
#include <ccan/tal/str/str.h>
#include <common/htlc_tx.h>
#include <common/initial_commit_tx.h>
#include <common/keyset.h>
#include <common/lease_rates.h>
#include <common/memleak.h>
#include <common/overflows.h>
#include <common/peer_billboard.h>
#include <common/status.h>
#include <common/subdaemon.h>
#include <common/type_to_string.h>
#include <hsmd/hsmd_wiregen.h>
#include <onchaind/onchain_types.h>
#include <onchaind/onchaind_wiregen.h>
#include <unistd.h>
#include <wire/wire_sync.h>
  #include "onchain_types_names_gen.h"

/* stdin == requests */
#define REQ_FD STDIN_FILENO
#define HSM_FD 3

/* Required in various places: keys for commitment transaction. */
static const struct keyset *keyset;

/* IFF it's their commitment tx: HSM can't derive their per-commitment point! */
static const struct pubkey *remote_per_commitment_point;

/* The commitment number we're dealing with (if not mutual close) */
static u64 commit_num;

/* The feerate for the transaction spending our delayed output. */
static u32 delayed_to_us_feerate;

/* The feerate for transactions spending HTLC outputs. */
static u32 htlc_feerate;

/* The feerate for transactions spending from revoked transactions. */
static u32 penalty_feerate;

/* Min and max feerates we ever used */
static u32 min_possible_feerate, max_possible_feerate;

/* The dust limit to use when we generate transactions. */
static struct amount_sat dust_limit;

/* The CSV delays for each side. */
static u32 to_self_delay[NUM_SIDES];

/* Where we send money to (our wallet) */
static struct pubkey our_wallet_pubkey;

/* Their revocation secret (only if they cheated). */
static const struct secret *remote_per_commitment_secret;

/* one value is useful for a few witness scripts */
static const u8 ONE = 0x1;

/* When to tell master about HTLCs which are missing/timed out */
static u32 reasonable_depth;

/* The messages to send at that depth. */
static u8 **missing_htlc_msgs;

/* The messages which were sent to us before init_reply was processed. */
static u8 **queued_msgs;

/* Our recorded channel balance at 'chain time' */
static struct amount_msat our_msat;

/* Needed for anchor outputs */
static struct pubkey funding_pubkey[NUM_SIDES];

/* At what commit number does option_static_remotekey apply? */
static u64 static_remotekey_start[NUM_SIDES];

/* Does option_anchor_outputs apply to this commitment tx? */
static bool option_anchor_outputs;

/* The minimum relay feerate acceptable to the fullnode.  */
static u32 min_relay_feerate;

/* If we broadcast a tx, or need a delay to resolve the output. */
struct proposed_resolution {
	/* This can be NULL if our proposal is to simply ignore it after depth */
	const struct bitcoin_tx *tx;
	/* Non-zero if this is CSV-delayed. */
	u32 depth_required;
	enum tx_type tx_type;
};

/* How it actually got resolved. */
struct resolution {
	struct bitcoin_txid txid;
	unsigned int depth;
	enum tx_type tx_type;
};

struct tracked_output {
	enum tx_type tx_type;
	struct bitcoin_outpoint outpoint;
	u32 tx_blockheight;
	/* FIXME: Convert all depths to blocknums, then just get new blk msgs */
	u32 depth;
	struct amount_sat sat;
	enum output_type output_type;

	/* If it is an HTLC, this is set, wscript is non-NULL. */
	struct htlc_stub htlc;
	const u8 *wscript;

	/* If it's an HTLC off our unilateral, this is their sig for htlc_tx */
	const struct bitcoin_signature *remote_htlc_sig;

	/* Our proposed solution (if any) */
	struct proposed_resolution *proposal;

	/* If it is resolved. */
	struct resolution *resolved;

	/* stashed so we can pass it along to the coin ledger */
	struct sha256 payment_hash;
};

static const char *tx_type_name(enum tx_type tx_type)
{
	size_t i;

	for (i = 0; enum_tx_type_names[i].name; i++)
		if (enum_tx_type_names[i].v == tx_type)
			return enum_tx_type_names[i].name;
	return "unknown";
}

static const char *output_type_name(enum output_type output_type)
{
	size_t i;

	for (i = 0; enum_output_type_names[i].name; i++)
		if (enum_output_type_names[i].v == output_type)
			return enum_output_type_names[i].name;
	return "unknown";
}

/* helper to compare output script with our tal'd script */
static bool wally_tx_output_scripteq(const struct wally_tx_output *out,
				     const u8 *script)
{
	return memeq(out->script, out->script_len, script, tal_bytelen(script));
}

/* The feerate for the HTLC txs (which we grind) are the same as the
 * feerate for the main tx.  However, there may be dust HTLCs which
 * were added to the fee, so we can only estimate a maximum feerate */
static void trim_maximum_feerate(struct amount_sat funding,
				 const struct tx_parts *commitment)
{
	size_t weight;
	struct amount_sat fee = funding;

	/* FIXME: This doesn't work for elements? */
	if (chainparams->is_elements)
		return;

	weight = bitcoin_tx_core_weight(tal_count(commitment->inputs),
					tal_count(commitment->outputs));

	/* BOLT #3:
	 * ## Commitment Transaction
	 *...
	 *   * `txin[0]` script bytes: 0
	 *   * `txin[0]` witness: `0 <signature_for_pubkey1> <signature_for_pubkey2>`
	 */
	/* Account for witness (1 byte count + 1 empty + sig + sig) */
	assert(tal_count(commitment->inputs) == 1);
	weight += bitcoin_tx_input_weight(false, 1 + 1 + 2 * bitcoin_tx_input_sig_weight());

	for (size_t i = 0; i < tal_count(commitment->outputs); i++) {
		struct amount_asset amt;
		weight += bitcoin_tx_output_weight(commitment->outputs[i]
						   ->script_len);

		amt = wally_tx_output_get_amount(commitment->outputs[i]);
		if (!amount_asset_is_main(&amt))
			continue;
		if (!amount_sat_sub(&fee, fee, amount_asset_to_sat(&amt))) {
			status_failed(STATUS_FAIL_INTERNAL_ERROR,
				      "Unable to subtract fee");
		}
	}

	status_debug("reducing max_possible_feerate from %u...",
		     max_possible_feerate);
	/* This is naive, but simple. */
	while (amount_sat_greater(amount_tx_fee(max_possible_feerate, weight),
				  fee))
		max_possible_feerate--;
	status_debug("... to %u", max_possible_feerate);
}

static void send_coin_mvt(struct chain_coin_mvt *mvt TAKES)
{
	wire_sync_write(REQ_FD,
			take(towire_onchaind_notify_coin_mvt(NULL, mvt)));

	if (taken(mvt))
		tal_free(mvt);
}

static void record_channel_withdrawal(const struct bitcoin_txid *tx_txid,
				      struct tracked_output *out,
				      u32 blockheight,
				      enum mvt_tag tag)
{
	send_coin_mvt(take(new_onchaind_withdraw(NULL, &out->outpoint, tx_txid,
						 blockheight, out->sat, tag)));
}

static void record_external_spend(const struct bitcoin_txid *txid,
				  struct tracked_output *out,
				  u32 blockheight,
				  enum mvt_tag tag)
{
	send_coin_mvt(take(new_coin_external_spend(NULL, &out->outpoint,
						   txid, blockheight,
						   out->sat, tag)));
}

static void record_external_output(const struct bitcoin_outpoint *out,
				   struct amount_sat amount,
				   u32 blockheight,
				   enum mvt_tag tag)
{
	send_coin_mvt(take(new_coin_external_deposit(NULL, out, blockheight,
						     amount, tag)));
}

static void record_external_deposit(const struct tracked_output *out,
				    u32 blockheight,
				    enum mvt_tag tag)
{
	record_external_output(&out->outpoint, out->sat, blockheight, tag);
}

static void record_channel_deposit(struct tracked_output *out,
				   u32 blockheight, enum mvt_tag tag)
{
	send_coin_mvt(take(new_onchaind_deposit(NULL,
						&out->outpoint,
						blockheight, out->sat,
						tag)));
}

static void record_to_us_htlc_fulfilled(struct tracked_output *out,
					u32 blockheight)
{
	send_coin_mvt(take(new_onchain_htlc_deposit(NULL,
						    &out->outpoint,
						    blockheight,
						    out->sat,
						    &out->payment_hash)));
}

static void record_to_them_htlc_fulfilled(struct tracked_output *out,
					  u32 blockheight)
{

	send_coin_mvt(take(new_onchain_htlc_withdraw(NULL,
						     &out->outpoint,
						     blockheight,
						     out->sat,
						     &out->payment_hash)));
}

static void record_ignored_wallet_deposit(struct tracked_output *out)
{
	struct bitcoin_outpoint outpoint;

	/* Every spend tx we construct has a single output. */
	bitcoin_txid(out->proposal->tx, &outpoint.txid);
	outpoint.n = 0;

	enum mvt_tag tag = TO_WALLET;
	if (out->tx_type == OUR_HTLC_TIMEOUT_TX
	    || out->tx_type == OUR_HTLC_SUCCESS_TX)
		tag = HTLC_TX;
	else if (out->tx_type == THEIR_REVOKED_UNILATERAL)
		tag = PENALTY;
	else if (out->tx_type == OUR_UNILATERAL
		|| out->tx_type == THEIR_UNILATERAL) {
		if (out->output_type == OUR_HTLC)
			tag = HTLC_TIMEOUT;
	}
	if (out->output_type == DELAYED_OUTPUT_TO_US)
		tag = CHANNEL_TO_US;

	/* Record the in/out through the channel */
	record_channel_deposit(out, out->tx_blockheight, tag);
	record_channel_withdrawal(&outpoint.txid, out, 0, IGNORED);
}

static void record_anchor(struct tracked_output *out)
{
	send_coin_mvt(take(new_coin_wallet_deposit(NULL,
					&out->outpoint,
					out->tx_blockheight,
					out->sat, ANCHOR)));
}

static void record_coin_movements(struct tracked_output *out,
				  u32 blockheight,
				  const struct bitcoin_tx *tx,
				  const struct bitcoin_txid *txid)
{
	/* For 'timeout' htlcs, we re-record them as a deposit
	 * before we withdraw them again. When the channel closed,
	 * we reported this as withdrawn (since we didn't know the
	 * total amount of pending htlcs that are to-them). So
	 * we have to "deposit" it again before we withdraw it.
	 * This is just to make the channel account close out nicely
	 * AND so we can accurately calculate our on-chain fee burden */
	if (out->tx_type == OUR_HTLC_TIMEOUT_TX
	    || out->tx_type == OUR_HTLC_SUCCESS_TX)
		record_channel_deposit(out, blockheight, HTLC_TX);

	if (out->resolved->tx_type == OUR_HTLC_TIMEOUT_TO_US)
		record_channel_deposit(out, blockheight, HTLC_TIMEOUT);

	/* there is a case where we've fulfilled an htlc onchain,
	 * in which case we log a deposit to the channel */
	if (out->resolved->tx_type == THEIR_HTLC_FULFILL_TO_US
	    || out->resolved->tx_type == OUR_HTLC_SUCCESS_TX)
		record_to_us_htlc_fulfilled(out, blockheight);

	/* If it's our to-us and our close, we publish *another* tx
	 * which spends the output when the timeout ends */
	if (out->tx_type == OUR_UNILATERAL) {
		if (out->output_type == DELAYED_OUTPUT_TO_US)
			record_channel_deposit(out, blockheight, CHANNEL_TO_US);
		else if (out->output_type == OUR_HTLC) {
			record_channel_deposit(out, blockheight, HTLC_TIMEOUT);
			record_channel_withdrawal(txid, out, blockheight, HTLC_TIMEOUT);
		} else if (out->output_type == THEIR_HTLC)
			record_channel_withdrawal(txid, out, blockheight, HTLC_FULFILL);
	}

	if (out->tx_type == THEIR_REVOKED_UNILATERAL
	    || out->resolved->tx_type == OUR_PENALTY_TX)
		record_channel_deposit(out, blockheight, PENALTY);

	if (out->resolved->tx_type == OUR_DELAYED_RETURN_TO_WALLET
	    || out->resolved->tx_type == THEIR_HTLC_FULFILL_TO_US
	    || out->output_type == DELAYED_OUTPUT_TO_US
	    || out->resolved->tx_type == OUR_HTLC_TIMEOUT_TO_US
	    || out->resolved->tx_type == OUR_PENALTY_TX) {
		/* penalty rbf cases, the amount might be zero */
		if (amount_sat_zero(out->sat))
			record_channel_withdrawal(txid, out, blockheight, TO_MINER);
		else
			record_channel_withdrawal(txid, out, blockheight, TO_WALLET);
	}
}

/* We vary feerate until signature they offered matches. */
static bool grind_htlc_tx_fee(struct amount_sat *fee,
			      struct bitcoin_tx *tx,
			      const struct bitcoin_signature *remotesig,
			      const u8 *wscript,
			      u64 weight)
{
	struct amount_sat prev_fee = AMOUNT_SAT(UINT64_MAX), input_amt;
	input_amt = psbt_input_get_amount(tx->psbt, 0);

	for (u64 i = min_possible_feerate; i <= max_possible_feerate; i++) {
		/* BOLT #3:
		 *
		 * The fee for an HTLC-timeout transaction:
		 *   - If `option_anchors_zero_fee_htlc_tx` applies:
		 *     1. MUST BE 0.
		 *   - Otherwise, MUST BE calculated to match:
		 *     1. Multiply `feerate_per_kw` by 663
		 *        (666 if `option_anchor_outputs` applies)
		 *        and divide by 1000 (rounding down).
		 *
		 * The fee for an HTLC-success transaction:
		 *  - If `option_anchors_zero_fee_htlc_tx` applies:
		 *    1. MUST BE 0.
		 *  - MUST BE calculated to match:
		 *     1. Multiply `feerate_per_kw` by 703
		 *        (706 if `option_anchor_outputs` applies)
		 *        and divide by 1000 (rounding down).
		 */
		struct amount_sat out;

		*fee = amount_tx_fee(i, weight);

		/* Minor optimization: don't check same fee twice */
		if (amount_sat_eq(*fee, prev_fee))
			continue;

		prev_fee = *fee;
		if (!amount_sat_sub(&out, input_amt, *fee))
			break;

		bitcoin_tx_output_set_amount(tx, 0, out);
		bitcoin_tx_finalize(tx);
		if (!check_tx_sig(tx, 0, NULL, wscript,
				  &keyset->other_htlc_key, remotesig))
			continue;

		status_debug("grind feerate_per_kw for %"PRIu64" = %"PRIu64,
			     weight, i);
		return true;
	}
	return false;
}

static bool set_htlc_timeout_fee(struct bitcoin_tx *tx,
				 const struct bitcoin_signature *remotesig,
				 const u8 *wscript)
{
	static struct amount_sat amount, fee = AMOUNT_SAT_INIT(UINT64_MAX);
	struct amount_asset asset = bitcoin_tx_output_get_amount(tx, 0);
	size_t weight;

	/* BOLT #3:
	 *
	 * The fee for an HTLC-timeout transaction:
	 *  - If `option_anchors_zero_fee_htlc_tx` applies:
	 *    1. MUST BE 0.
	 *  - Otherwise, MUST BE calculated to match:
	 *    1. Multiply `feerate_per_kw` by 663 (666 if `option_anchor_outputs`
	 *       applies) and divide by 1000 (rounding down).
	 */
	if (option_anchor_outputs)
		weight = 666;
	else
		weight = 663;
	weight += elements_tx_overhead(chainparams, 1, 1);

	assert(amount_asset_is_main(&asset));
	amount = amount_asset_to_sat(&asset);

	if (amount_sat_eq(fee, AMOUNT_SAT(UINT64_MAX))) {
		struct amount_sat grindfee;
		if (grind_htlc_tx_fee(&grindfee, tx, remotesig, wscript, weight)) {
			/* Cache this for next time */
			fee = grindfee;
			return true;
		}
		return false;
	}

	if (!amount_sat_sub(&amount, amount, fee))
		status_failed(STATUS_FAIL_INTERNAL_ERROR,
			      "Cannot deduct htlc-timeout fee %s from tx %s",
			      type_to_string(tmpctx, struct amount_sat, &fee),
			      type_to_string(tmpctx, struct bitcoin_tx, tx));

	bitcoin_tx_output_set_amount(tx, 0, amount);
	bitcoin_tx_finalize(tx);
	return check_tx_sig(tx, 0, NULL, wscript,
			    &keyset->other_htlc_key, remotesig);
}

static void set_htlc_success_fee(struct bitcoin_tx *tx,
				 const struct bitcoin_signature *remotesig,
				 const u8 *wscript)
{
	static struct amount_sat amt, fee = AMOUNT_SAT_INIT(UINT64_MAX);
	struct amount_asset asset;
	size_t weight;

	/* BOLT #3:
	 *
	 * The fee for an HTLC-success transaction:
	 * - If `option_anchors_zero_fee_htlc_tx` applies:
	 *   1. MUST BE 0.
	 * - MUST BE calculated to match:
	 *   1. Multiply `feerate_per_kw` by 703 (706 if `option_anchor_outputs`
	 *      applies) and divide by 1000 (rounding down).
	 */
	if (option_anchor_outputs)
		weight = 706;
	else
		weight = 703;

	weight += elements_tx_overhead(chainparams, 1, 1);
	if (amount_sat_eq(fee, AMOUNT_SAT(UINT64_MAX))) {
		if (!grind_htlc_tx_fee(&fee, tx, remotesig, wscript, weight))
			status_failed(STATUS_FAIL_INTERNAL_ERROR,
				      "htlc_success_fee can't be found "
				      "for tx %s (weight %zu, feerate %u-%u), signature %s, wscript %s",
				      type_to_string(tmpctx, struct bitcoin_tx,
						     tx),
				      weight,
				      min_possible_feerate, max_possible_feerate,
				      type_to_string(tmpctx,
						     struct bitcoin_signature,
						     remotesig),
				      tal_hex(tmpctx, wscript));
		return;
	}

	asset = bitcoin_tx_output_get_amount(tx, 0);
	assert(amount_asset_is_main(&asset));
	amt = amount_asset_to_sat(&asset);

	if (!amount_sat_sub(&amt, amt, fee))
		status_failed(STATUS_FAIL_INTERNAL_ERROR,
			      "Cannot deduct htlc-success fee %s from tx %s",
			      type_to_string(tmpctx, struct amount_sat, &fee),
			      type_to_string(tmpctx, struct bitcoin_tx, tx));
	bitcoin_tx_output_set_amount(tx, 0, amt);
	bitcoin_tx_finalize(tx);

	if (check_tx_sig(tx, 0, NULL, wscript,
			 &keyset->other_htlc_key, remotesig))
		return;

	status_failed(STATUS_FAIL_INTERNAL_ERROR,
		      "htlc_success_fee %s failed sigcheck "
		      " for tx %s, signature %s, wscript %s",
		      type_to_string(tmpctx, struct amount_sat, &fee),
		      type_to_string(tmpctx, struct bitcoin_tx, tx),
		      type_to_string(tmpctx, struct bitcoin_signature, remotesig),
		      tal_hex(tmpctx, wscript));
}

static u8 *delayed_payment_to_us(const tal_t *ctx,
				 struct bitcoin_tx *tx,
				 const u8 *wscript)
{
	return towire_hsmd_sign_delayed_payment_to_us(ctx, commit_num,
						     tx, wscript);
}

static u8 *remote_htlc_to_us(const tal_t *ctx,
			     struct bitcoin_tx *tx,
			     const u8 *wscript)
{
	return towire_hsmd_sign_remote_htlc_to_us(ctx,
						 remote_per_commitment_point,
						 tx, wscript,
						 option_anchor_outputs);
}

static u8 *penalty_to_us(const tal_t *ctx,
			 struct bitcoin_tx *tx,
			 const u8 *wscript)
{
	return towire_hsmd_sign_penalty_to_us(ctx, remote_per_commitment_secret,
					     tx, wscript);
}

/*
 * This covers:
 * 1. to-us output spend (`<local_delayedsig> 0`)
 * 2. the their-commitment, our HTLC timeout case (`<remotehtlcsig> 0`),
 * 3. the their-commitment, our HTLC redeem case (`<remotehtlcsig> <payment_preimage>`)
 * 4. the their-revoked-commitment, to-local (`<revocation_sig> 1`)
 * 5. the their-revoked-commitment, htlc (`<revocation_sig> <revocationkey>`)
 *
 * Overrides *tx_type if it all turns to dust.
 */
static struct bitcoin_tx *tx_to_us(const tal_t *ctx,
				   u8 *(*hsm_sign_msg)(const tal_t *ctx,
						       struct bitcoin_tx *tx,
						       const u8 *wscript),
				   struct tracked_output *out,
				   u32 to_self_delay,
				   u32 locktime,
				   const void *elem, size_t elemsize,
				   const u8 *wscript,
				   enum tx_type *tx_type,
				   u32 feerate)
{
	struct bitcoin_tx *tx;
	struct amount_sat fee, min_out, amt;
	struct bitcoin_signature sig;
	size_t weight;
	u8 *msg;
	u8 **witness;

	tx = bitcoin_tx(ctx, chainparams, 1, 1, locktime);
	bitcoin_tx_add_input(tx, &out->outpoint, to_self_delay,
			     NULL, out->sat, NULL, wscript);

	bitcoin_tx_add_output(
	    tx, scriptpubkey_p2wpkh(tx, &our_wallet_pubkey), NULL, out->sat);

	/* Worst-case sig is 73 bytes */
	weight = bitcoin_tx_weight(tx) + 1 + 3 + 73 + 0 + tal_count(wscript);
	weight += elements_tx_overhead(chainparams, 1, 1);
	fee = amount_tx_fee(feerate, weight);

	/* Result is trivial?  Spend with small feerate, but don't wait
	 * around for it as it might not confirm. */
	if (!amount_sat_add(&min_out, dust_limit, fee))
		status_failed(STATUS_FAIL_INTERNAL_ERROR,
			      "Cannot add dust_limit %s and fee %s",
			      type_to_string(tmpctx, struct amount_sat, &dust_limit),
			      type_to_string(tmpctx, struct amount_sat, &fee));

	if (amount_sat_less(out->sat, min_out)) {
		/* FIXME: We should use SIGHASH_NONE so others can take it */
		fee = amount_tx_fee(feerate_floor(), weight);
		status_unusual("TX %s amount %s too small to"
			       " pay reasonable fee, using minimal fee"
			       " and ignoring",
			       tx_type_name(*tx_type),
			       type_to_string(tmpctx, struct amount_sat, &out->sat));
		*tx_type = IGNORING_TINY_PAYMENT;
	}

	/* This can only happen if feerate_floor() is still too high; shouldn't
	 * happen! */
	if (!amount_sat_sub(&amt, out->sat, fee)) {
		amt = dust_limit;
		status_broken("TX %s can't afford minimal feerate"
			      "; setting output to %s",
			      tx_type_name(*tx_type),
			      type_to_string(tmpctx, struct amount_sat,
					     &amt));
	}
	bitcoin_tx_output_set_amount(tx, 0, amt);
	bitcoin_tx_finalize(tx);

	if (!wire_sync_write(HSM_FD, take(hsm_sign_msg(NULL, tx, wscript))))
		status_failed(STATUS_FAIL_HSM_IO, "Writing sign request to hsm");
	msg = wire_sync_read(tmpctx, HSM_FD);
	if (!msg || !fromwire_hsmd_sign_tx_reply(msg, &sig)) {
		status_failed(STATUS_FAIL_HSM_IO,
			      "Reading sign_tx_reply: %s",
			      tal_hex(tmpctx, msg));
	}

	witness = bitcoin_witness_sig_and_element(tx, &sig, elem,
						  elemsize, wscript);
	bitcoin_tx_input_set_witness(tx, 0, take(witness));
	return tx;
}

/** replace_penalty_tx_to_us
 *
 * @brief creates a replacement TX for
 * a given penalty tx.
 *
 * @param ctx - the context to allocate
 * off of.
 * @param hsm_sign_msg - function to construct
 * the signing message to HSM.
 * @param penalty_tx - the original
 * penalty transaction.
 * @param output_amount - the output
 * amount to use instead of the
 * original penalty transaction.
 * If this amount is below the dust
 * limit, the output is replaced with
 * an `OP_RETURN` instead.
 *
 * @return the signed transaction.
 */
static struct bitcoin_tx *
replace_penalty_tx_to_us(const tal_t *ctx,
			 u8 *(*hsm_sign_msg)(const tal_t *ctx,
					     struct bitcoin_tx *tx,
					     const u8 *wscript),
			 const struct bitcoin_tx *penalty_tx,
			 struct amount_sat *output_amount)
{
	struct bitcoin_tx *tx;

	/* The penalty tx input.  */
	const struct wally_tx_input *input;
	/* Specs of the penalty tx input.  */
	struct bitcoin_outpoint input_outpoint;
	u8 *input_wscript;
	u8 *input_element;
	struct amount_sat input_amount;

	/* Signature from the HSM.  */
	u8 *msg;
	struct bitcoin_signature sig;
	/* Witness we generate from the signature and other data.  */
	u8 **witness;


	/* Get the single input of the penalty tx.  */
	input = &penalty_tx->wtx->inputs[0];
	/* Extract the input-side data.  */
	bitcoin_tx_input_get_txid(penalty_tx, 0, &input_outpoint.txid);
	input_outpoint.n = input->index;
	input_wscript = tal_dup_arr(tmpctx, u8,
				    input->witness->items[2].witness,
				    input->witness->items[2].witness_len,
				    0);
	input_element = tal_dup_arr(tmpctx, u8,
				    input->witness->items[1].witness,
				    input->witness->items[1].witness_len,
				    0);
	input_amount = psbt_input_get_amount(penalty_tx->psbt, 0);

	/* Create the replacement.  */
	tx = bitcoin_tx(ctx, chainparams, 1, 1, /*locktime*/ 0);
	/* Reconstruct the input.  */
	bitcoin_tx_add_input(tx, &input_outpoint,
			     BITCOIN_TX_RBF_SEQUENCE,
			     NULL, input_amount, NULL, input_wscript);
	/* Reconstruct the output with a smaller amount.  */
	if (amount_sat_greater(*output_amount, dust_limit))
		bitcoin_tx_add_output(tx,
				      scriptpubkey_p2wpkh(tx,
							  &our_wallet_pubkey),
				      NULL,
				      *output_amount);
	else {
		bitcoin_tx_add_output(tx,
				      scriptpubkey_opreturn_padded(tx),
				      NULL,
				      AMOUNT_SAT(0));
		*output_amount = AMOUNT_SAT(0);
	}

	/* Finalize the transaction.  */
	bitcoin_tx_finalize(tx);

	/* Ask HSM to sign it.  */
	if (!wire_sync_write(HSM_FD, take(hsm_sign_msg(NULL, tx,
							input_wscript))))
		status_failed(STATUS_FAIL_HSM_IO, "While feebumping penalty: writing sign request to hsm");
	msg = wire_sync_read(tmpctx, HSM_FD);
	if (!msg || !fromwire_hsmd_sign_tx_reply(msg, &sig))
		status_failed(STATUS_FAIL_HSM_IO, "While feebumping penalty: reading sign_tx_reply: %s", tal_hex(tmpctx, msg));

	/* Install the witness with the signature.  */
	witness = bitcoin_witness_sig_and_element(tx, &sig,
						  input_element,
						  tal_bytelen(input_element),
						  input_wscript);
	bitcoin_tx_input_set_witness(tx, 0, take(witness));

	return tx;
}

/** min_rbf_bump
 *
 * @brief computes the minimum RBF bump required by
 * BIP125, given an index.
 *
 * @desc BIP125 requires that an replacement transaction
 * pay, not just the fee of the evicted transactions,
 * but also the minimum relay fee for itself.
 * This function assumes that previous RBF attempts
 * paid exactly the return value for that attempt, on
 * top of the initial transaction fee.
 * It can serve as a baseline for other functions that
 * compute a suggested fee: get whichever is higher,
 * the fee this function suggests, or your own unique
 * function.
 *
 * This function is provided as a common function that
 * all RBF-bump computations can use.
 *
 * @param weight - the weight of the transaction you
 * are RBFing.
 * @param index - 0 makes no sense, 1 means this is
 * the first RBF attempt, 2 means this is the 2nd
 * RBF attempt, etc.
 *
 * @return the suggested total fee.
 */
static struct amount_sat min_rbf_bump(size_t weight,
				      size_t index)
{
	struct amount_sat min_relay_fee;
	struct amount_sat min_rbf_bump;

	/* Compute the minimum relay fee for a transaction of the given
	 * weight.  */
	min_relay_fee = amount_tx_fee(min_relay_feerate, weight);

	/* For every RBF attempt, we add the min-relay-fee.
	 * Or in other words, we multiply the min-relay-fee by the
	 * index number of the attempt.
	 */
	if (mul_overflows_u64(index, min_relay_fee.satoshis)) /* Raw: multiplication.  */
		min_rbf_bump = AMOUNT_SAT(UINT64_MAX);
	else
		min_rbf_bump.satoshis = index * min_relay_fee.satoshis; /* Raw: multiplication.  */

	return min_rbf_bump;
}

/** compute_penalty_output_amount
 *
 * @brief computes the appropriate output amount for a
 * penalty transaction that spends a theft transaction
 * that is already of a specific depth.
 *
 * @param initial_amount - the outout amount of the first
 * penalty transaction.
 * @param depth - the current depth of the theft
 * transaction.
 * @param max_depth - the maximum depth of the theft
 * transaction, after which the theft transaction will
 * succeed.
 * @param weight - the weight of the first penalty
 * transaction, in Sipa.
 */
static struct amount_sat
compute_penalty_output_amount(struct amount_sat initial_amount,
			      u32 depth, u32 max_depth,
			      size_t weight)
{
	struct amount_sat max_output_amount;
	struct amount_sat output_amount;
	struct amount_sat deducted_amount;

	assert(depth <= max_depth);
	assert(depth > 0);

	/* The difference between initial_amount, and the fee suggested
	 * by min_rbf_bump, is the largest allowed output amount.
	 *
	 * depth = 1 is the first attempt, thus maps to the 0th RBF
	 * (i.e. the initial attempt that is not RBFed itself).
	 * We actually start to replace at depth = 2, so we use
	 * depth - 1 as the index for min_rbf_bump.
	 */
	if (!amount_sat_sub(&max_output_amount,
			    initial_amount, min_rbf_bump(weight, depth - 1)))
		/* If min_rbf_bump is larger than the initial_amount,
		 * we should just donate the whole output as fee,
		 * meaning we get 0 output amount.
		 */
		return AMOUNT_SAT(0);

	/* Map the depth / max_depth into a number between 0->1.  */
	double x = (double) depth / (double) max_depth;
	/* Get the cube of the above position, resulting in a graph
	 * where the y is close to 0 up to less than halfway through,
	 * then quickly rises up to 1 as depth nears the max depth.
	 */
	double y = x * x * x;
	/* Scale according to the initial_amount.  */
	deducted_amount.satoshis = (u64) (y * initial_amount.satoshis); /* Raw: multiplication.  */

	/* output_amount = initial_amount - deducted_amount.  */
	if (!amount_sat_sub(&output_amount,
			    initial_amount, deducted_amount))
		/* If underflow, force to 0.  */
		output_amount = AMOUNT_SAT(0);

	/* If output exceeds max, return max.  */
	if (amount_sat_less(max_output_amount, output_amount))
		return max_output_amount;

	return output_amount;
}


static void hsm_sign_local_htlc_tx(struct bitcoin_tx *tx,
				   const u8 *wscript,
				   struct bitcoin_signature *sig)
{
	u8 *msg = towire_hsmd_sign_local_htlc_tx(NULL, commit_num,
						tx, wscript,
						option_anchor_outputs);

	if (!wire_sync_write(HSM_FD, take(msg)))
		status_failed(STATUS_FAIL_HSM_IO,
			      "Writing sign_local_htlc_tx to hsm");
	msg = wire_sync_read(tmpctx, HSM_FD);
	if (!msg || !fromwire_hsmd_sign_tx_reply(msg, sig))
		status_failed(STATUS_FAIL_HSM_IO,
			      "Reading sign_local_htlc_tx: %s",
			      tal_hex(tmpctx, msg));
}

static void hsm_get_per_commitment_point(struct pubkey *per_commitment_point)
{
	u8 *msg = towire_hsmd_get_per_commitment_point(NULL, commit_num);
	struct secret *unused;

	if (!wire_sync_write(HSM_FD, take(msg)))
		status_failed(STATUS_FAIL_HSM_IO, "Writing sign_htlc_tx to hsm");
	msg = wire_sync_read(tmpctx, HSM_FD);
	if (!msg
	    || !fromwire_hsmd_get_per_commitment_point_reply(tmpctx, msg,
							    per_commitment_point,
							    &unused))
		status_failed(STATUS_FAIL_HSM_IO,
			      "Reading hsm_get_per_commitment_point_reply: %s",
			      tal_hex(tmpctx, msg));
}

static struct tracked_output *
new_tracked_output(struct tracked_output ***outs,
		   const struct bitcoin_outpoint *outpoint,
		   u32 tx_blockheight,
		   enum tx_type tx_type,
		   struct amount_sat sat,
		   enum output_type output_type,
		   const struct htlc_stub *htlc,
		   const u8 *wscript,
		   const struct bitcoin_signature *remote_htlc_sig TAKES)
{
	struct tracked_output *out = tal(*outs, struct tracked_output);

	status_debug("Tracking output %s: %s/%s",
		     type_to_string(tmpctx, struct bitcoin_outpoint, outpoint),
		     tx_type_name(tx_type),
		     output_type_name(output_type));

	out->tx_type = tx_type;
	out->outpoint = *outpoint;
	out->tx_blockheight = tx_blockheight;
	out->depth = 0;
	out->sat = sat;
	out->output_type = output_type;
	out->proposal = NULL;
	out->resolved = NULL;
	if (htlc)
		out->htlc = *htlc;
	out->wscript = tal_steal(out, wscript);
	out->remote_htlc_sig = tal_dup_or_null(out, struct bitcoin_signature,
					       remote_htlc_sig);

	tal_arr_expand(outs, out);

	return out;
}

static void ignore_output(struct tracked_output *out)
{
	status_debug("Ignoring output %s: %s/%s",
		     type_to_string(tmpctx, struct bitcoin_outpoint,
				    &out->outpoint),
		     tx_type_name(out->tx_type),
		     output_type_name(out->output_type));

	out->resolved = tal(out, struct resolution);
	out->resolved->txid = out->outpoint.txid;
	out->resolved->depth = 0;
	out->resolved->tx_type = SELF;
}

static enum wallet_tx_type onchain_txtype_to_wallet_txtype(enum tx_type t)
{
	switch (t) {
	case FUNDING_TRANSACTION:
		return TX_CHANNEL_FUNDING;
	case MUTUAL_CLOSE:
		return TX_CHANNEL_CLOSE;
	case OUR_UNILATERAL:
		return TX_CHANNEL_UNILATERAL;
	case THEIR_HTLC_FULFILL_TO_US:
	case OUR_HTLC_SUCCESS_TX:
		return TX_CHANNEL_HTLC_SUCCESS;
	case OUR_HTLC_TIMEOUT_TO_US:
	case OUR_HTLC_TIMEOUT_TX:
		return TX_CHANNEL_HTLC_TIMEOUT;
	case OUR_DELAYED_RETURN_TO_WALLET:
	case SELF:
		return TX_CHANNEL_SWEEP;
	case OUR_PENALTY_TX:
		return TX_CHANNEL_PENALTY;
	case THEIR_DELAYED_CHEAT:
		return TX_CHANNEL_CHEAT | TX_THEIRS;
	case THEIR_UNILATERAL:
	case UNKNOWN_UNILATERAL:
	case THEIR_REVOKED_UNILATERAL:
		return TX_CHANNEL_UNILATERAL | TX_THEIRS;
	case THEIR_HTLC_TIMEOUT_TO_THEM:
		return TX_CHANNEL_HTLC_TIMEOUT | TX_THEIRS;
	case OUR_HTLC_FULFILL_TO_THEM:
		return TX_CHANNEL_HTLC_SUCCESS | TX_THEIRS;
	case IGNORING_TINY_PAYMENT:
	case UNKNOWN_TXTYPE:
		return TX_UNKNOWN;
	}
	abort();
}

/** proposal_is_rbfable
 *
 * @brief returns true if the given proposal
 * would be RBFed if the output it is tracking
 * increases in depth without being spent.
 */
static bool proposal_is_rbfable(const struct proposed_resolution *proposal)
{
	/* Future onchain resolutions, such as anchored commitments, might
	 * want to RBF as well.
	 */
	return proposal->tx_type == OUR_PENALTY_TX;
}

/** proposal_should_rbf
 *
 * @brief the given output just increased its depth,
 * so the proposal for it should be RBFed and
 * rebroadcast.
 *
 * @desc precondition: the given output must have an
 * rbfable proposal as per `proposal_is_rbfable`.
 */
static void proposal_should_rbf(struct tracked_output *out)
{
	struct bitcoin_tx *tx = NULL;
	u32 depth;

	assert(out->proposal);
	assert(proposal_is_rbfable(out->proposal));

	depth = out->depth;

	/* Do not RBF at depth 1.
	 *
	 * Since we react to *onchain* events, whatever proposal we made,
	 * the output for that proposal is already at depth 1.
	 *
	 * Since our initial proposal was broadcasted with the output at
	 * depth 1, we should not RBF until a new block arrives, which is
	 * at depth 2.
	 */
	if (depth <= 1)
		return;

	if (out->proposal->tx_type == OUR_PENALTY_TX) {
		u32 max_depth = to_self_delay[REMOTE];
		u32 my_depth = depth;
		size_t weight = bitcoin_tx_weight(out->proposal->tx);
		struct amount_sat initial_amount;
		struct amount_sat new_amount;

		if (max_depth >= 1)
			max_depth -= 1;
		if (my_depth >= max_depth)
			my_depth = max_depth;

		bitcoin_tx_output_get_amount_sat(out->proposal->tx, 0,
						 &initial_amount);

		/* Compute the new output amount for the RBF.  */
		new_amount = compute_penalty_output_amount(initial_amount,
							   my_depth, max_depth,
							   weight);
		assert(amount_sat_less_eq(new_amount, initial_amount));
		/* Recreate the penalty tx.  */
		tx = replace_penalty_tx_to_us(tmpctx,
					      &penalty_to_us,
					      out->proposal->tx, &new_amount);

		/* We also update the output's value, so our accounting
		 * is correct. */
		out->sat = new_amount;

		status_debug("Created RBF OUR_PENALTY_TX with output %s "
			     "(originally %s) for depth %"PRIu32"/%"PRIu32".",
			     type_to_string(tmpctx, struct amount_sat,
					    &new_amount),
			     type_to_string(tmpctx, struct amount_sat,
					    &initial_amount),
			     depth, to_self_delay[LOCAL]);
	}
	/* Add other RBF-able proposals here.  */

	/* Broadcast the transaction.  */
	if (tx) {
		enum wallet_tx_type wtt;

		status_debug("Broadcasting RBF %s (%s) to resolve %s/%s "
			     "depth=%"PRIu32"",
			     tx_type_name(out->proposal->tx_type),
			     type_to_string(tmpctx, struct bitcoin_tx, tx),
			     tx_type_name(out->tx_type),
			     output_type_name(out->output_type),
			     depth);

		wtt = onchain_txtype_to_wallet_txtype(out->proposal->tx_type);
		wire_sync_write(REQ_FD,
				take(towire_onchaind_broadcast_tx(NULL, tx,
								 wtt,
								 true)));
	}
}

static void proposal_meets_depth(struct tracked_output *out)
{
	bool is_rbf = false;

	/* If we simply wanted to ignore it after some depth */
	if (!out->proposal->tx) {
		ignore_output(out);

		if (out->proposal->tx_type == THEIR_HTLC_TIMEOUT_TO_THEM)
			record_external_deposit(out, out->tx_blockheight,
						HTLC_TIMEOUT);

		return;
	}

	status_debug("Broadcasting %s (%s) to resolve %s/%s",
		     tx_type_name(out->proposal->tx_type),
		     type_to_string(tmpctx, struct bitcoin_tx, out->proposal->tx),
		     tx_type_name(out->tx_type),
		     output_type_name(out->output_type));

	if (out->proposal)
		/* Our own penalty transactions are going to be RBFed.  */
		is_rbf = proposal_is_rbfable(out->proposal);

	wire_sync_write(
	    REQ_FD,
	    take(towire_onchaind_broadcast_tx(
		 NULL, out->proposal->tx,
		 onchain_txtype_to_wallet_txtype(out->proposal->tx_type),
		 is_rbf)));

	/* Don't wait for this if we're ignoring the tiny payment. */
	if (out->proposal->tx_type == IGNORING_TINY_PAYMENT) {
		ignore_output(out);
		record_ignored_wallet_deposit(out);
	}

	/* Otherwise we will get a callback when it's in a block. */
}

static void propose_resolution(struct tracked_output *out,
			       const struct bitcoin_tx *tx,
			       unsigned int depth_required,
			       enum tx_type tx_type)
{
	status_debug("Propose handling %s/%s by %s (%s) after %u blocks",
		     tx_type_name(out->tx_type),
		     output_type_name(out->output_type),
		     tx_type_name(tx_type),
		     tx ? type_to_string(tmpctx, struct bitcoin_tx, tx):"IGNORING",
		     depth_required);

	out->proposal = tal(out, struct proposed_resolution);
	out->proposal->tx = tal_steal(out->proposal, tx);
	out->proposal->depth_required = depth_required;
	out->proposal->tx_type = tx_type;

	if (depth_required == 0)
		proposal_meets_depth(out);
}

static void propose_resolution_at_block(struct tracked_output *out,
					const struct bitcoin_tx *tx,
					unsigned int block_required,
					enum tx_type tx_type)
{
	u32 depth;

	/* Expiry could be in the past! */
	if (block_required < out->tx_blockheight)
		depth = 0;
	else /* Note that out->tx_blockheight is already at depth 1 */
		depth = block_required - out->tx_blockheight + 1;
	propose_resolution(out, tx, depth, tx_type);
}

static bool is_valid_sig(const u8 *e)
{
	struct bitcoin_signature sig;
	return signature_from_der(e, tal_count(e), &sig);
}

/* We ignore things which look like signatures. */
static bool input_similar(const struct wally_tx_input *i1,
			  const struct wally_tx_input *i2)
{
	u8 *s1, *s2;

	if (!memeq(i1->txhash, WALLY_TXHASH_LEN, i2->txhash, WALLY_TXHASH_LEN))
		return false;

	if (i1->index != i2->index)
		return false;

	if (!scripteq(i1->script, i2->script))
		return false;

	if (i1->sequence != i2->sequence)
		return false;

	if (i1->witness->num_items != i2->witness->num_items)
		return false;

	for (size_t i = 0; i < i1->witness->num_items; i++) {
		/* Need to wrap these in `tal_arr`s since the primitives
		 * except to be able to call tal_bytelen on them */
		s1 = tal_dup_arr(tmpctx, u8, i1->witness->items[i].witness,
				 i1->witness->items[i].witness_len, 0);
		s2 = tal_dup_arr(tmpctx, u8, i2->witness->items[i].witness,
				 i2->witness->items[i].witness_len, 0);

		if (scripteq(s1, s2))
			continue;

		if (is_valid_sig(s1) && is_valid_sig(s2))
			continue;
		return false;
	}

	return true;
}

/* This simple case: true if this was resolved by our proposal. */
static bool resolved_by_proposal(struct tracked_output *out,
				 const struct tx_parts *tx_parts)
{
	/* If there's no TX associated, it's not us. */
	if (!out->proposal->tx)
		return false;

	/* Our proposal can change as feerates change.  Input
	 * comparison (ignoring signatures) works pretty well. */
	if (tal_count(tx_parts->inputs) != out->proposal->tx->wtx->num_inputs)
		return false;

	for (size_t i = 0; i < tal_count(tx_parts->inputs); i++) {
		if (!input_similar(tx_parts->inputs[i],
				   &out->proposal->tx->wtx->inputs[i]))
			return false;
	}

	out->resolved = tal(out, struct resolution);
	out->resolved->txid = tx_parts->txid;
	status_debug("Resolved %s/%s by our proposal %s (%s)",
		     tx_type_name(out->tx_type),
		     output_type_name(out->output_type),
		     tx_type_name(out->proposal->tx_type),
		     type_to_string(tmpctx, struct bitcoin_txid,
				    &out->resolved->txid));

	out->resolved->depth = 0;
	out->resolved->tx_type = out->proposal->tx_type;
	return true;
}

/* Otherwise, we figure out what happened and then call this. */
static void resolved_by_other(struct tracked_output *out,
			      const struct bitcoin_txid *txid,
			      enum tx_type tx_type)
{
	out->resolved = tal(out, struct resolution);
	out->resolved->txid = *txid;
	out->resolved->depth = 0;
	out->resolved->tx_type = tx_type;

	status_debug("Resolved %s/%s by %s (%s)",
		     tx_type_name(out->tx_type),
		     output_type_name(out->output_type),
		     tx_type_name(tx_type),
		     type_to_string(tmpctx, struct bitcoin_txid, txid));
}

static void unknown_spend(struct tracked_output *out,
			  const struct tx_parts *tx_parts)
{
	out->resolved = tal(out, struct resolution);
	out->resolved->txid = tx_parts->txid;
	out->resolved->depth = 0;
	out->resolved->tx_type = UNKNOWN_TXTYPE;

	status_broken("Unknown spend of %s/%s by %s",
		     tx_type_name(out->tx_type),
		     output_type_name(out->output_type),
		     type_to_string(tmpctx, struct bitcoin_txid,
				    &tx_parts->txid));
}

static u64 unmask_commit_number(const struct tx_parts *tx,
				uint32_t locktime,
				enum side opener,
				const struct pubkey *local_payment_basepoint,
				const struct pubkey *remote_payment_basepoint)
{
	u64 obscurer;
	const struct pubkey *keys[NUM_SIDES];
	keys[LOCAL] = local_payment_basepoint;
	keys[REMOTE] = remote_payment_basepoint;

	/* BOLT #3:
	 *
	 * The 48-bit commitment number is obscured by `XOR` with the lower 48 bits of...
	 */
	obscurer = commit_number_obscurer(keys[opener], keys[!opener]);

	/* BOLT #3:
	 *
	 * * locktime: upper 8 bits are 0x20, lower 24 bits are the lower 24 bits of the obscured commitment number
	 *...
	 * * `txin[0]` sequence: upper 8 bits are 0x80, lower 24 bits are upper 24 bits of the obscured commitment number
	 */
	return ((locktime & 0x00FFFFFF)
		| (tx->inputs[0]->sequence & (u64)0x00FFFFFF) << 24)
		^ obscurer;
}

static bool is_mutual_close(const struct tx_parts *tx,
			    const u8 *local_scriptpubkey,
			    const u8 *remote_scriptpubkey)
{
	size_t i;
	bool local_matched = false, remote_matched = false;

	for (i = 0; i < tal_count(tx->outputs); i++) {
		/* To be paranoid, we only let each one match once. */
		if (chainparams->is_elements &&
		    tx->outputs[i]->script_len == 0) {
			/* This is a fee output, ignore please */
			continue;
		} else if (wally_tx_output_scripteq(tx->outputs[i],
						    local_scriptpubkey)
			   && !local_matched) {
			local_matched = true;
		} else if (wally_tx_output_scripteq(tx->outputs[i],
						    remote_scriptpubkey)
			   && !remote_matched)
			remote_matched = true;
		else
			return false;
	}

	return true;
}

/* We only ever send out one, so matching it is easy. */
static bool is_local_commitment(const struct bitcoin_txid *txid,
				const struct bitcoin_txid *our_broadcast_txid)
{
	return bitcoin_txid_eq(txid, our_broadcast_txid);
}

/* BOLT #5:
 *
 * Outputs that are *resolved* are considered *irrevocably resolved*
 * once the remote's *resolving* transaction is included in a block at least 100
 * deep, on the most-work blockchain.
 */
static size_t num_not_irrevocably_resolved(struct tracked_output **outs)
{
	size_t i, num = 0;

	for (i = 0; i < tal_count(outs); i++) {
		if (!outs[i]->resolved || outs[i]->resolved->depth < 100)
			num++;
	}
	return num;
}

static u32 prop_blockheight(const struct tracked_output *out)
{
	return out->tx_blockheight + out->proposal->depth_required;
}

static void billboard_update(struct tracked_output **outs)
{
	const struct tracked_output *best = NULL;

	/* Highest priority is to report on proposals we have */
	for (size_t i = 0; i < tal_count(outs); i++) {
		if (!outs[i]->proposal || outs[i]->resolved)
			continue;
		if (!best || prop_blockheight(outs[i]) < prop_blockheight(best))
			best = outs[i];
	}

	if (best) {
		/* If we've broadcast and not seen yet, this happens */
		if (best->proposal->depth_required <= best->depth) {
			peer_billboard(false,
				       "%u outputs unresolved: waiting confirmation that we spent %s (%s) using %s",
				       num_not_irrevocably_resolved(outs),
				       output_type_name(best->output_type),
				       type_to_string(tmpctx,
						      struct bitcoin_outpoint,
						      &best->outpoint),
				       tx_type_name(best->proposal->tx_type));
		} else {
			peer_billboard(false,
				       "%u outputs unresolved: in %u blocks will spend %s (%s) using %s",
				       num_not_irrevocably_resolved(outs),
				       best->proposal->depth_required - best->depth,
				       output_type_name(best->output_type),
				       type_to_string(tmpctx,
						      struct bitcoin_outpoint,
						      &best->outpoint),
				       tx_type_name(best->proposal->tx_type));
		}
		return;
	}

	/* Now, just report on the last thing we're waiting out. */
	for (size_t i = 0; i < tal_count(outs); i++) {
		/* FIXME: Can this happen?  No proposal, no resolution? */
		if (!outs[i]->resolved)
			continue;
		if (!best || outs[i]->resolved->depth < best->resolved->depth)
			best = outs[i];
	}

	if (best) {
		peer_billboard(false,
			       "All outputs resolved:"
			       " waiting %u more blocks before forgetting"
			       " channel",
			       best->resolved->depth < 100
			       ? 100 - best->resolved->depth : 0);
		return;
	}

	/* Not sure this can happen, but take last one (there must be one!) */
	best = outs[tal_count(outs)-1];
	peer_billboard(false, "%u outputs unresolved: %s is one (depth %u)",
		       num_not_irrevocably_resolved(outs),
		       output_type_name(best->output_type), best->depth);
}

static void unwatch_txid(const struct bitcoin_txid *txid)
{
	u8 *msg;

	msg = towire_onchaind_unwatch_tx(NULL, txid);
	wire_sync_write(REQ_FD, take(msg));
}

static void handle_htlc_onchain_fulfill(struct tracked_output *out,
					const struct tx_parts *tx_parts,
					const struct bitcoin_outpoint *htlc_outpoint)
{
	const struct wally_tx_witness_item *preimage_item;
	struct preimage preimage;
	struct sha256 sha;
	struct ripemd160 ripemd;

	/* Our HTLC, they filled (must be an HTLC-success tx). */
	if (out->tx_type == THEIR_UNILATERAL
		|| out->tx_type == THEIR_REVOKED_UNILATERAL) {
		/* BOLT #3:
		 *
		 * ## HTLC-Timeout and HTLC-Success Transactions
		 *
		 * ...  `txin[0]` witness stack: `0 <remotehtlcsig> <localhtlcsig>
		 * <payment_preimage>` for HTLC-success
		 */
		if (tx_parts->inputs[htlc_outpoint->n]->witness->num_items != 5) /* +1 for wscript */
			status_failed(STATUS_FAIL_INTERNAL_ERROR,
				      "%s/%s spent with weird witness %zu",
				      tx_type_name(out->tx_type),
				      output_type_name(out->output_type),
				      tx_parts->inputs[htlc_outpoint->n]->witness->num_items);

		preimage_item = &tx_parts->inputs[htlc_outpoint->n]->witness->items[3];
	} else if (out->tx_type == OUR_UNILATERAL) {
		/* BOLT #3:
		 *
		 * The remote node can redeem the HTLC with the witness:
		 *
		 *    <remotehtlcsig> <payment_preimage>
		 */
		if (tx_parts->inputs[htlc_outpoint->n]->witness->num_items != 3) /* +1 for wscript */
			status_failed(STATUS_FAIL_INTERNAL_ERROR,
				      "%s/%s spent with weird witness %zu",
				      tx_type_name(out->tx_type),
				      output_type_name(out->output_type),
				      tx_parts->inputs[htlc_outpoint->n]->witness->num_items);

		preimage_item = &tx_parts->inputs[htlc_outpoint->n]->witness->items[1];
	} else
		status_failed(STATUS_FAIL_INTERNAL_ERROR,
			      "onchain_fulfill for %s/%s?",
			      tx_type_name(out->tx_type),
			      output_type_name(out->output_type));

	/* cppcheck-suppress uninitvar - doesn't know status_failed exits? */
	if (preimage_item->witness_len != sizeof(preimage)) {
		/* It's possible something terrible happened and we broadcast
		 * an old commitment state, which they're now cleaning up.
		 *
		 * We stumble along.
		 */
		if (out->tx_type == OUR_UNILATERAL
		    && preimage_item->witness_len == PUBKEY_CMPR_LEN) {
			status_unusual("Our cheat attempt failed, they're "
				       "taking our htlc out (%s)",
				       type_to_string(tmpctx, struct amount_sat,
						      &out->sat));
			return;
		}
		status_failed(STATUS_FAIL_INTERNAL_ERROR,
			      "%s/%s spent with bad witness length %zu",
			      tx_type_name(out->tx_type),
			      output_type_name(out->output_type),
			      preimage_item->witness_len);
	}
	memcpy(&preimage, preimage_item->witness, sizeof(preimage));
	sha256(&sha, &preimage, sizeof(preimage));
	ripemd160(&ripemd, &sha, sizeof(sha));

	if (!ripemd160_eq(&ripemd, &out->htlc.ripemd))
		status_failed(STATUS_FAIL_INTERNAL_ERROR,
			      "%s/%s spent with bad preimage %s (ripemd not %s)",
			      tx_type_name(out->tx_type),
			      output_type_name(out->output_type),
			      type_to_string(tmpctx, struct preimage, &preimage),
			      type_to_string(tmpctx, struct ripemd160,
					     &out->htlc.ripemd));

	/* we stash the payment_hash into the tracking_output so we
	 * can pass it along, if needbe, to the coin movement tracker */
	out->payment_hash = sha;

	/* Tell master we found a preimage. */
	status_debug("%s/%s gave us preimage %s",
		     tx_type_name(out->tx_type),
		     output_type_name(out->output_type),
		     type_to_string(tmpctx, struct preimage, &preimage));
	wire_sync_write(REQ_FD,
			take(towire_onchaind_extracted_preimage(NULL,
							       &preimage)));
}

static void resolve_htlc_tx(struct tracked_output ***outs,
			    size_t out_index,
			    const struct tx_parts *htlc_tx,
			    size_t input_num,
			    u32 tx_blockheight)
{
	struct tracked_output *out;
	struct bitcoin_tx *tx;
	struct amount_sat amt;
	struct amount_asset asset;
	struct bitcoin_outpoint outpoint;
	enum tx_type tx_type = OUR_DELAYED_RETURN_TO_WALLET;
	u8 *wscript = bitcoin_wscript_htlc_tx(htlc_tx, to_self_delay[LOCAL],
					      &keyset->self_revocation_key,
					      &keyset->self_delayed_payment_key);


	/* BOLT #5:
	 *
	 *       - SHOULD resolve the HTLC-timeout transaction by spending it to
	 *         a convenient address...
	 *       - MUST wait until the `OP_CHECKSEQUENCEVERIFY` delay has passed
	 *         (as specified by the remote node's `open_channel`
	 *         `to_self_delay` field) before spending that HTLC-timeout
	 *         output.
	 */
	outpoint.txid = htlc_tx->txid;
	outpoint.n = input_num;

	asset = wally_tx_output_get_amount(htlc_tx->outputs[outpoint.n]);
	assert(amount_asset_is_main(&asset));
	amt = amount_asset_to_sat(&asset);
	out = new_tracked_output(outs, &outpoint,
 				 tx_blockheight,
 				 (*outs)[out_index]->resolved->tx_type,
				 amt,
 				 DELAYED_OUTPUT_TO_US,
 				 NULL, NULL, NULL);

	/* BOLT #3:
	 *
	 * ## HTLC-Timeout and HTLC-Success Transactions
	 *
	 * These HTLC transactions are almost identical, except the
	 * HTLC-timeout transaction is timelocked.
	 *
	 * ... to collect the output, the local node uses an input with
	 * nSequence `to_self_delay` and a witness stack `<local_delayedsig>
	 * 0`
	 */
	tx = tx_to_us(*outs, delayed_payment_to_us, out, to_self_delay[LOCAL],
		      0, NULL, 0, wscript, &tx_type, htlc_feerate);

	propose_resolution(out, tx, to_self_delay[LOCAL], tx_type);
}

/* BOLT #5:
 *
 *   - MUST *resolve* the _remote node's HTLC-timeout transaction_ by spending it
 *     using the revocation private key.
 *   - MUST *resolve* the _remote node's HTLC-success transaction_ by spending it
 *     using the revocation private key.
 */
static void steal_htlc_tx(struct tracked_output *out,
			  struct tracked_output ***outs,
			  const struct tx_parts *htlc_tx,
			  u32 htlc_tx_blockheight,
			  enum tx_type htlc_tx_type,
			  const struct bitcoin_outpoint *htlc_outpoint)
{
	struct bitcoin_tx *tx;
	enum tx_type tx_type = OUR_PENALTY_TX;
	struct tracked_output *htlc_out;
	struct amount_asset asset;
	struct amount_sat htlc_out_amt;

	u8 *wscript = bitcoin_wscript_htlc_tx(htlc_tx, to_self_delay[REMOTE],
					      &keyset->self_revocation_key,
					      &keyset->self_delayed_payment_key);

	asset = wally_tx_output_get_amount(htlc_tx->outputs[htlc_outpoint->n]);
	assert(amount_asset_is_main(&asset));
	htlc_out_amt = amount_asset_to_sat(&asset);

	htlc_out = new_tracked_output(outs,
				      htlc_outpoint, htlc_tx_blockheight,
				      htlc_tx_type,
				      htlc_out_amt,
				      DELAYED_CHEAT_OUTPUT_TO_THEM,
				      &out->htlc, wscript, NULL);
	/* BOLT #3:
	 *
	 * To spend this via penalty, the remote node uses a witness stack
	 * `<revocationsig> 1`
	 */
	tx = tx_to_us(htlc_out, penalty_to_us, htlc_out,
		      BITCOIN_TX_RBF_SEQUENCE, 0,
		      &ONE, sizeof(ONE),
		      htlc_out->wscript,
		      &tx_type, penalty_feerate);

	/* mark commitment tx htlc output as 'resolved by them' */
	resolved_by_other(out, &htlc_tx->txid, htlc_tx_type);

	/* annnd done! */
	propose_resolution(htlc_out, tx, 0, tx_type);
}

static void onchain_annotate_txout(const struct bitcoin_outpoint *outpoint,
				   enum wallet_tx_type type)
{
	wire_sync_write(REQ_FD, take(towire_onchaind_annotate_txout(
				    tmpctx, outpoint, type)));
}

static void onchain_annotate_txin(const struct bitcoin_txid *txid, u32 innum,
				  enum wallet_tx_type type)
{
	wire_sync_write(REQ_FD, take(towire_onchaind_annotate_txin(
				    tmpctx, txid, innum, type)));
}

/* An output has been spent: see if it resolves something we care about. */
static void output_spent(struct tracked_output ***outs,
			 const struct tx_parts *tx_parts,
			 u32 input_num,
			 u32 tx_blockheight)
{
	for (size_t i = 0; i < tal_count(*outs); i++) {
		struct tracked_output *out = (*outs)[i];
		struct bitcoin_outpoint htlc_outpoint;

		if (out->resolved)
			continue;

		if (!wally_tx_input_spends(tx_parts->inputs[input_num],
					   &out->outpoint))
			continue;

		/* Was this our resolution? */
		if (resolved_by_proposal(out, tx_parts)) {
			/* If it's our htlc tx, we need to resolve that, too. */
			if (out->resolved->tx_type == OUR_HTLC_SUCCESS_TX
			    || out->resolved->tx_type == OUR_HTLC_TIMEOUT_TX)
				resolve_htlc_tx(outs, i, tx_parts, input_num,
						tx_blockheight);

			record_coin_movements(out, tx_blockheight,
					      out->proposal->tx,
					      &tx_parts->txid);
			return;
		}

		htlc_outpoint.txid = tx_parts->txid;
		htlc_outpoint.n = input_num;

		switch (out->output_type) {
		case OUTPUT_TO_US:
		case DELAYED_OUTPUT_TO_US:
			unknown_spend(out, tx_parts);
			record_external_deposit(out, tx_blockheight, PENALIZED);
			break;

		case THEIR_HTLC:
			record_external_deposit(out, out->tx_blockheight,
						HTLC_TIMEOUT);
			record_external_spend(&tx_parts->txid, out,
					      tx_blockheight, HTLC_TIMEOUT);

			if (out->tx_type == THEIR_REVOKED_UNILATERAL) {
				/* we've actually got a 'new' output here */
				steal_htlc_tx(out, outs, tx_parts,
					      tx_blockheight,
					      THEIR_HTLC_TIMEOUT_TO_THEM,
					      &htlc_outpoint);
			} else {
				/* We ignore this timeout tx, since we should
				 * resolve by ignoring once we reach depth. */
				onchain_annotate_txout(
				    &htlc_outpoint,
				    TX_CHANNEL_HTLC_TIMEOUT | TX_THEIRS);
			}
			break;

		case OUR_HTLC:
			/* The only way	they can spend this: fulfill; even
			 * if it's revoked: */
			/* BOLT #5:
			 *
			 * ## HTLC Output Handling: Local Commitment, Local Offers
			 *...
			 *    - MUST extract the payment preimage from the
			 *      transaction input witness.
			 *...
			 * ## HTLC Output Handling: Remote Commitment, Local Offers
			 *...
			 *     - MUST extract the payment preimage from the
			 *       HTLC-success transaction input witness.
			 */
			handle_htlc_onchain_fulfill(out, tx_parts,
						    &htlc_outpoint);

			record_to_them_htlc_fulfilled(out, tx_blockheight);
			record_external_spend(&tx_parts->txid, out,
					      tx_blockheight, HTLC_FULFILL);

			if (out->tx_type == THEIR_REVOKED_UNILATERAL) {
				steal_htlc_tx(out, outs, tx_parts,
					      tx_blockheight,
					      OUR_HTLC_FULFILL_TO_THEM,
					      &htlc_outpoint);
			} else {
				/* BOLT #5:
				 *
				 * ## HTLC Output Handling: Local Commitment,
				 *    Local Offers
				 *...
				 *  - if the commitment transaction HTLC output
				 *    is spent using the payment preimage, the
				 *    output is considered *irrevocably resolved*
				 */
				ignore_output(out);

				onchain_annotate_txout(
				    &htlc_outpoint,
				    TX_CHANNEL_HTLC_SUCCESS | TX_THEIRS);
			}
			break;

		case FUNDING_OUTPUT:
			/* Master should be restarting us, as this implies
			 * that our old tx was unspent. */
			status_failed(STATUS_FAIL_INTERNAL_ERROR,
				      "Funding output spent again!");

		case DELAYED_CHEAT_OUTPUT_TO_THEM:
			/* They successfully spent a delayed revoked output */
			resolved_by_other(out, &tx_parts->txid,
					  THEIR_DELAYED_CHEAT);

			record_external_deposit(out, tx_blockheight, STOLEN);
			break;
		/* Um, we don't track these! */
		case OUTPUT_TO_THEM:
		case DELAYED_OUTPUT_TO_THEM:
		case ELEMENTS_FEE:
		case ANCHOR_TO_US:
		case ANCHOR_TO_THEM:
			status_failed(STATUS_FAIL_INTERNAL_ERROR,
				      "Tracked spend of %s/%s?",
				      tx_type_name(out->tx_type),
				      output_type_name(out->output_type));
		}
		return;
	}

	struct bitcoin_txid txid;
	wally_tx_input_get_txid(tx_parts->inputs[input_num], &txid);
	/* Not interesting to us, so unwatch the tx and all its outputs */
	status_debug("Notified about tx %s output %u spend, but we don't care",
		     type_to_string(tmpctx, struct bitcoin_txid, &txid),
		     tx_parts->inputs[input_num]->index);

	unwatch_txid(&tx_parts->txid);
}

static void update_resolution_depth(struct tracked_output *out, u32 depth)
{
	bool reached_reasonable_depth;

	status_debug("%s/%s->%s depth %u",
		     tx_type_name(out->tx_type),
		     output_type_name(out->output_type),
		     tx_type_name(out->resolved->tx_type),
		     depth);

	/* We only set this once. */
	reached_reasonable_depth = (out->resolved->depth < reasonable_depth
				    && depth >= reasonable_depth);

	/* BOLT #5:
	 *
	 *   - if the commitment transaction HTLC output has *timed out* and
	 *     hasn't been *resolved*:
	 *    - MUST *resolve* the output by spending it using the HTLC-timeout
	 *      transaction.
	 *    - once the resolving transaction has reached reasonable depth:
	 *      - MUST fail the corresponding incoming HTLC (if any).
	 */
	if ((out->resolved->tx_type == OUR_HTLC_TIMEOUT_TX
	     || out->resolved->tx_type == OUR_HTLC_TIMEOUT_TO_US)
	    && reached_reasonable_depth) {
		u8 *msg;
		status_debug("%s/%s reached reasonable depth %u",
			     tx_type_name(out->tx_type),
			     output_type_name(out->output_type),
			     depth);
		msg = towire_onchaind_htlc_timeout(out, &out->htlc);
		wire_sync_write(REQ_FD, take(msg));
	}
	out->resolved->depth = depth;
}

static void tx_new_depth(struct tracked_output **outs,
			 const struct bitcoin_txid *txid, u32 depth)
{
	size_t i;

	/* Special handling for commitment tx reaching depth */
	if (bitcoin_txid_eq(&outs[0]->resolved->txid, txid)
	    && depth >= reasonable_depth
	    && missing_htlc_msgs) {
		status_debug("Sending %zu missing htlc messages",
			     tal_count(missing_htlc_msgs));
		for (i = 0; i < tal_count(missing_htlc_msgs); i++)
			wire_sync_write(REQ_FD, missing_htlc_msgs[i]);
		/* Don't do it again. */
		missing_htlc_msgs = tal_free(missing_htlc_msgs);
	}

	for (i = 0; i < tal_count(outs); i++) {
		/* Update output depth. */
		if (bitcoin_txid_eq(&outs[i]->outpoint.txid, txid))
			outs[i]->depth = depth;

		/* Is this tx resolving an output? */
		if (outs[i]->resolved) {
			if (bitcoin_txid_eq(&outs[i]->resolved->txid, txid)) {
				update_resolution_depth(outs[i], depth);
			}
			continue;
		}

		/* Otherwise, is this something we have a pending
		 * resolution for? */
		if (outs[i]->proposal
		    && bitcoin_txid_eq(&outs[i]->outpoint.txid, txid)
		    && depth >= outs[i]->proposal->depth_required) {
			proposal_meets_depth(outs[i]);
		}

		/* Otherwise, is this an output whose proposed resolution
		 * we should RBF?  */
		if (outs[i]->proposal
		    && bitcoin_txid_eq(&outs[i]->outpoint.txid, txid)
		    && proposal_is_rbfable(outs[i]->proposal))
			proposal_should_rbf(outs[i]);
	}
}

/* BOLT #5:
 *
 * A local node:
 *   - if it receives (or already possesses) a payment preimage for an unresolved
 *   HTLC output that it has been offered AND for which it has committed to an
 *   outgoing HTLC:
 *     - MUST *resolve* the output by spending it, using the HTLC-success
 *     transaction.
 *     - MUST NOT reveal its own preimage when it's not the final recipient...
 *     - MUST resolve the output of that HTLC-success transaction.
 *   - otherwise:
 *     - if the *remote node* is NOT irrevocably committed to the HTLC:
 *       - MUST NOT *resolve* the output by spending it.
 *...
 * ## HTLC Output Handling: Remote Commitment, Remote Offers
 *...
 * A local node:
 *  - if it receives (or already possesses) a payment preimage for an unresolved
 *   HTLC output that it was offered AND for which it has committed to an
 * outgoing HTLC:
 *     - MUST *resolve* the output by spending it to a convenient address.
 *   - otherwise:
 *     - if the remote node is NOT irrevocably committed to the HTLC:
 *       - MUST NOT *resolve* the output by spending it.
 */
/* Master makes sure we only get told preimages once other node is committed. */
static void handle_preimage(struct tracked_output **outs,
			    const struct preimage *preimage)
{
	size_t i;
	struct sha256 sha;
	struct ripemd160 ripemd;
	u8 **witness;

	sha256(&sha, preimage, sizeof(*preimage));
	ripemd160(&ripemd, &sha, sizeof(sha));

	for (i = 0; i < tal_count(outs); i++) {
		struct bitcoin_tx *tx;
		struct bitcoin_signature sig;

		if (outs[i]->output_type != THEIR_HTLC)
			continue;

		if (!ripemd160_eq(&outs[i]->htlc.ripemd, &ripemd))
			continue;

		/* Too late? */
		if (outs[i]->resolved) {
			status_broken("HTLC already resolved by %s"
				     " when we found preimage",
				     tx_type_name(outs[i]->resolved->tx_type));
			return;
		}

		/* stash the payment_hash so we can track this coin movement */
		outs[i]->payment_hash = sha;

		/* Discard any previous resolution.  Could be a timeout,
		 * could be due to multiple identical rhashes in tx. */
		outs[i]->proposal = tal_free(outs[i]->proposal);

		/* BOLT #5:
		 *
		 *
		 * ## HTLC Output Handling: Local Commitment, Remote Offers
		 *...
		 * A local node:
		 *  - if it receives (or already possesses) a payment preimage
		 *    for an unresolved HTLC output that it has been offered
		 *    AND for which it has committed to an outgoing HTLC:
		 *    - MUST *resolve* the output by spending it, using the
		 *      HTLC-success transaction.
		 */
		if (outs[i]->remote_htlc_sig) {
			struct amount_msat htlc_amount;
			if (!amount_sat_to_msat(&htlc_amount, outs[i]->sat))
				status_failed(STATUS_FAIL_INTERNAL_ERROR,
					      "Overflow in output %zu %s",
					      i,
					      type_to_string(tmpctx,
							     struct amount_sat,
							     &outs[i]->sat));
			tx = htlc_success_tx(outs[i], chainparams,
					     &outs[i]->outpoint,
					     outs[i]->wscript,
					     htlc_amount,
					     to_self_delay[LOCAL],
					     0,
					     keyset, option_anchor_outputs);
			set_htlc_success_fee(tx, outs[i]->remote_htlc_sig,
					     outs[i]->wscript);
			hsm_sign_local_htlc_tx(tx, outs[i]->wscript, &sig);
			witness = bitcoin_witness_htlc_success_tx(
			    tx, &sig, outs[i]->remote_htlc_sig, preimage,
			    outs[i]->wscript);
			bitcoin_tx_input_set_witness(tx, 0, take(witness));
			propose_resolution(outs[i], tx, 0, OUR_HTLC_SUCCESS_TX);
		} else {
			enum tx_type tx_type = THEIR_HTLC_FULFILL_TO_US;

			/* BOLT #5:
			 *
			 * ## HTLC Output Handling: Remote Commitment, Remote
			 *    Offers
			 *...
			 * A local node:
			 * - if it receives (or already possesses) a payment
			 *   preimage for an unresolved HTLC output that it was
			 *   offered AND for which it has committed to an
			 *   outgoing HTLC:
			 *    - MUST *resolve* the output by spending it to a
			 *      convenient address.
			 */
			tx = tx_to_us(outs[i], remote_htlc_to_us, outs[i],
				      option_anchor_outputs ? 1 : 0,
				      0, preimage, sizeof(*preimage),
				      outs[i]->wscript, &tx_type,
				      htlc_feerate);
			propose_resolution(outs[i], tx, 0, tx_type);

		}
	}
}

#if DEVELOPER
static void memleak_remove_globals(struct htable *memtable, const tal_t *topctx)
{
	if (keyset)
		memleak_remove_region(memtable, keyset, sizeof(*keyset));
	memleak_remove_pointer(memtable, remote_per_commitment_point);
	memleak_remove_pointer(memtable, remote_per_commitment_secret);
	memleak_remove_pointer(memtable, topctx);
	memleak_remove_region(memtable,
			      missing_htlc_msgs, tal_bytelen(missing_htlc_msgs));
	memleak_remove_region(memtable,
			      queued_msgs, tal_bytelen(queued_msgs));
}

static bool handle_dev_memleak(struct tracked_output **outs, const u8 *msg)
{
	struct htable *memtable;
	bool found_leak;

	if (!fromwire_onchaind_dev_memleak(msg))
		return false;

	memtable = memleak_find_allocations(tmpctx, msg, msg);
	/* Top-level context is parent of outs */
	memleak_remove_globals(memtable, tal_parent(outs));
	memleak_remove_region(memtable, outs, tal_bytelen(outs));

	found_leak = dump_memleak(memtable, memleak_status_broken);
	wire_sync_write(REQ_FD,
			take(towire_onchaind_dev_memleak_reply(NULL,
							      found_leak)));
	return true;
}
#else
static bool handle_dev_memleak(struct tracked_output **outs, const u8 *msg)
{
	return false;
}
#endif /* !DEVELOPER */

/* BOLT #5:
 *
 * A node:
 *  - once it has broadcast a funding transaction OR sent a commitment signature
 *  for a commitment transaction that contains an HTLC output:
 *    - until all outputs are *irrevocably resolved*:
 *      - MUST monitor the blockchain for transactions that spend any output that
 *      is NOT *irrevocably resolved*.
 */
static void wait_for_resolved(struct tracked_output **outs)
{
	billboard_update(outs);

	while (num_not_irrevocably_resolved(outs) != 0) {
		u8 *msg;
		struct bitcoin_txid txid;
		u32 input_num, depth, tx_blockheight;
		struct preimage preimage;
		struct tx_parts *tx_parts;

		if (tal_count(queued_msgs)) {
			msg = tal_steal(outs, queued_msgs[0]);
			tal_arr_remove(&queued_msgs, 0);
		} else
			msg = wire_sync_read(outs, REQ_FD);

		status_debug("Got new message %s",
			     onchaind_wire_name(fromwire_peektype(msg)));

		if (fromwire_onchaind_depth(msg, &txid, &depth))
			tx_new_depth(outs, &txid, depth);
		else if (fromwire_onchaind_spent(msg, msg, &tx_parts, &input_num,
						&tx_blockheight)) {
			output_spent(&outs, tx_parts, input_num, tx_blockheight);
		} else if (fromwire_onchaind_known_preimage(msg, &preimage))
			handle_preimage(outs, &preimage);
		else if (!handle_dev_memleak(outs, msg))
			master_badmsg(-1, msg);

		billboard_update(outs);
		tal_free(msg);
		clean_tmpctx();
	}

	wire_sync_write(REQ_FD,
			take(towire_onchaind_all_irrevocably_resolved(outs)));
}

static int cmp_htlc_cltv(const struct htlc_stub *a,
			 const struct htlc_stub *b, void *unused)
{
	if (a->cltv_expiry < b->cltv_expiry)
		return -1;
	else if (a->cltv_expiry > b->cltv_expiry)
		return 1;
	return 0;
}

struct htlcs_info {
	struct htlc_stub *htlcs;
	bool *tell_if_missing;
	bool *tell_immediately;
};

static struct htlcs_info *init_reply(const tal_t *ctx, const char *what)
{
	struct htlcs_info *htlcs_info = tal(ctx, struct htlcs_info);
	u8 *msg;

	/* commit_num is 0 for mutual close, but we don't care about HTLCs
	 * then anyway. */

	/* Send init_reply first, so billboard gets credited to ONCHAIND */
	wire_sync_write(REQ_FD,
			take(towire_onchaind_init_reply(NULL, commit_num)));

	peer_billboard(true, what);

	/* Read in htlcs */
	for (;;) {
		msg = wire_sync_read(queued_msgs, REQ_FD);
		if (fromwire_onchaind_htlcs(htlcs_info, msg,
					    &htlcs_info->htlcs,
					    &htlcs_info->tell_if_missing,
					    &htlcs_info->tell_immediately)) {
			tal_free(msg);
			break;
		}

		/* Process later */
		tal_arr_expand(&queued_msgs, msg);
	}

	/* We want htlcs to be a valid tal parent, so make it a zero-length
	 * array if NULL (fromwire makes it NULL if there are no entries) */
	if (!htlcs_info->htlcs)
		htlcs_info->htlcs = tal_arr(htlcs_info, struct htlc_stub, 0);

	/* Sort by CLTV, so matches are in CLTV order (and easy to skip dups) */
	asort(htlcs_info->htlcs, tal_count(htlcs_info->htlcs),
	      cmp_htlc_cltv, NULL);

	return htlcs_info;
}

static void handle_mutual_close(struct tracked_output **outs,
				const struct tx_parts *tx)
{
	/* In this case, we don't care about htlcs: there are none. */
	init_reply(tmpctx, "Tracking mutual close transaction");

	/* Annotate the first input as close. We can currently only have a
	 * single input for these. */
	onchain_annotate_txin(&tx->txid, 0, TX_CHANNEL_CLOSE);

	/* BOLT #5:
	 *
	 * A closing transaction *resolves* the funding transaction output.
	 *
	 * In the case of a mutual close, a node need not do anything else, as it has
	 * already agreed to the output, which is sent to its specified `scriptpubkey`
	 */
	resolved_by_other(outs[0], &tx->txid, MUTUAL_CLOSE);
	wait_for_resolved(outs);
}

static u8 **derive_htlc_scripts(const struct htlc_stub *htlcs, enum side side)
{
	size_t i;
	u8 **htlc_scripts = tal_arr(htlcs, u8 *, tal_count(htlcs));

	for (i = 0; i < tal_count(htlcs); i++) {
		if (htlcs[i].owner == side)
			htlc_scripts[i] = htlc_offered_wscript(htlc_scripts,
							       &htlcs[i].ripemd,
							       keyset,
							       option_anchor_outputs);
		else {
			/* FIXME: remove abs_locktime */
			struct abs_locktime ltime;
			if (!blocks_to_abs_locktime(htlcs[i].cltv_expiry,
						    &ltime))
				status_failed(STATUS_FAIL_INTERNAL_ERROR,
					      "Could not convert cltv_expiry %u to locktime",
					      htlcs[i].cltv_expiry);
			htlc_scripts[i] = htlc_received_wscript(htlc_scripts,
								&htlcs[i].ripemd,
								&ltime,
								keyset,
								option_anchor_outputs);
		}
	}
	return htlc_scripts;
}

static size_t resolve_our_htlc_ourcommit(struct tracked_output *out,
					 const size_t *matches,
					 const struct htlc_stub *htlcs,
					 u8 **htlc_scripts)
{
	struct bitcoin_tx *tx = NULL;
	struct bitcoin_signature localsig;
	size_t i;
	struct amount_msat htlc_amount;
	u8 **witness;

	if (!amount_sat_to_msat(&htlc_amount, out->sat))
		status_failed(STATUS_FAIL_INTERNAL_ERROR,
			      "Overflow in our_htlc output %s",
			      type_to_string(tmpctx, struct amount_sat,
					     &out->sat));

	assert(tal_count(matches));

	/* These htlcs are all possibilities, but signature will only match
	 * one with the correct cltv: check which that is. */
	for (i = 0; i < tal_count(matches); i++) {
		/* Skip over duplicate HTLCs, since we only need one. */
		if (i > 0
		    && (htlcs[matches[i]].cltv_expiry
			== htlcs[matches[i-1]].cltv_expiry))
			continue;

		/* BOLT #5:
		 *
		 * ## HTLC Output Handling: Local Commitment, Local Offers
		 * ...
		 *  - if the commitment transaction HTLC output has *timed out*
		 *  and hasn't been *resolved*:
		 *    - MUST *resolve* the output by spending it using the
		 *    HTLC-timeout transaction.
		 */
		tx = htlc_timeout_tx(tmpctx, chainparams,
				     &out->outpoint,
				     htlc_scripts[matches[i]], htlc_amount,
				     htlcs[matches[i]].cltv_expiry,
				     to_self_delay[LOCAL], 0, keyset,
				     option_anchor_outputs);

		if (set_htlc_timeout_fee(tx, out->remote_htlc_sig,
					 htlc_scripts[matches[i]]))
			break;
	}

	/* Since there's been trouble with this before, we go to some length
	 * to give details here! */
	if (i == tal_count(matches)) {
		char *cltvs, *wscripts;

		cltvs = tal_fmt(tmpctx, "%u", htlcs[matches[0]].cltv_expiry);
		wscripts = tal_hex(tmpctx, htlc_scripts[matches[0]]);

		for (i = 1; i < tal_count(matches); i++) {
			tal_append_fmt(&cltvs, "/%u",
				       htlcs[matches[i]].cltv_expiry);
			tal_append_fmt(&wscripts, "/%s",
				       tal_hex(tmpctx, htlc_scripts[matches[i]]));
		}

		status_failed(STATUS_FAIL_INTERNAL_ERROR,
			      "No valid signature found for %zu htlc_timeout_txs"
			      " feerate %u-%u,"
			      " last tx %s, input %s, signature %s,"
			      " cltvs %s wscripts %s"
			      " %s",
			      tal_count(matches),
			      min_possible_feerate, max_possible_feerate,
			      type_to_string(tmpctx, struct bitcoin_tx, tx),
			      type_to_string(tmpctx, struct amount_sat,
					     &out->sat),
			      type_to_string(tmpctx, struct bitcoin_signature,
					     out->remote_htlc_sig),
			      cltvs, wscripts,
			      option_anchor_outputs
			      ? "option_anchor_outputs" : "");
	}

	hsm_sign_local_htlc_tx(tx, htlc_scripts[matches[i]], &localsig);

	witness = bitcoin_witness_htlc_timeout_tx(tx, &localsig,
						  out->remote_htlc_sig,
						  htlc_scripts[matches[i]]);

	bitcoin_tx_input_set_witness(tx, 0, take(witness));

	/* Steals tx onto out */
	propose_resolution_at_block(out, tx, htlcs[matches[i]].cltv_expiry,
				    OUR_HTLC_TIMEOUT_TX);

	return matches[i];
}

/* wscript for *received* htlcs (ie. our htlcs in their commit tx, or their
 * htlcs in our commit tx) includes cltv, so they must be the same for all
 * matching htlcs.  Unless, of course, they've found a sha256 clash. */
static u32 matches_cltv(const size_t *matches,
			const struct htlc_stub *htlcs)
{
	for (size_t i = 1; i < tal_count(matches); i++) {
		assert(matches[i] < tal_count(htlcs));
		assert(htlcs[matches[i]].cltv_expiry
		       == htlcs[matches[i-1]].cltv_expiry);
	}
	return htlcs[matches[0]].cltv_expiry;
}

static size_t resolve_our_htlc_theircommit(struct tracked_output *out,
					   const size_t *matches,
					   const struct htlc_stub *htlcs,
					   u8 **htlc_scripts)
{
	struct bitcoin_tx *tx;
	enum tx_type tx_type = OUR_HTLC_TIMEOUT_TO_US;
	u32 cltv_expiry = matches_cltv(matches, htlcs);

	/* BOLT #5:
	 *
	 * ## HTLC Output Handling: Remote Commitment, Local Offers
	 * ...
	 *
	 *   - if the commitment transaction HTLC output has *timed out* AND NOT
	 *     been *resolved*:
	 *     - MUST *resolve* the output, by spending it to a convenient
	 *       address.
	 */
	tx = tx_to_us(out, remote_htlc_to_us, out,
		      option_anchor_outputs ? 1 : 0,
		      cltv_expiry, NULL, 0,
		      htlc_scripts[matches[0]], &tx_type, htlc_feerate);

	propose_resolution_at_block(out, tx, cltv_expiry, tx_type);

	/* They're all equivalent: might as well use first one. */
	return matches[0];
}

/* Returns which htlcs it chose to use of matches[] */
static size_t resolve_their_htlc(struct tracked_output *out,
				 const size_t *matches,
				 const struct htlc_stub *htlcs,
				 u8 **htlc_scripts)
{
	size_t which_htlc;

	/* BOLT #5:
	 *
	 * ## HTLC Output Handling: Remote Commitment, Remote Offers
	 *...
	 * ### Requirements
	 *...
	 * If not otherwise resolved, once the HTLC output has expired, it is
	 * considered *irrevocably resolved*.
	 */

	/* BOLT #5:
	 *
	 * ## HTLC Output Handling: Local Commitment, Remote Offers
	 *...
	 * ### Requirements
	 *...
	 * If not otherwise resolved, once the HTLC output has expired, it is
	 * considered *irrevocably resolved*.
	 */

	/* The two cases are identical as far as default handling goes.
	 * But in the remote commitment / remote offer (ie. caller is
	 * handle_their_unilateral), htlcs which match may have different cltvs.
	 * So wait until the worst case (largest HTLC). */
	assert(tal_count(matches));
	which_htlc = matches[0];
	for (size_t i = 1; i < tal_count(matches); i++) {
		if (htlcs[matches[i]].cltv_expiry > htlcs[which_htlc].cltv_expiry)
			which_htlc = matches[i];
	}

	/* If we hit timeout depth, resolve by ignoring. */
	propose_resolution_at_block(out, NULL, htlcs[which_htlc].cltv_expiry,
				    THEIR_HTLC_TIMEOUT_TO_THEM);
	return which_htlc;
}

/* Return tal_arr of htlc indexes. */
static const size_t *match_htlc_output(const tal_t *ctx,
				       const struct wally_tx_output *out,
				       u8 **htlc_scripts)
{
	size_t *matches = tal_arr(ctx, size_t, 0);
	const u8 *script = tal_dup_arr(tmpctx, u8, out->script, out->script_len,
				       0);
	/* Must be a p2wsh output */
	if (!is_p2wsh(script, NULL))
		return matches;

	for (size_t i = 0; i < tal_count(htlc_scripts); i++) {
		struct sha256 sha;
		if (!htlc_scripts[i])
			continue;

		sha256(&sha, htlc_scripts[i], tal_count(htlc_scripts[i]));
		if (memeq(script + 2, tal_count(script) - 2, &sha, sizeof(sha)))
			tal_arr_expand(&matches, i);
	}
	return matches;
}

/* They must all be in the same direction, since the scripts are different for
 * each dir.  Unless, of course, they've found a sha256 clash. */
static enum side matches_direction(const size_t *matches,
				   const struct htlc_stub *htlcs)
{
	for (size_t i = 1; i < tal_count(matches); i++) {
		assert(matches[i] < tal_count(htlcs));
		assert(htlcs[matches[i]].owner == htlcs[matches[i-1]].owner);
	}
	return htlcs[matches[0]].owner;
}

/* Tell master about any we didn't use, if it wants to know. */
static void note_missing_htlcs(u8 **htlc_scripts,
			       const struct htlcs_info *htlcs_info)
{
	for (size_t i = 0; i < tal_count(htlcs_info->htlcs); i++) {
		u8 *msg;

		/* Used. */
		if (!htlc_scripts[i])
			continue;

		/* Doesn't care. */
		if (!htlcs_info->tell_if_missing[i])
			continue;

		msg = towire_onchaind_missing_htlc_output(missing_htlc_msgs,
							  &htlcs_info->htlcs[i]);
		if (htlcs_info->tell_immediately[i])
			wire_sync_write(REQ_FD, take(msg));
		else
			tal_arr_expand(&missing_htlc_msgs, msg);
	}
}

static void get_anchor_scriptpubkeys(const tal_t *ctx, u8 **anchor)
{
	if (!option_anchor_outputs) {
		anchor[LOCAL] = anchor[REMOTE] = NULL;
		return;
	}

	for (enum side side = 0; side < NUM_SIDES; side++) {
		u8 *wscript = bitcoin_wscript_anchor(tmpctx,
						     &funding_pubkey[side]);
		anchor[side] = scriptpubkey_p2wsh(ctx, wscript);
	}
}

static u8 *scriptpubkey_to_remote(const tal_t *ctx,
				  const struct pubkey *remotekey,
				  u32 csv_lock)
{
	/* BOLT #3:
	 *
	 * #### `to_remote` Output
	 *
	 * If `option_anchors` applies to the commitment
	 * transaction, the `to_remote` output is encumbered by a one
	 * block csv lock.
	 *    <remote_pubkey> OP_CHECKSIGVERIFY 1 OP_CHECKSEQUENCEVERIFY
	 *
	 *...
	 * Otherwise, this output is a simple P2WPKH to `remotepubkey`.
	 */
	if (option_anchor_outputs) {
		return scriptpubkey_p2wsh(ctx,
					  anchor_to_remote_redeem(tmpctx,
								  remotekey,
								  csv_lock));
	} else {
		return scriptpubkey_p2wpkh(ctx, remotekey);
	}
}

static void our_unilateral_to_us(struct tracked_output ***outs,
				 const struct bitcoin_outpoint *outpoint,
				 u32 tx_blockheight,
				 struct amount_sat amt,
				 u16 sequence,
				 const u8 *local_scriptpubkey,
				 const u8 *local_wscript)
{
	struct bitcoin_tx *to_us;
	struct tracked_output *out;
	enum tx_type tx_type = OUR_DELAYED_RETURN_TO_WALLET;

	/* BOLT #5:
	 *
	 * A node:
	 *   - upon discovering its *local commitment
	 *   transaction*:
	 *     - SHOULD spend the `to_local` output to a
	 *       convenient address.
	 *     - MUST wait until the `OP_CHECKSEQUENCEVERIFY`
	 *       delay has passed (as specified by the remote
	 *       node's `to_self_delay` field) before spending
	 *       the output.
	 */
	out = new_tracked_output(outs, outpoint, tx_blockheight,
				 OUR_UNILATERAL,
				 amt,
				 DELAYED_OUTPUT_TO_US,
				 NULL, NULL, NULL);
	/* BOLT #3:
	 *
	 * The output is spent by an input with
	 * `nSequence` field set to `to_self_delay` (which can
	 * only be valid after that duration has passed) and
	 * witness:
	 *
	 *	<local_delayedsig> <>
	 */
	to_us = tx_to_us(out, delayed_payment_to_us, out,
			 sequence, 0, NULL, 0,
			 local_wscript, &tx_type,
			 delayed_to_us_feerate);

	/* BOLT #5:
	 *
	 * Note: if the output is spent (as recommended), the
	 * output is *resolved* by the spending transaction
	 */
	propose_resolution(out, to_us, sequence, tx_type);
}

static void handle_our_unilateral(const struct tx_parts *tx,
				  u32 tx_blockheight,
				  const struct basepoints basepoints[NUM_SIDES],
				  const enum side opener,
				  const struct bitcoin_signature *remote_htlc_sigs,
				  struct tracked_output **outs)
{
	u8 **htlc_scripts;
	u8 *local_wscript, *script[NUM_SIDES], *anchor[NUM_SIDES];
	struct pubkey local_per_commitment_point;
	struct keyset *ks;
	size_t i;
	struct htlcs_info *htlcs_info;

	htlcs_info = init_reply(tx, "Tracking our own unilateral close");
	onchain_annotate_txin(&tx->txid, 0, TX_CHANNEL_UNILATERAL);

	/* BOLT #5:
	 *
	 * In this case, a node discovers its *local commitment transaction*,
	 * which *resolves* the funding transaction output.
	 */
	resolved_by_other(outs[0], &tx->txid, OUR_UNILATERAL);

	/* Figure out what delayed to-us output looks like */
	hsm_get_per_commitment_point(&local_per_commitment_point);

	/* keyset is const, we need a non-const ptr to set it up */
	keyset = ks = tal(tx, struct keyset);
	if (!derive_keyset(&local_per_commitment_point,
			   &basepoints[LOCAL],
			   &basepoints[REMOTE],
			   commit_num >= static_remotekey_start[LOCAL],
			   ks))
		status_failed(STATUS_FAIL_INTERNAL_ERROR,
			      "Deriving keyset for %"PRIu64, commit_num);

	status_debug("Deconstructing unilateral tx: %"PRIu64
		     " using keyset: "
		     " self_revocation_key: %s"
		     " self_delayed_payment_key: %s"
		     " self_payment_key: %s"
		     " other_payment_key: %s"
		     " self_htlc_key: %s"
		     " other_htlc_key: %s",
		     commit_num,
		     type_to_string(tmpctx, struct pubkey,
				    &keyset->self_revocation_key),
		     type_to_string(tmpctx, struct pubkey,
				    &keyset->self_delayed_payment_key),
		     type_to_string(tmpctx, struct pubkey,
				    &keyset->self_payment_key),
		     type_to_string(tmpctx, struct pubkey,
				    &keyset->other_payment_key),
		     type_to_string(tmpctx, struct pubkey,
				    &keyset->self_htlc_key),
		     type_to_string(tmpctx, struct pubkey,
				    &keyset->other_htlc_key));

	local_wscript = to_self_wscript(tmpctx, to_self_delay[LOCAL],
					1, keyset);

	/* Figure out what to-us output looks like. */
	script[LOCAL] = scriptpubkey_p2wsh(tmpctx, local_wscript);

	/* Figure out what direct to-them output looks like. */
	script[REMOTE] = scriptpubkey_to_remote(tmpctx,
						&keyset->other_payment_key, 1);

	/* Calculate all the HTLC scripts so we can match them */
	htlc_scripts = derive_htlc_scripts(htlcs_info->htlcs, LOCAL);

	status_debug("Script to-me: %u: %s (%s)",
		     to_self_delay[LOCAL],
		     tal_hex(tmpctx, script[LOCAL]),
		     tal_hex(tmpctx, local_wscript));
	status_debug("Script to-them: %s",
		     tal_hex(tmpctx, script[REMOTE]));

	for (i = 0; i < tal_count(tx->outputs); i++) {
		if (tx->outputs[i]->script == NULL)
			continue;
		status_debug("Output %zu: %s", i,
			     tal_hexstr(tmpctx, tx->outputs[i]->script,
					tx->outputs[i]->script_len));
	}

	get_anchor_scriptpubkeys(tmpctx, anchor);

	for (i = 0; i < tal_count(tx->outputs); i++) {
		struct tracked_output *out;
		const size_t *matches;
		size_t which_htlc;
		struct amount_asset asset = wally_tx_output_get_amount(tx->outputs[i]);
		struct amount_sat amt;
		struct bitcoin_outpoint outpoint;

		outpoint.txid = tx->txid;
		outpoint.n = i;

		assert(amount_asset_is_main(&asset));
		amt = amount_asset_to_sat(&asset);

		if (chainparams->is_elements
		    && tx->outputs[i]->script_len == 0) {
			status_debug("OUTPUT %zu is a fee output", i);
			/* An empty script simply means that that this is a
			 * fee output. */
			out = new_tracked_output(&outs,
						 &outpoint, tx_blockheight,
						 OUR_UNILATERAL,
						 amt,
						 ELEMENTS_FEE,
						 NULL, NULL, NULL);
			ignore_output(out);
			continue;
		} else if (script[LOCAL]
			   && wally_tx_output_scripteq(tx->outputs[i],
						       script[LOCAL])) {
			our_unilateral_to_us(&outs, &outpoint, tx_blockheight,
					     amt, to_self_delay[LOCAL],
					     script[LOCAL],
					     local_wscript);

			script[LOCAL] = NULL;
			continue;
		}
		if (script[REMOTE]
		    && wally_tx_output_scripteq(tx->outputs[i],
						script[REMOTE])) {
			/* BOLT #5:
			 *
			 *     - MAY ignore the `to_remote` output.
			 *       - Note: No action is required by the local
			 *       node, as `to_remote` is considered *resolved*
			 *       by the commitment transaction itself.
			 */
			out = new_tracked_output(&outs, &outpoint,
						 tx_blockheight,
						 OUR_UNILATERAL,
						 amt,
						 OUTPUT_TO_THEM,
						 NULL, NULL, NULL);
			ignore_output(out);
			record_external_deposit(out, tx_blockheight, TO_THEM);
			script[REMOTE] = NULL;
			continue;
		}
		if (anchor[LOCAL]
		    && wally_tx_output_scripteq(tx->outputs[i],
						anchor[LOCAL])) {
			/* FIXME: We should be able to spend this! */
			out = new_tracked_output(&outs, &outpoint,
						 tx_blockheight,
						 OUR_UNILATERAL,
						 amt,
						 ANCHOR_TO_US,
						 NULL, NULL, NULL);
			ignore_output(out);
			record_anchor(out);
			anchor[LOCAL] = NULL;
			continue;
		}
		if (anchor[REMOTE]
		    && wally_tx_output_scripteq(tx->outputs[i],
						anchor[REMOTE])) {
			out = new_tracked_output(&outs, &outpoint,
						 tx_blockheight,
						 OUR_UNILATERAL,
						 amt,
						 ANCHOR_TO_THEM,
						 NULL, NULL, NULL);
			ignore_output(out);
			record_external_deposit(out, tx_blockheight, ANCHOR);
			anchor[REMOTE] = NULL;
			continue;
		}

		matches = match_htlc_output(tmpctx, tx->outputs[i], htlc_scripts);
		/* FIXME: limp along when this happens! */
		if (tal_count(matches) == 0) {
			bool found = false;

			/* Maybe they're using option_will_fund? */
			if (opener == REMOTE && script[LOCAL]) {
				status_debug("Grinding for our to_local");
				/* We already tried `1` */
				for (size_t csv = 2;
				     csv <= LEASE_RATE_DURATION;
				     csv++) {

					local_wscript
						= to_self_wscript(tmpctx,
								  to_self_delay[LOCAL],
								  csv, keyset);

					script[LOCAL]
						= scriptpubkey_p2wsh(tmpctx,
								     local_wscript);
					if (!wally_tx_output_scripteq(
						       tx->outputs[i],
						       script[LOCAL]))
						continue;

					our_unilateral_to_us(&outs, &outpoint,
							     tx_blockheight,
							     amt,
							     max_unsigned(to_self_delay[LOCAL], csv),
							     script[LOCAL],
							     local_wscript);

					script[LOCAL] = NULL;
					found = true;
					break;
				}
			} else if (opener == LOCAL && script[REMOTE]) {
				status_debug("Grinding for to_remote (ours)");
				/* We already tried `1` */
				for (size_t csv = 2;
				     csv <= LEASE_RATE_DURATION;
				     csv++) {

					script[REMOTE]
						= scriptpubkey_to_remote(tmpctx,
								&keyset->other_payment_key,
								csv);

					if (!wally_tx_output_scripteq(tx->outputs[i], script[REMOTE]))
						continue;

					/* BOLT #5:
					 *
					 *     - MAY ignore the `to_remote` output.
					 *       - Note: No action is required by the local
					 *       node, as `to_remote` is considered *resolved*
					 *       by the commitment transaction itself.
					 */
					out = new_tracked_output(&outs,
								 &outpoint,
								 tx_blockheight,
								 OUR_UNILATERAL,
								 amt,
								 OUTPUT_TO_THEM,
								 NULL, NULL, NULL);
					ignore_output(out);
					record_external_deposit(out,
								tx_blockheight,
								TO_THEM);
					script[REMOTE] = NULL;
					found = true;
					break;
				}
			}


			if (found)
				continue;

			onchain_annotate_txout(&outpoint, TX_CHANNEL_PENALTY | TX_THEIRS);

			record_external_output(&outpoint, amt,
					       tx_blockheight,
					       PENALTY);
			status_failed(STATUS_FAIL_INTERNAL_ERROR,
				      "Could not find resolution for output %zu",
				      i);
		}

		if (matches_direction(matches, htlcs_info->htlcs) == LOCAL) {
			/* BOLT #5:
			 *
			 *     - MUST handle HTLCs offered by itself as specified
			 *       in [HTLC Output Handling: Local Commitment,
			 *       Local Offers]
			 */
			out = new_tracked_output(&outs, &outpoint,
						 tx_blockheight,
						 OUR_UNILATERAL,
						 amt,
						 OUR_HTLC,
						 NULL, NULL,
						 remote_htlc_sigs);
			/* Tells us which htlc to use */
			which_htlc = resolve_our_htlc_ourcommit(out, matches,
								htlcs_info->htlcs,
								htlc_scripts);
		} else {
			out = new_tracked_output(&outs, &outpoint,
						 tx_blockheight,
						 OUR_UNILATERAL,
						 amt,
						 THEIR_HTLC,
						 NULL, NULL,
						 remote_htlc_sigs);
			/* BOLT #5:
			 *
			 *     - MUST handle HTLCs offered by the remote node
			 *     as specified in [HTLC Output Handling: Local
			 *     Commitment, Remote Offers]
			 */
			/* Tells us which htlc to use */
			which_htlc = resolve_their_htlc(out, matches,
							htlcs_info->htlcs,
							htlc_scripts);
		}
		out->htlc = htlcs_info->htlcs[which_htlc];
		out->wscript = tal_steal(out, htlc_scripts[which_htlc]);

		/* Each of these consumes one HTLC signature */
		remote_htlc_sigs++;
		/* We've matched this HTLC, can't do again. */
		htlc_scripts[which_htlc] = NULL;

	}

	note_missing_htlcs(htlc_scripts, htlcs_info);
	tal_free(htlcs_info);

	wait_for_resolved(outs);
}

/* We produce individual penalty txs.  It's less efficient, but avoids them
 * using HTLC txs to block our penalties for long enough to pass the CSV
 * delay */
static void steal_to_them_output(struct tracked_output *out, u32 csv)
{
	u8 *wscript;
	struct bitcoin_tx *tx;
	enum tx_type tx_type = OUR_PENALTY_TX;

	/* BOLT #3:
	 *
	 * If a revoked commitment transaction is published, the other party
	 * can spend this output immediately with the following witness:
	 *
	 *    <revocation_sig> 1
	 */
	wscript = bitcoin_wscript_to_local(tmpctx, to_self_delay[REMOTE], csv,
					   &keyset->self_revocation_key,
					   &keyset->self_delayed_payment_key);

	tx = tx_to_us(tmpctx, penalty_to_us, out, BITCOIN_TX_RBF_SEQUENCE, 0,
		      &ONE, sizeof(ONE), wscript, &tx_type, penalty_feerate);

	propose_resolution(out, tx, 0, tx_type);
}

static void steal_htlc(struct tracked_output *out)
{
	struct bitcoin_tx *tx;
	enum tx_type tx_type = OUR_PENALTY_TX;
	u8 der[PUBKEY_CMPR_LEN];

	/* BOLT #3:
	 *
	 * If a revoked commitment transaction is published, the remote node can
	 * spend this output immediately with the following witness:
	 *
	 *     <revocation_sig> <revocationpubkey>
	 */
	pubkey_to_der(der, &keyset->self_revocation_key);
	tx = tx_to_us(out, penalty_to_us, out, BITCOIN_TX_RBF_SEQUENCE, 0,
		      der, sizeof(der), out->wscript, &tx_type,
		      penalty_feerate);

	propose_resolution(out, tx, 0, tx_type);
}

/* Tell wallet that we have discovered a UTXO from a to-remote output,
 * which it can spend with a little additional info we give here. */
static void tell_wallet_to_remote(const struct tx_parts *tx,
				  const struct bitcoin_outpoint *outpoint,
				  u32 tx_blockheight,
				  const u8 *scriptpubkey,
				  const struct pubkey *per_commit_point,
				  bool option_static_remotekey,
				  u32 csv_lock)
{
	struct amount_asset asset = wally_tx_output_get_amount(tx->outputs[outpoint->n]);
	struct amount_sat amt;

	assert(amount_asset_is_main(&asset));
	amt = amount_asset_to_sat(&asset);

	/* A NULL per_commit_point is how we indicate the pubkey doesn't need
	 * changing. */
	if (option_static_remotekey)
		per_commit_point = NULL;

	wire_sync_write(REQ_FD,
			take(towire_onchaind_add_utxo(NULL, outpoint,
						     per_commit_point,
						     amt,
						     tx_blockheight,
						     scriptpubkey,
						     csv_lock)));
}

static void their_unilateral_local(struct tracked_output ***outs,
				   const struct tx_parts *tx,
				   const struct bitcoin_outpoint *outpoint,
				   u32 tx_blockheight,
				   struct amount_sat amt,
				   const u8 *local_scriptpubkey,
				   enum tx_type tx_type,
				   u32 csv_lock)
{
	struct tracked_output *out;
	/* BOLT #5:
	 *
	 * - MAY take no action in regard to the associated
	 *   `to_remote`, which is simply a P2WPKH output to
	 *   the *local node*.
	 *   - Note: `to_remote` is considered *resolved* by the
	 *     commitment transaction itself.
	 */
	out = new_tracked_output(outs,
				 outpoint,
				 tx_blockheight,
				 tx_type,
				 amt,
				 OUTPUT_TO_US,
				 NULL, NULL,
				 NULL);
	ignore_output(out);

	tell_wallet_to_remote(tx, outpoint,
			      tx_blockheight,
			      local_scriptpubkey,
			      remote_per_commitment_point,
			      commit_num >= static_remotekey_start[REMOTE],
			      csv_lock);
}


/* BOLT #5:
 *
 * If any node tries to cheat by broadcasting an outdated commitment
 * transaction (any previous commitment transaction besides the most current
 * one), the other node in the channel can use its revocation private key to
 * claim all the funds from the channel's original funding transaction.
 */
static void handle_their_cheat(const struct tx_parts *tx,
			       u32 tx_blockheight,
			       const struct secret *revocation_preimage,
			       const struct basepoints basepoints[NUM_SIDES],
			       const enum side opener,
			       struct tracked_output **outs)
{
	u8 **htlc_scripts;
	u8 *remote_wscript, *script[NUM_SIDES], *anchor[NUM_SIDES];
	struct keyset *ks;
	struct pubkey *k;
	size_t i;
	struct htlcs_info *htlcs_info;

	htlcs_info = init_reply(tx,
				"Tracking their illegal close: taking all funds");
	onchain_annotate_txin(
	    &tx->txid, 0, TX_CHANNEL_UNILATERAL | TX_CHANNEL_CHEAT | TX_THEIRS);

	/* BOLT #5:
	 *
	 * Once a node discovers a commitment transaction for which *it* has a
	 * revocation private key, the funding transaction output is *resolved*.
	 */
	resolved_by_other(outs[0], &tx->txid, THEIR_REVOKED_UNILATERAL);

	/* FIXME: Types. */
	BUILD_ASSERT(sizeof(struct secret) == sizeof(*revocation_preimage));
	remote_per_commitment_secret = tal_dup(tx, struct secret,
					       (struct secret *)
					       revocation_preimage);

	/* Need tmpvar for non-const.  */
	remote_per_commitment_point = k = tal(tx, struct pubkey);
	if (!pubkey_from_secret(remote_per_commitment_secret, k))
		status_failed(STATUS_FAIL_INTERNAL_ERROR,
			      "Failed derive from per_commitment_secret %s",
			      type_to_string(tmpctx, struct secret,
					     remote_per_commitment_secret));

	status_debug("Deriving keyset %"PRIu64
		     ": per_commit_point=%s"
		     " self_payment_basepoint=%s"
		     " other_payment_basepoint=%s"
		     " self_htlc_basepoint=%s"
		     " other_htlc_basepoint=%s"
		     " self_delayed_basepoint=%s"
		     " other_revocation_basepoint=%s",
		     commit_num,
		     type_to_string(tmpctx, struct pubkey,
				    remote_per_commitment_point),
		     type_to_string(tmpctx, struct pubkey,
				    &basepoints[REMOTE].payment),
		     type_to_string(tmpctx, struct pubkey,
				    &basepoints[LOCAL].payment),
		     type_to_string(tmpctx, struct pubkey,
				    &basepoints[REMOTE].htlc),
		     type_to_string(tmpctx, struct pubkey,
				    &basepoints[LOCAL].htlc),
		     type_to_string(tmpctx, struct pubkey,
				    &basepoints[REMOTE].delayed_payment),
		     type_to_string(tmpctx, struct pubkey,
				    &basepoints[LOCAL].revocation));

	/* keyset is const, we need a non-const ptr to set it up */
	keyset = ks = tal(tx, struct keyset);
	if (!derive_keyset(remote_per_commitment_point,
			   &basepoints[REMOTE],
			   &basepoints[LOCAL],
			   commit_num >= static_remotekey_start[REMOTE],
			   ks))
		status_failed(STATUS_FAIL_INTERNAL_ERROR,
			      "Deriving keyset for %"PRIu64, commit_num);

	status_debug("Deconstructing revoked unilateral tx: %"PRIu64
		     " using keyset: "
		     " self_revocation_key: %s"
		     " self_delayed_payment_key: %s"
		     " self_payment_key: %s"
		     " other_payment_key: %s"
		     " self_htlc_key: %s"
		     " other_htlc_key: %s"
		     " (static_remotekey = %"PRIu64"/%"PRIu64")",
		     commit_num,
		     type_to_string(tmpctx, struct pubkey,
				    &keyset->self_revocation_key),
		     type_to_string(tmpctx, struct pubkey,
				    &keyset->self_delayed_payment_key),
		     type_to_string(tmpctx, struct pubkey,
				    &keyset->self_payment_key),
		     type_to_string(tmpctx, struct pubkey,
				    &keyset->other_payment_key),
		     type_to_string(tmpctx, struct pubkey,
				    &keyset->self_htlc_key),
		     type_to_string(tmpctx, struct pubkey,
				    &keyset->other_htlc_key),
		     static_remotekey_start[LOCAL],
		     static_remotekey_start[REMOTE]);

	remote_wscript = to_self_wscript(tmpctx, to_self_delay[REMOTE],
					 1, keyset);

	/* Figure out what to-them output looks like. */
	script[REMOTE] = scriptpubkey_p2wsh(tmpctx, remote_wscript);

	/* Figure out what direct to-us output looks like. */
	script[LOCAL] = scriptpubkey_to_remote(tmpctx,
					       &keyset->other_payment_key, 1);

	/* Calculate all the HTLC scripts so we can match them */
	htlc_scripts = derive_htlc_scripts(htlcs_info->htlcs, REMOTE);

	status_debug("Script to-them: %u: %s (%s)",
		     to_self_delay[REMOTE],
		     tal_hex(tmpctx, script[REMOTE]),
		     tal_hex(tmpctx, remote_wscript));
	status_debug("Script to-me: %s",
		     tal_hex(tmpctx, script[LOCAL]));

	get_anchor_scriptpubkeys(tmpctx, anchor);

	for (i = 0; i < tal_count(tx->outputs); i++) {
 		if (tx->outputs[i]->script_len == 0)
			continue;
		status_debug("Output %zu: %s",
			     i, tal_hexstr(tmpctx, tx->outputs[i]->script,
					   tx->outputs[i]->script_len));
	}

	for (i = 0; i < tal_count(tx->outputs); i++) {
		struct tracked_output *out;
		const size_t *matches;
		size_t which_htlc;
		struct amount_asset asset = wally_tx_output_get_amount(tx->outputs[i]);
		struct amount_sat amt;
		struct bitcoin_outpoint outpoint;

		outpoint.txid = tx->txid;
		outpoint.n = i;

		assert(amount_asset_is_main(&asset));
		amt = amount_asset_to_sat(&asset);

		if (chainparams->is_elements
		    && tx->outputs[i]->script_len == 0) {
			/* An empty script simply means that that this is a
			 * fee output. */
			out = new_tracked_output(&outs, &outpoint,
						 tx_blockheight,
						 THEIR_REVOKED_UNILATERAL,
						 amt,
						 ELEMENTS_FEE,
						 NULL, NULL, NULL);
			ignore_output(out);
			continue;
		}

		if (script[LOCAL]
		    && wally_tx_output_scripteq(tx->outputs[i],
						script[LOCAL])) {
			their_unilateral_local(&outs, tx, &outpoint,
					       tx_blockheight,
					       amt, script[LOCAL],
					       THEIR_REVOKED_UNILATERAL, 1);
			script[LOCAL] = NULL;
			continue;
		}
		if (script[REMOTE]
		    && wally_tx_output_scripteq(tx->outputs[i],
						script[REMOTE])) {
			/* BOLT #5:
			 *
			 *   - MUST *resolve* the _remote node's main output_ by
			 *     spending it using the revocation private key.
			*/
			out = new_tracked_output(&outs, &outpoint,
						 tx_blockheight,
						 THEIR_REVOKED_UNILATERAL,
						 amt,
						 DELAYED_CHEAT_OUTPUT_TO_THEM,
						 NULL, NULL, NULL);
			steal_to_them_output(out, 1);
			script[REMOTE] = NULL;
			continue;
		}
		if (anchor[LOCAL]
		    && wally_tx_output_scripteq(tx->outputs[i],
						anchor[LOCAL])) {
			/* FIXME: We should be able to spend this! */
			out = new_tracked_output(&outs, &outpoint,
						 tx_blockheight,
						 THEIR_REVOKED_UNILATERAL,
						 amt,
						 ANCHOR_TO_US,
						 NULL, NULL, NULL);
			ignore_output(out);
			record_anchor(out);
			anchor[LOCAL] = NULL;
			continue;
		}
		if (anchor[REMOTE]
		    && wally_tx_output_scripteq(tx->outputs[i],
						anchor[REMOTE])) {
			out = new_tracked_output(&outs, &outpoint,
						 tx_blockheight,
						 THEIR_REVOKED_UNILATERAL,
						 amt,
						 ANCHOR_TO_THEM,
						 NULL, NULL, NULL);
			ignore_output(out);
			record_external_deposit(out, tx_blockheight, ANCHOR);
			anchor[REMOTE] = NULL;
			continue;
		}

		matches = match_htlc_output(tmpctx, tx->outputs[i], htlc_scripts);
		if (tal_count(matches) == 0) {
			bool found = false;
			if (opener == REMOTE && script[LOCAL]) {
				status_debug("Grinding for commitment to_remote"
					     " (ours)");
				/* We already tried `1` */
				for (size_t csv = 2;
				     csv <= LEASE_RATE_DURATION;
				     csv++) {
					script[LOCAL]
						= scriptpubkey_to_remote(tmpctx,
								&keyset->other_payment_key,
								csv);
					if (!wally_tx_output_scripteq(
						       tx->outputs[i],
						       script[LOCAL]))
						continue;

					their_unilateral_local(&outs, tx,
							       &outpoint,
							       tx_blockheight,
							       amt,
							       script[LOCAL],
							       THEIR_REVOKED_UNILATERAL,
							       csv);
					script[LOCAL] = NULL;
					found = true;
					break;
				}
			} else if (opener == LOCAL && script[REMOTE]) {
				status_debug("Grinding for commitment to_local"
					     " (theirs)");
				for (size_t csv = 2;
				     csv <= LEASE_RATE_DURATION;
				     csv++) {
					remote_wscript
						= to_self_wscript(tmpctx,
								  to_self_delay[REMOTE],
								  csv, keyset);
					script[REMOTE]
						= scriptpubkey_p2wsh(tmpctx,
								remote_wscript);


					if (!wally_tx_output_scripteq(tx->outputs[i], script[REMOTE]))
						continue;

					out = new_tracked_output(&outs,
								 &outpoint,
								 tx_blockheight,
								 THEIR_REVOKED_UNILATERAL,
								 amt,
								 DELAYED_CHEAT_OUTPUT_TO_THEM,
								 NULL, NULL, NULL);
					steal_to_them_output(out, csv);
					script[REMOTE] = NULL;
					found = true;
					break;
				}
			}

			if (!found) {
				record_external_output(&outpoint, amt,
						       tx_blockheight,
						       PENALTY);
				status_broken("Could not find resolution"
					      " for output %zu: did"
					      " *we* cheat?", i);
			}
			continue;
		}

		/* In this case, we don't care which HTLC we choose; so pick
		   first one */
		which_htlc = matches[0];
		if (matches_direction(matches, htlcs_info->htlcs) == LOCAL) {
			/* BOLT #5:
			 *
			 *   - MUST *resolve* the _local node's offered HTLCs_ in one of three ways:
			 *     * spend the *commitment tx* using the payment revocation private key.
			 *     * spend the *commitment tx* once the HTLC timeout has passed.
			 *     * spend the *HTLC-success tx*, if the remote node has published it.
			 */
			out = new_tracked_output(&outs, &outpoint,
						 tx_blockheight,
						 THEIR_REVOKED_UNILATERAL,
						 amt,
						 OUR_HTLC,
						 &htlcs_info->htlcs[which_htlc],
						 htlc_scripts[which_htlc],
						 NULL);
			steal_htlc(out);
		} else {
			out = new_tracked_output(&outs, &outpoint,
						 tx_blockheight,
						 THEIR_REVOKED_UNILATERAL,
						 amt,
						 THEIR_HTLC,
						 &htlcs_info->htlcs[which_htlc],
						 htlc_scripts[which_htlc],
						 NULL);
			/* BOLT #5:
			 *
			 *   - MUST *resolve* the _remote node's offered HTLCs_ in one of three ways:
			 *     * spend the *commitment tx* using the payment revocation private key.
			 *     * spend the *commitment tx* using the payment preimage (if known).
			 *     * spend the *HTLC-timeout tx*, if the remote node has published it.
			 */
			steal_htlc(out);
		}
		htlc_scripts[which_htlc] = NULL;
	}

	note_missing_htlcs(htlc_scripts, htlcs_info);
	tal_free(htlcs_info);

	wait_for_resolved(outs);
}

static void handle_their_unilateral(const struct tx_parts *tx,
				    u32 tx_blockheight,
				    const struct pubkey *this_remote_per_commitment_point,
				    const struct basepoints basepoints[NUM_SIDES],
				    const enum side opener,
				    struct tracked_output **outs)
{
	u8 **htlc_scripts;
	u8 *remote_wscript, *script[NUM_SIDES], *anchor[NUM_SIDES];
	struct keyset *ks;
	size_t i;
	struct htlcs_info *htlcs_info;

	htlcs_info = init_reply(tx, "Tracking their unilateral close");
	onchain_annotate_txin(&tx->txid, 0, TX_CHANNEL_UNILATERAL | TX_THEIRS);

	/* HSM can't derive this. */
	remote_per_commitment_point = this_remote_per_commitment_point;

	/* BOLT #5:
	 *
	 * # Unilateral Close Handling: Remote Commitment Transaction
	 *
	 * The *remote node's* commitment transaction *resolves* the funding
	 * transaction output.
	 *
	 * There are no delays constraining node behavior in this case, so
	 * it's simpler for a node to handle than the case in which it
	 * discovers its local commitment transaction (see [Unilateral Close
	 * Handling: Local Commitment Transaction]
	 */
	resolved_by_other(outs[0], &tx->txid, THEIR_UNILATERAL);

	status_debug("Deriving keyset %"PRIu64
		     ": per_commit_point=%s"
		     " self_payment_basepoint=%s"
		     " other_payment_basepoint=%s"
		     " self_htlc_basepoint=%s"
		     " other_htlc_basepoint=%s"
		     " self_delayed_basepoint=%s"
		     " other_revocation_basepoint=%s",
		     commit_num,
		     type_to_string(tmpctx, struct pubkey,
				    remote_per_commitment_point),
		     type_to_string(tmpctx, struct pubkey,
				    &basepoints[REMOTE].payment),
		     type_to_string(tmpctx, struct pubkey,
				    &basepoints[LOCAL].payment),
		     type_to_string(tmpctx, struct pubkey,
				    &basepoints[REMOTE].htlc),
		     type_to_string(tmpctx, struct pubkey,
				    &basepoints[LOCAL].htlc),
		     type_to_string(tmpctx, struct pubkey,
				    &basepoints[REMOTE].delayed_payment),
		     type_to_string(tmpctx, struct pubkey,
				    &basepoints[LOCAL].revocation));

	/* keyset is const, we need a non-const ptr to set it up */
	keyset = ks = tal(tx, struct keyset);
	if (!derive_keyset(remote_per_commitment_point,
			   &basepoints[REMOTE],
			   &basepoints[LOCAL],
			   commit_num >= static_remotekey_start[REMOTE],
			   ks))
		status_failed(STATUS_FAIL_INTERNAL_ERROR,
			      "Deriving keyset for %"PRIu64, commit_num);

	status_debug("Deconstructing unilateral tx: %"PRIu64
		     " using keyset: "
		     " self_revocation_key: %s"
		     " self_delayed_payment_key: %s"
		     " self_payment_key: %s"
		     " other_payment_key: %s"
		     " self_htlc_key: %s"
		     " other_htlc_key: %s",
		     commit_num,
		     type_to_string(tmpctx, struct pubkey,
				    &keyset->self_revocation_key),
		     type_to_string(tmpctx, struct pubkey,
				    &keyset->self_delayed_payment_key),
		     type_to_string(tmpctx, struct pubkey,
				    &keyset->self_payment_key),
		     type_to_string(tmpctx, struct pubkey,
				    &keyset->other_payment_key),
		     type_to_string(tmpctx, struct pubkey,
				    &keyset->self_htlc_key),
		     type_to_string(tmpctx, struct pubkey,
				    &keyset->other_htlc_key));

	/* Calculate all the HTLC scripts so we can match them */
	htlc_scripts = derive_htlc_scripts(htlcs_info->htlcs, REMOTE);

	get_anchor_scriptpubkeys(tmpctx, anchor);

	for (i = 0; i < tal_count(tx->outputs); i++) {
 		if (tx->outputs[i]->script_len == 0)
			continue;
		status_debug("Output %zu: %s",
			     i, tal_hexstr(tmpctx, tx->outputs[i]->script,
					   tx->outputs[i]->script_len));
	}

	remote_wscript = to_self_wscript(tmpctx, to_self_delay[REMOTE],
					 1, keyset);
	script[REMOTE] = scriptpubkey_p2wsh(tmpctx, remote_wscript);

	script[LOCAL] = scriptpubkey_to_remote(tmpctx,
					       &keyset->other_payment_key,
					       1);

	status_debug("Script to-them: %u: %s (%s)",
		     to_self_delay[REMOTE],
		     tal_hex(tmpctx, script[REMOTE]),
		     tal_hex(tmpctx, remote_wscript));
	status_debug("Script to-me: %s",
		     tal_hex(tmpctx, script[LOCAL]));

	for (i = 0; i < tal_count(tx->outputs); i++) {
		struct tracked_output *out;
		const size_t *matches;
		size_t which_htlc;
		struct amount_asset asset = wally_tx_output_get_amount(tx->outputs[i]);
		struct amount_sat amt;
		struct bitcoin_outpoint outpoint;

		assert(amount_asset_is_main(&asset));
		amt = amount_asset_to_sat(&asset);

		outpoint.txid = tx->txid;
		outpoint.n = i;

		if (chainparams->is_elements &&
		    tx->outputs[i]->script_len == 0) {
			/* An empty script simply means that that this is a
			 * fee output. */
			out = new_tracked_output(&outs, &outpoint,
						 tx_blockheight,
						 THEIR_UNILATERAL,
						 amt,
						 ELEMENTS_FEE,
						 NULL, NULL, NULL);
			ignore_output(out);
			continue;
		} else if (script[LOCAL]
			   && wally_tx_output_scripteq(tx->outputs[i],
						       script[LOCAL])) {
			their_unilateral_local(&outs, tx, &outpoint,
					       tx_blockheight,
					       amt, script[LOCAL],
					       THEIR_UNILATERAL, 1);

			script[LOCAL] = NULL;
			continue;
		}
		if (script[REMOTE]
		    && wally_tx_output_scripteq(tx->outputs[i],
						script[REMOTE])) {
			/* BOLT #5:
			 *
			 * - MAY take no action in regard to the associated
			 *  `to_local`, which is a payment output to the *remote
			 *   node*.
			 *   - Note: `to_local` is considered *resolved* by the
			 *     commitment transaction itself.
			 */
			out = new_tracked_output(&outs, &outpoint,
						 tx_blockheight,
						 THEIR_UNILATERAL,
						 amt,
						 DELAYED_OUTPUT_TO_THEM,
						 NULL, NULL, NULL);
			ignore_output(out);
			record_external_deposit(out, tx_blockheight, TO_THEM);
			continue;
		}
		if (anchor[LOCAL]
		    && wally_tx_output_scripteq(tx->outputs[i],
						anchor[LOCAL])) {
			/* FIXME: We should be able to spend this! */
			out = new_tracked_output(&outs, &outpoint,
						 tx_blockheight,
						 THEIR_UNILATERAL,
						 amt,
						 ANCHOR_TO_US,
						 NULL, NULL, NULL);

			ignore_output(out);
			record_anchor(out);
			anchor[LOCAL] = NULL;
			continue;
		}
		if (anchor[REMOTE]
		    && wally_tx_output_scripteq(tx->outputs[i],
						anchor[REMOTE])) {
			out = new_tracked_output(&outs, &outpoint,
						 tx_blockheight,
						 THEIR_UNILATERAL,
						 amt,
						 ANCHOR_TO_THEM,
						 NULL, NULL, NULL);
			ignore_output(out);
			anchor[REMOTE] = NULL;
			record_external_deposit(out, tx_blockheight, ANCHOR);
			continue;
		}

		matches = match_htlc_output(tmpctx, tx->outputs[i], htlc_scripts);
		if (tal_count(matches) == 0) {
			bool found = false;

			/* We need to hunt for it (option_will_fund?) */
			if (opener == REMOTE && script[LOCAL]) {
				status_debug("Grinding for commitment to_remote"
					     " (ours)");
				/* We already tried `1` */
				for (size_t csv = 2;
				     csv <= LEASE_RATE_DURATION;
				     csv++) {
					script[LOCAL]
						= scriptpubkey_to_remote(tmpctx,
								&keyset->other_payment_key,
								csv);
					if (!wally_tx_output_scripteq(
						       tx->outputs[i],
						       script[LOCAL]))
						continue;

					their_unilateral_local(&outs, tx,
							       &outpoint,
							       tx_blockheight,
							       amt,
							       script[LOCAL],
							       THEIR_UNILATERAL,
							       csv);
					script[LOCAL] = NULL;
					found = true;
					break;
				}
			} else if (opener == LOCAL && script[REMOTE]) {
				status_debug("Grinding for commitment to_local"
					     " (theirs)");
				/* We already tried `1` */
				for (size_t csv = 2;
				     csv <= LEASE_RATE_DURATION;
				     csv++) {
					remote_wscript
						= to_self_wscript(tmpctx,
								  to_self_delay[REMOTE],
								  csv, keyset);
					script[REMOTE]
						= scriptpubkey_p2wsh(tmpctx,
								remote_wscript);


					if (!wally_tx_output_scripteq(tx->outputs[i], script[REMOTE]))
						continue;

					out = new_tracked_output(&outs,
								 &outpoint,
								 tx_blockheight,
								 THEIR_UNILATERAL,
								 amt,
								 DELAYED_OUTPUT_TO_THEM,
								 NULL, NULL, NULL);
					ignore_output(out);
					record_external_deposit(out,
								tx_blockheight,
								TO_THEM);
					found = true;
					break;
				}
			}

			if (found)
				continue;

			record_external_output(&outpoint, amt,
					       tx_blockheight,
					       PENALTY);
			status_failed(STATUS_FAIL_INTERNAL_ERROR,
				      "Could not find resolution for output %zu",
				      i);
		}

		if (matches_direction(matches, htlcs_info->htlcs) == LOCAL) {
			/* BOLT #5:
			 *
			 * - MUST handle HTLCs offered by itself as specified in
			 *   [HTLC Output Handling: Remote Commitment,
			 *   Local Offers]
			 */
			out = new_tracked_output(&outs, &outpoint,
						 tx_blockheight,
						 THEIR_UNILATERAL,
						 amt,
						 OUR_HTLC,
						 NULL, NULL,
						 NULL);
			which_htlc = resolve_our_htlc_theircommit(out,
								  matches,
								  htlcs_info->htlcs,
								  htlc_scripts);
		} else {
			out = new_tracked_output(&outs, &outpoint,
						 tx_blockheight,
						 THEIR_UNILATERAL,
						 amt,
						 THEIR_HTLC,
						 NULL, NULL,
						 NULL);
			/* BOLT #5:
			 *
			 * - MUST handle HTLCs offered by the remote node as
			 *   specified in [HTLC Output Handling: Remote
			 *   Commitment, Remote Offers]
			 */
			which_htlc = resolve_their_htlc(out, matches,
							htlcs_info->htlcs,
							htlc_scripts);
		}
		out->htlc = htlcs_info->htlcs[which_htlc];
		out->wscript = tal_steal(out, htlc_scripts[which_htlc]);
		htlc_scripts[which_htlc] = NULL;
	}

	note_missing_htlcs(htlc_scripts, htlcs_info);
	tal_free(htlcs_info);

	wait_for_resolved(outs);
}

static void handle_unknown_commitment(const struct tx_parts *tx,
				      u32 tx_blockheight,
				      const struct pubkey *possible_remote_per_commitment_point,
				      const struct basepoints basepoints[NUM_SIDES],
				      struct tracked_output **outs)
{
	int to_us_output = -1;
	/* We have two possible local scripts, depending on options */
	u8 *local_scripts[2];
	struct htlcs_info *htlcs_info;

	onchain_annotate_txin(&tx->txid, 0, TX_CHANNEL_UNILATERAL | TX_THEIRS);

	resolved_by_other(outs[0], &tx->txid, UNKNOWN_UNILATERAL);

	/* This is the not-option_static_remotekey case, if we got a hint
	 * from them about the per-commitment point */
	if (possible_remote_per_commitment_point) {
		struct keyset *ks = tal(tmpctx, struct keyset);
		if (!derive_keyset(possible_remote_per_commitment_point,
				   &basepoints[REMOTE],
				   &basepoints[LOCAL],
				   false,
				   ks))
			status_failed(STATUS_FAIL_INTERNAL_ERROR,
				      "Deriving keyset for possible_remote_per_commitment_point %s",
				      type_to_string(tmpctx, struct pubkey,
						     possible_remote_per_commitment_point));

		local_scripts[0] = scriptpubkey_p2wpkh(tmpctx,
						       &ks->other_payment_key);
	} else {
		local_scripts[0] = NULL;
	}

	/* For option_will_fund, we need to figure out what CSV lock was used */
	for (size_t csv = 1; csv <= LEASE_RATE_DURATION; csv++) {

		/* Other possible local script is for option_static_remotekey */
		local_scripts[1] = scriptpubkey_to_remote(tmpctx,
							  &basepoints[LOCAL].payment,
							  csv);

		for (size_t i = 0; i < tal_count(tx->outputs); i++) {
			struct tracked_output *out;
			struct amount_asset asset = wally_tx_output_get_amount(tx->outputs[i]);
			struct amount_sat amt;
			int which_script;
			struct bitcoin_outpoint outpoint;

			assert(amount_asset_is_main(&asset));
			amt = amount_asset_to_sat(&asset);

			outpoint.txid = tx->txid;
			outpoint.n = i;

			/* Elements can have empty output scripts (fee output) */
			if (local_scripts[0]
			    && wally_tx_output_scripteq(tx->outputs[i], local_scripts[0]))
				which_script = 0;
			else if (local_scripts[1]
				 && wally_tx_output_scripteq(tx->outputs[i],
							     local_scripts[1]))
				which_script = 1;
			else {
				/* Record every output on this tx as an
				 * external 'penalty' */
				record_external_output(&outpoint, amt,
						       tx_blockheight,
						       PENALTY);

				continue;
			}

			/* BOLT #5:
			 *
			 * - MAY take no action in regard to the associated
			 *   `to_remote`, which is simply a P2WPKH output to
			 *   the *local node*.
			 *   - Note: `to_remote` is considered *resolved* by the
			 *     commitment transaction itself.
			 */
			out = new_tracked_output(&outs, &outpoint,
						 tx_blockheight,
						 UNKNOWN_UNILATERAL,
						 amt,
						 OUTPUT_TO_US, NULL, NULL, NULL);
			ignore_output(out);

			tell_wallet_to_remote(tx, &outpoint,
					      tx_blockheight,
					      local_scripts[which_script],
					      possible_remote_per_commitment_point,
					      which_script == 1,
					      csv);
			local_scripts[0] = local_scripts[1] = NULL;
			to_us_output = i;
			/* Even though we're finished, we keep rolling
			 * so we log all the outputs */
		}
	}

	if (to_us_output == -1) {
		status_broken("FUNDS LOST.  Unknown commitment #%"PRIu64"!",
			      commit_num);
		htlcs_info = init_reply(tx, "ERROR: FUNDS LOST.  Unknown commitment!");
	} else {
		status_broken("ERROR: Unknown commitment #%"PRIu64
			      ", recovering our funds!",
			      commit_num);
		htlcs_info = init_reply(tx, "ERROR: Unknown commitment, recovering our funds!");
	}

	/* Tell master to give up on HTLCs immediately. */
	for (size_t i = 0; i < tal_count(htlcs_info->htlcs); i++) {
		u8 *msg;

		if (!htlcs_info->tell_if_missing[i])
			continue;

		msg = towire_onchaind_missing_htlc_output(NULL,
							  &htlcs_info->htlcs[i]);
		wire_sync_write(REQ_FD, take(msg));
	}

	tal_free(htlcs_info);
	wait_for_resolved(outs);
}

int main(int argc, char *argv[])
{
	setup_locale();

	const tal_t *ctx = tal(NULL, char);
	u8 *msg;
	struct pubkey remote_per_commit_point, old_remote_per_commit_point;
	enum side opener;
	struct basepoints basepoints[NUM_SIDES];
	struct shachain shachain;
	struct tx_parts *tx;
	struct tracked_output **outs;
	struct bitcoin_outpoint funding;
	struct bitcoin_txid our_broadcast_txid;
	struct bitcoin_signature *remote_htlc_sigs;
	struct amount_sat funding_sats;
	u8 *scriptpubkey[NUM_SIDES];
	u32 locktime, tx_blockheight;
	struct pubkey *possible_remote_per_commitment_point;

	subdaemon_setup(argc, argv);

	status_setup_sync(REQ_FD);

	missing_htlc_msgs = tal_arr(ctx, u8 *, 0);
	queued_msgs = tal_arr(ctx, u8 *, 0);

	msg = wire_sync_read(tmpctx, REQ_FD);
	if (!fromwire_onchaind_init(tmpctx, msg,
				   &shachain,
				   &chainparams,
				   &funding_sats,
				   &our_msat,
				   &old_remote_per_commit_point,
				   &remote_per_commit_point,
				   &to_self_delay[LOCAL],
				   &to_self_delay[REMOTE],
				   &delayed_to_us_feerate,
				   &htlc_feerate,
				   &penalty_feerate,
				   &dust_limit,
				   &our_broadcast_txid,
				   &scriptpubkey[LOCAL],
				   &scriptpubkey[REMOTE],
				   &our_wallet_pubkey,
				   &opener,
				   &basepoints[LOCAL],
				   &basepoints[REMOTE],
				   &tx,
				   &locktime,
				   &tx_blockheight,
				   &reasonable_depth,
				   &remote_htlc_sigs,
				   &min_possible_feerate,
				   &max_possible_feerate,
				   &possible_remote_per_commitment_point,
				   &funding_pubkey[LOCAL],
				   &funding_pubkey[REMOTE],
				   &static_remotekey_start[LOCAL],
				   &static_remotekey_start[REMOTE],
				   &option_anchor_outputs,
				   &min_relay_feerate)) {
		master_badmsg(WIRE_ONCHAIND_INIT, msg);
	}

	status_debug("delayed_to_us_feerate = %u, htlc_feerate = %u, "
		     "penalty_feerate = %u", delayed_to_us_feerate,
		     htlc_feerate, penalty_feerate);
	/* We need to keep tx around, but there's only one: not really a leak */
	tal_steal(ctx, notleak(tx));

	outs = tal_arr(ctx, struct tracked_output *, 0);
	wally_tx_input_get_txid(tx->inputs[0], &funding.txid);
	funding.n = tx->inputs[0]->index;
	new_tracked_output(&outs, &funding,
			   0, /* We don't care about funding blockheight */
			   FUNDING_TRANSACTION,
			   funding_sats,
			   FUNDING_OUTPUT, NULL, NULL, NULL);

	/* Record funding output spent */
	send_coin_mvt(take(new_coin_channel_close(NULL, &tx->txid,
						  &funding, tx_blockheight,
						  our_msat,
						  funding_sats)));

	status_debug("Remote per-commit point: %s",
		     type_to_string(tmpctx, struct pubkey,
				    &remote_per_commit_point));
	status_debug("Old remote per-commit point: %s",
		     type_to_string(tmpctx, struct pubkey,
				    &old_remote_per_commit_point));

	trim_maximum_feerate(funding_sats, tx);

	/* BOLT #5:
	 *
	 * There are three ways a channel can end:
	 *
	 * 1. The good way (*mutual close*): at some point the local and
	 * remote nodes agree to close the channel. They generate a *closing
	 * transaction* (which is similar to a commitment transaction, but
	 * without any pending payments) and publish it on the blockchain (see
	 * [BOLT #2: Channel Close](02-peer-protocol.md#channel-close)).
	 */
	if (is_mutual_close(tx, scriptpubkey[LOCAL], scriptpubkey[REMOTE]))
		handle_mutual_close(outs, tx);
	else {
		/* BOLT #5:
		 *
		 * 2. The bad way (*unilateral close*): something goes wrong,
		 *    possibly without evil intent on either side. Perhaps one
		 *    party crashed, for instance. One side publishes its
		 *    *latest commitment transaction*.
		 */
		struct secret revocation_preimage;
		commit_num = unmask_commit_number(tx, locktime, opener,
						  &basepoints[LOCAL].payment,
						  &basepoints[REMOTE].payment);

		status_debug("commitnum = %"PRIu64
			     ", revocations_received = %"PRIu64,
			     commit_num, revocations_received(&shachain));

		if (is_local_commitment(&tx->txid, &our_broadcast_txid))
			handle_our_unilateral(tx, tx_blockheight,
					      basepoints,
					      opener,
					      remote_htlc_sigs,
					      outs);
		/* BOLT #5:
		 *
		 * 3. The ugly way (*revoked transaction close*): one of the
		 * parties deliberately tries to cheat, by publishing an
		 * *outdated commitment transaction* (presumably, a prior
		 * version, which is more in its favor).
		 */
		else if (shachain_get_secret(&shachain, commit_num,
					     &revocation_preimage)) {
			handle_their_cheat(tx,
					   tx_blockheight,
					   &revocation_preimage,
					   basepoints,
					   opener,
					   outs);
		/* BOLT #5:
		 *
		 * There may be more than one valid, *unrevoked* commitment
		 * transaction after a signature has been received via
		 * `commitment_signed` and before the corresponding
		 * `revoke_and_ack`. As such, either commitment may serve as
		 * the *remote node's* commitment transaction; hence, the
		 * local node is required to handle both.
		 */
		} else if (commit_num == revocations_received(&shachain)) {
			status_debug("Their unilateral tx, old commit point");
			handle_their_unilateral(tx, tx_blockheight,
						&old_remote_per_commit_point,
						basepoints,
						opener,
						outs);
		} else if (commit_num == revocations_received(&shachain) + 1) {
			status_debug("Their unilateral tx, new commit point");
			handle_their_unilateral(tx, tx_blockheight,
						&remote_per_commit_point,
						basepoints,
						opener,
						outs);
		} else {
			handle_unknown_commitment(tx, tx_blockheight,
						  possible_remote_per_commitment_point,
						  basepoints,
						  outs);
		}
	}

	/* We're done! */
	tal_free(ctx);
	daemon_shutdown();

	return 0;
}
