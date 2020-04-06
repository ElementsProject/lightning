#include <bitcoin/feerate.h>
#include <bitcoin/script.h>
#include <ccan/crypto/shachain/shachain.h>
#include <ccan/mem/mem.h>
#include <ccan/tal/str/str.h>
#include <common/amount.h>
#include <common/derive_basepoints.h>
#include <common/htlc_tx.h>
#include <common/initial_commit_tx.h>
#include <common/key_derive.h>
#include <common/keyset.h>
#include <common/memleak.h>
#include <common/peer_billboard.h>
#include <common/status.h>
#include <common/subdaemon.h>
#include <common/type_to_string.h>
#include <common/utils.h>
#include <common/version.h>
#include <common/wallet.h>
#include <errno.h>
#include <hsmd/gen_hsm_wire.h>
#include <inttypes.h>
#include <lightningd/channel_state.h>
#include <onchaind/gen_onchain_wire.h>
#include <onchaind/onchain_types.h>
#include <stdio.h>
#include <unistd.h>
#include <wire/wire_sync.h>
  #include "gen_onchain_types_names.h"

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

/* Does option_static_remotekey apply to this commitment tx? */
bool option_static_remotekey;

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
	struct bitcoin_txid txid;
	u32 tx_blockheight;
	/* FIXME: Convert all depths to blocknums, then just get new blk msgs */
	u32 depth;
	u32 outnum;
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

	const struct chainparams *chainparams;
};

/* We vary feerate until signature they offered matches. */
static bool grind_htlc_tx_fee(struct amount_sat *fee,
			      struct bitcoin_tx *tx,
			      const struct bitcoin_signature *remotesig,
			      const u8 *wscript,
			      u64 weight)
{
	struct amount_sat prev_fee = AMOUNT_SAT(UINT64_MAX);

	for (u64 i = min_possible_feerate; i <= max_possible_feerate; i++) {
		/* BOLT #3:
		 *
		 * The fee for an HTLC-timeout transaction:
		 *   - MUST BE calculated to match:
		 *     1. Multiply `feerate_per_kw` by 663 and divide by 1000
		 *     (rounding down).
		 *
		 * The fee for an HTLC-success transaction:
		 *   - MUST BE calculated to match:
		 *     1. Multiply `feerate_per_kw` by 703 and divide by 1000
		 *     (rounding down).
		 */
		struct amount_sat out;

		*fee = amount_tx_fee(i, weight);

		/* Minor optimization: don't check same fee twice */
		if (amount_sat_eq(*fee, prev_fee))
			continue;

		prev_fee = *fee;
		if (!amount_sat_sub(&out, *tx->input_amounts[0], *fee))
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
	size_t weight = elements_add_overhead(663, tx->wtx->num_inputs,
					      tx->wtx->num_outputs);

	assert(amount_asset_is_main(&asset));
	amount = amount_asset_to_sat(&asset);

	/* BOLT #3:
	 *
	 * The fee for an HTLC-timeout transaction:
	 *  - MUST BE calculated to match:
	 *    1. Multiply `feerate_per_kw` by 663 and divide by 1000 (rounding
	 *    down).
	 */
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
	size_t weight = elements_add_overhead(703, tx->wtx->num_inputs,
					      tx->wtx->num_outputs);
	/* BOLT #3:
	 *
	 * The fee for an HTLC-success transaction:
	 *  - MUST BE calculated to match:
	 *    1. Multiply `feerate_per_kw` by 703 and divide by 1000
	 *    (rounding down).
	 */
	if (amount_sat_eq(fee, AMOUNT_SAT(UINT64_MAX))) {
		if (!grind_htlc_tx_fee(&fee, tx, remotesig, wscript, weight))
			status_failed(STATUS_FAIL_INTERNAL_ERROR,
				      "htlc_success_fee can't be found "
				      " for tx %s, signature %s, wscript %s",
				      type_to_string(tmpctx, struct bitcoin_tx,
						     tx),
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

static u8 *delayed_payment_to_us(const tal_t *ctx,
				 struct bitcoin_tx *tx,
				 const u8 *wscript)
{
	return towire_hsm_sign_delayed_payment_to_us(ctx, commit_num,
						     tx, wscript,
						     *tx->input_amounts[0]);
}

static u8 *remote_htlc_to_us(const tal_t *ctx,
			     struct bitcoin_tx *tx,
			     const u8 *wscript)
{
	return towire_hsm_sign_remote_htlc_to_us(ctx,
						 remote_per_commitment_point,
						 tx, wscript,
						 *tx->input_amounts[0]);
}

static u8 *penalty_to_us(const tal_t *ctx,
			 struct bitcoin_tx *tx,
			 const u8 *wscript)
{
	return towire_hsm_sign_penalty_to_us(ctx, remote_per_commitment_secret,
					     tx, wscript, *tx->input_amounts[0],
					     NULL, NULL);
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

	tx = bitcoin_tx(ctx, out->chainparams, 1, 1, locktime);
	bitcoin_tx_add_input(tx, &out->txid, out->outnum, to_self_delay,
			     out->sat, NULL);

	bitcoin_tx_add_output(
	    tx, scriptpubkey_p2wpkh(tx, &our_wallet_pubkey), out->sat);

	/* Worst-case sig is 73 bytes */
	weight = bitcoin_tx_weight(tx) + 1 + 3 + 73 + 0 + tal_count(wscript);
	weight = elements_add_overhead(weight, 1, 1);
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
	if (!msg || !fromwire_hsm_sign_tx_reply(msg, &sig)) {
		status_failed(STATUS_FAIL_HSM_IO,
			      "Reading sign_tx_reply: %s",
			      tal_hex(tmpctx, msg));
	}

	witness = bitcoin_witness_sig_and_element(tx, &sig, elem,
						  elemsize, wscript);
	bitcoin_tx_input_set_witness(tx, 0, take(witness));
	return tx;
}

static void hsm_sign_local_htlc_tx(struct bitcoin_tx *tx,
				   const u8 *wscript,
				   struct bitcoin_signature *sig)
{
	u8 *msg = towire_hsm_sign_local_htlc_tx(NULL, commit_num,
					  tx, wscript,
					  *tx->input_amounts[0]);

	if (!wire_sync_write(HSM_FD, take(msg)))
		status_failed(STATUS_FAIL_HSM_IO,
			      "Writing sign_local_htlc_tx to hsm");
	msg = wire_sync_read(tmpctx, HSM_FD);
	if (!msg || !fromwire_hsm_sign_tx_reply(msg, sig))
		status_failed(STATUS_FAIL_HSM_IO,
			      "Reading sign_local_htlc_tx: %s",
			      tal_hex(tmpctx, msg));
}

static void hsm_get_per_commitment_point(struct pubkey *per_commitment_point)
{
	u8 *msg = towire_hsm_get_per_commitment_point(NULL, commit_num);
	struct secret *unused;

	if (!wire_sync_write(HSM_FD, take(msg)))
		status_failed(STATUS_FAIL_HSM_IO, "Writing sign_htlc_tx to hsm");
	msg = wire_sync_read(tmpctx, HSM_FD);
	if (!msg
	    || !fromwire_hsm_get_per_commitment_point_reply(tmpctx, msg,
							    per_commitment_point,
							    &unused))
		status_failed(STATUS_FAIL_HSM_IO,
			      "Reading hsm_get_per_commitment_point_reply: %s",
			      tal_hex(tmpctx, msg));
}

static struct tracked_output *
new_tracked_output(const struct chainparams *chainparams,
		   struct tracked_output ***outs,
		   const struct bitcoin_txid *txid,
		   u32 tx_blockheight,
		   enum tx_type tx_type,
		   u32 outnum,
		   struct amount_sat sat,
		   enum output_type output_type,
		   const struct htlc_stub *htlc,
		   const u8 *wscript,
		   const secp256k1_ecdsa_signature *remote_htlc_sig)
{
	struct tracked_output *out = tal(*outs, struct tracked_output);

	status_debug("Tracking output %u of %s: %s/%s",
		     outnum,
		     type_to_string(tmpctx, struct bitcoin_txid, txid),
		     tx_type_name(tx_type),
		     output_type_name(output_type));

	out->tx_type = tx_type;
	out->txid = *txid;
	out->tx_blockheight = tx_blockheight;
	out->depth = 0;
	out->outnum = outnum;
	out->sat = sat;
	out->output_type = output_type;
	out->proposal = NULL;
	out->resolved = NULL;
	out->chainparams = chainparams;
	if (htlc)
		out->htlc = *htlc;
	out->wscript = tal_steal(out, wscript);
	if (remote_htlc_sig) {
		struct bitcoin_signature *sig;
		sig = tal(out, struct bitcoin_signature);
		sig->s = *remote_htlc_sig;
		sig->sighash_type = SIGHASH_ALL;
		out->remote_htlc_sig = sig;
	} else
		out->remote_htlc_sig = NULL;

	tal_arr_expand(outs, out);

	return out;
}

static void ignore_output(struct tracked_output *out)
{
	status_debug("Ignoring output %u of %s: %s/%s",
		     out->outnum,
		     type_to_string(tmpctx, struct bitcoin_txid, &out->txid),
		     tx_type_name(out->tx_type),
		     output_type_name(out->output_type));

	out->resolved = tal(out, struct resolution);
	out->resolved->txid = out->txid;
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

static void proposal_meets_depth(struct tracked_output *out)
{
	/* If we simply wanted to ignore it after some depth */
	if (!out->proposal->tx) {
		ignore_output(out);
		return;
	}

	status_debug("Broadcasting %s (%s) to resolve %s/%s",
		     tx_type_name(out->proposal->tx_type),
		     type_to_string(tmpctx, struct bitcoin_tx, out->proposal->tx),
		     tx_type_name(out->tx_type),
		     output_type_name(out->output_type));

	wire_sync_write(
	    REQ_FD,
	    take(towire_onchain_broadcast_tx(
		NULL, out->proposal->tx,
		onchain_txtype_to_wallet_txtype(out->proposal->tx_type))));

	/* Don't wait for this if we're ignoring the tiny payment. */
	if (out->proposal->tx_type == IGNORING_TINY_PAYMENT)
		ignore_output(out);

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
				 const struct bitcoin_tx *tx)
{
	/* If there's no TX associated, it's not us. */
	if (!out->proposal->tx)
		return false;

	/* Our proposal can change as feerates change.  Input
	 * comparison (ignoring signatures) works pretty well.
	 *
	 * FIXME: Better would be to compare outputs, but they weren't
	 * saved to db correctly until now. (COMPAT_V052)
	 */
	if (tx->wtx->num_inputs != out->proposal->tx->wtx->num_inputs)
		return false;

	for (size_t i = 0; i < tx->wtx->num_inputs; i++) {
		if (!input_similar(&tx->wtx->inputs[i], &out->proposal->tx->wtx->inputs[i]))
			return false;
	}

	out->resolved = tal(out, struct resolution);
	bitcoin_txid(tx, &out->resolved->txid);
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
			  const struct bitcoin_tx *tx)
{
	out->resolved = tal(out, struct resolution);
	bitcoin_txid(tx, &out->resolved->txid);
	out->resolved->depth = 0;
	out->resolved->tx_type = UNKNOWN_TXTYPE;

	status_broken("Unknown spend of %s/%s by %s",
		     tx_type_name(out->tx_type),
		     output_type_name(out->output_type),
		     type_to_string(tmpctx, struct bitcoin_tx, tx));
}

static u64 unmask_commit_number(const struct bitcoin_tx *tx,
				enum side funder,
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
	obscurer = commit_number_obscurer(keys[funder], keys[!funder]);

	/* BOLT #3:
	 *
	 * * locktime: upper 8 bits are 0x20, lower 24 bits are the lower 24 bits of the obscured commitment number
	 *...
	 * * `txin[0]` sequence: upper 8 bits are 0x80, lower 24 bits are upper 24 bits of the obscured commitment number
	 */
	return ((tx->wtx->locktime & 0x00FFFFFF)
		| (tx->wtx->inputs[0].sequence & (u64)0x00FFFFFF) << 24)
		^ obscurer;
}

static bool is_mutual_close(const struct bitcoin_tx *tx,
			    const u8 *local_scriptpubkey,
			    const u8 *remote_scriptpubkey)
{
	size_t i;
	bool local_matched = false, remote_matched = false;

	for (i = 0; i < tx->wtx->num_outputs; i++) {
		const u8 *script = bitcoin_tx_output_get_script(tmpctx, tx, i);
		/* To be paranoid, we only let each one match once. */
		if (chainparams->is_elements &&
		    (script == NULL || tal_bytelen(script) == 0)) {
			/* This is a fee output, ignore please */
			continue;
		} else if (scripteq(script, local_scriptpubkey)
		    && !local_matched)
			local_matched = true;
		else if (scripteq(script, remote_scriptpubkey)
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
				       "%u outputs unresolved: waiting confirmation that we spent %s (%s:%u) using %s",
				       num_not_irrevocably_resolved(outs),
				       output_type_name(best->output_type),
				       type_to_string(tmpctx, struct bitcoin_txid,
						      &best->txid),
				       best->outnum,
				       tx_type_name(best->proposal->tx_type));
		} else {
			peer_billboard(false,
				       "%u outputs unresolved: in %u blocks will spend %s (%s:%u) using %s",
				       num_not_irrevocably_resolved(outs),
				       best->proposal->depth_required - best->depth,
				       output_type_name(best->output_type),
				       type_to_string(tmpctx, struct bitcoin_txid,
						      &best->txid),
				       best->outnum,
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

static void unwatch_tx(const struct bitcoin_tx *tx)
{
	u8 *msg;
	struct bitcoin_txid txid;

	bitcoin_txid(tx, &txid);

	msg = towire_onchain_unwatch_tx(tx, &txid);
	wire_sync_write(REQ_FD, take(msg));
}

static void handle_htlc_onchain_fulfill(struct tracked_output *out,
					const struct bitcoin_tx *tx)
{
	const u8 *witness_preimage;
	struct preimage preimage;
	struct sha256 sha;
	struct ripemd160 ripemd;

	/* Our HTLC, they filled (must be an HTLC-success tx). */
	if (out->tx_type == THEIR_UNILATERAL) {
		/* BOLT #3:
		 *
		 * ## HTLC-Timeout and HTLC-Success Transactions
		 *
		 * ...  `txin[0]` witness stack: `0 <remotehtlcsig> <localhtlcsig>
		 * <payment_preimage>` for HTLC-success
		 */
		if (tx->wtx->inputs[0].witness->num_items != 5) /* +1 for wscript */
			status_failed(STATUS_FAIL_INTERNAL_ERROR,
				      "%s/%s spent with weird witness %zu",
				      tx_type_name(out->tx_type),
				      output_type_name(out->output_type),
				      tx->wtx->inputs[0].witness->num_items);

		witness_preimage =
		    bitcoin_tx_input_get_witness(tmpctx, tx, 0, 3);
	} else if (out->tx_type == OUR_UNILATERAL) {
		/* BOLT #3:
		 *
		 * The remote node can redeem the HTLC with the witness:
		 *
		 *    <remotehtlcsig> <payment_preimage>
		 */
		if (tx->wtx->inputs[0].witness->num_items != 3) /* +1 for wscript */
			status_failed(STATUS_FAIL_INTERNAL_ERROR,
				      "%s/%s spent with weird witness %zu",
				      tx_type_name(out->tx_type),
				      output_type_name(out->output_type),
				      tx->wtx->inputs[0].witness->num_items);

		witness_preimage =
		    bitcoin_tx_input_get_witness(tmpctx, tx, 0, 1);
	} else
		status_failed(STATUS_FAIL_INTERNAL_ERROR,
			      "onchain_fulfill for %s/%s?",
			      tx_type_name(out->tx_type),
			      output_type_name(out->output_type));

	if (tal_count(witness_preimage) != sizeof(preimage))
		status_failed(STATUS_FAIL_INTERNAL_ERROR,
			      "%s/%s spent with bad witness length %zu",
			      tx_type_name(out->tx_type),
			      output_type_name(out->output_type),
			      tal_count(witness_preimage));
	memcpy(&preimage, witness_preimage, sizeof(preimage));
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

	/* Tell master we found a preimage. */
	status_debug("%s/%s gave us preimage %s",
		     tx_type_name(out->tx_type),
		     output_type_name(out->output_type),
		     type_to_string(tmpctx, struct preimage, &preimage));
	wire_sync_write(REQ_FD,
			take(towire_onchain_extracted_preimage(NULL,
							       &preimage)));
}

static void resolve_htlc_tx(const struct chainparams *chainparams,
			    struct tracked_output ***outs,
			    size_t out_index,
			    const struct bitcoin_tx *htlc_tx,
			    const struct bitcoin_txid *htlc_txid,
			    u32 tx_blockheight)
{
	struct tracked_output *out;
	struct bitcoin_tx *tx;
	struct amount_sat amt;
	struct amount_asset asset;
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
	asset = bitcoin_tx_output_get_amount(htlc_tx, 0);
	assert(amount_asset_is_main(&asset));
	amt = amount_asset_to_sat(&asset);
	out = new_tracked_output(chainparams, outs, htlc_txid, tx_blockheight,
				 (*outs)[out_index]->resolved->tx_type,
				 0, amt,
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
static void steal_htlc_tx(struct tracked_output *out)
{
	struct bitcoin_tx *tx;
	enum tx_type tx_type = OUR_PENALTY_TX;

	/* BOLT #3:
	 *
	 * To spend this via penalty, the remote node uses a witness stack
	 * `<revocationsig> 1`
	 */
	tx = tx_to_us(out, penalty_to_us, out, 0xFFFFFFFF, 0, &ONE,
		      sizeof(ONE), out->wscript, &tx_type, penalty_feerate);
	propose_resolution(out, tx, 0, tx_type);
}

static void onchain_annotate_txout(const struct bitcoin_txid *txid, u32 outnum,
				   enum wallet_tx_type type)
{
	wire_sync_write(REQ_FD, take(towire_onchain_annotate_txout(
				    tmpctx, txid, outnum, type)));
}

static void onchain_annotate_txin(const struct bitcoin_txid *txid, u32 innum,
				  enum wallet_tx_type type)
{
	wire_sync_write(REQ_FD, take(towire_onchain_annotate_txin(
				    tmpctx, txid, innum, type)));
}

/* An output has been spent: see if it resolves something we care about. */
static void output_spent(const struct chainparams *chainparams,
			 struct tracked_output ***outs,
			 const struct bitcoin_tx *tx,
			 u32 input_num,
			 u32 tx_blockheight)
{
	struct bitcoin_txid txid, tmptxid, spendertxid;

	bitcoin_txid(tx, &txid);
	bitcoin_txid(tx, &spendertxid);

	for (size_t i = 0; i < tal_count(*outs); i++) {
		struct tracked_output *out = (*outs)[i];
		if (out->resolved)
			continue;

		if (tx->wtx->inputs[input_num].index != out->outnum)
			continue;

		bitcoin_tx_input_get_txid(tx, input_num, &tmptxid);
		if (!bitcoin_txid_eq(&tmptxid, &out->txid))
			continue;

		/* Was this our resolution? */
		if (resolved_by_proposal(out, tx)) {
			/* If it's our htlc tx, we need to resolve that, too. */
			if (out->resolved->tx_type == OUR_HTLC_SUCCESS_TX
			    || out->resolved->tx_type == OUR_HTLC_TIMEOUT_TX)
				resolve_htlc_tx(chainparams, outs, i, tx, &txid,
						tx_blockheight);
			return;
		}

		switch (out->output_type) {
		case OUTPUT_TO_US:
		case DELAYED_OUTPUT_TO_US:
			unknown_spend(out, tx);
			break;

		case THEIR_HTLC:
			if (out->tx_type == THEIR_REVOKED_UNILATERAL) {
				steal_htlc_tx(out);
			} else {
				/* We ignore this timeout tx, since we should
				 * resolve by ignoring once we reach depth. */
				onchain_annotate_txout(
				    &spendertxid, out->outnum,
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
			handle_htlc_onchain_fulfill(out, tx);
			if (out->tx_type == THEIR_REVOKED_UNILATERAL)
				steal_htlc_tx(out);
			else {
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
				    &spendertxid, out->outnum,
				    TX_CHANNEL_HTLC_SUCCESS | TX_THEIRS);
			}
			break;

		case FUNDING_OUTPUT:
			/* Master should be restarting us, as this implies
			 * that our old tx was unspent. */
			status_failed(STATUS_FAIL_INTERNAL_ERROR,
				      "Funding output spent again!");

		/* Um, we don't track these! */
		case OUTPUT_TO_THEM:
		case DELAYED_OUTPUT_TO_THEM:
		case ELEMENTS_FEE:
			status_failed(STATUS_FAIL_INTERNAL_ERROR,
				      "Tracked spend of %s/%s?",
				      tx_type_name(out->tx_type),
				      output_type_name(out->output_type));
		}
		return;
	}

	bitcoin_tx_input_get_txid(tx, input_num, &txid);
	/* Not interesting to us, so unwatch the tx and all its outputs */
	status_debug("Notified about tx %s output %u spend, but we don't care",
		     type_to_string(tmpctx, struct bitcoin_txid, &txid),
		     tx->wtx->inputs[input_num].index);

	unwatch_tx(tx);
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
		msg = towire_onchain_htlc_timeout(out, &out->htlc);
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
		if (bitcoin_txid_eq(&outs[i]->txid, txid))
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
		    && bitcoin_txid_eq(&outs[i]->txid, txid)
		    && depth >= outs[i]->proposal->depth_required) {
			proposal_meets_depth(outs[i]);
		}
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
static void handle_preimage(const struct chainparams *chainparams,
			    struct tracked_output **outs,
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
			tx = htlc_success_tx(outs[i],
					     chainparams,
					     &outs[i]->txid,
					     outs[i]->outnum,
					     htlc_amount,
					     to_self_delay[LOCAL],
					     0,
					     keyset);
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
			tx = tx_to_us(outs[i], remote_htlc_to_us, outs[i], 0,
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
	/* memleak_scan_region is overkill if these are simple pointers to
	 * objects which don't contain pointers, but it works. */
	if (keyset)
		memleak_scan_region(memtable, keyset, sizeof(*keyset));

	if (remote_per_commitment_point)
		memleak_scan_region(memtable, remote_per_commitment_point,
				    sizeof(*remote_per_commitment_point));

	if (remote_per_commitment_secret)
		memleak_scan_region(memtable, remote_per_commitment_secret,
				    sizeof(*remote_per_commitment_secret));

	/* top-level context args */
	memleak_scan_region(memtable, topctx, 0);

	memleak_scan_region(memtable, missing_htlc_msgs,
			    tal_bytelen(missing_htlc_msgs));
}

static bool handle_dev_memleak(struct tracked_output **outs, const u8 *msg)
{
	struct htable *memtable;
	bool found_leak;

	if (!fromwire_onchain_dev_memleak(msg))
		return false;

	memtable = memleak_enter_allocations(tmpctx, msg, msg);
	/* Top-level context is parent of outs */
	memleak_remove_globals(memtable, tal_parent(outs));
	memleak_remove_referenced(memtable, outs);

	found_leak = dump_memleak(memtable);
	wire_sync_write(REQ_FD,
			take(towire_onchain_dev_memleak_reply(NULL,
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
static void wait_for_resolved(const struct chainparams *chainparams,
			      struct tracked_output **outs)
{
	billboard_update(outs);

	while (num_not_irrevocably_resolved(outs) != 0) {
		u8 *msg = wire_sync_read(outs, REQ_FD);
		struct bitcoin_txid txid;
		struct bitcoin_tx *tx;
		u32 input_num, depth, tx_blockheight;
		struct preimage preimage;

		status_debug("Got new message %s",
			     onchain_wire_type_name(fromwire_peektype(msg)));

		if (fromwire_onchain_depth(msg, &txid, &depth))
			tx_new_depth(outs, &txid, depth);
		else if (fromwire_onchain_spent(msg, msg, &tx, &input_num,
						&tx_blockheight)) {
			tx->chainparams = chainparams;
			output_spent(chainparams, &outs, tx, input_num, tx_blockheight);
		} else if (fromwire_onchain_known_preimage(msg, &preimage))
			handle_preimage(chainparams, outs, &preimage);
		else if (!handle_dev_memleak(outs, msg))
			master_badmsg(-1, msg);

		billboard_update(outs);
		tal_free(msg);
		clean_tmpctx();
	}

	wire_sync_write(REQ_FD,
			take(towire_onchain_all_irrevocably_resolved(outs)));
}

static void init_reply(const char *what)
{
	/* Send init_reply first, so billboard gets credited to ONCHAIND */
	wire_sync_write(REQ_FD, take(towire_onchain_init_reply(NULL)));
	peer_billboard(true, what);
}

static void handle_mutual_close(const struct chainparams *chainparams,
				const struct bitcoin_txid *txid,
				struct tracked_output **outs)
{
	init_reply("Tracking mutual close transaction");

	/* Annotate the first input as close. We can currently only have a
	 * single input for these. */
	onchain_annotate_txin(txid, 0, TX_CHANNEL_CLOSE);

	/* BOLT #5:
	 *
	 * A closing transaction *resolves* the funding transaction output.
	 *
	 * In the case of a mutual close, a node need not do anything else, as it has
	 * already agreed to the output, which is sent to its specified `scriptpubkey`
	 */
	resolved_by_other(outs[0], txid, MUTUAL_CLOSE);

	wait_for_resolved(chainparams, outs);
}

static u8 **derive_htlc_scripts(const struct htlc_stub *htlcs, enum side side)
{
	size_t i;
	u8 **htlc_scripts = tal_arr(htlcs, u8 *, tal_count(htlcs));

	for (i = 0; i < tal_count(htlcs); i++) {
		if (htlcs[i].owner == side)
			htlc_scripts[i] = htlc_offered_wscript(htlc_scripts,
							       &htlcs[i].ripemd,
							       keyset);
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
								keyset);
		}
	}
	return htlc_scripts;
}

static size_t resolve_our_htlc_ourcommit(const struct chainparams *chainparams,
					 struct tracked_output *out,
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
				     &out->txid, out->outnum,
				     htlc_amount,
				     htlcs[matches[i]].cltv_expiry,
				     to_self_delay[LOCAL], 0, keyset);

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
			      " cltvs %s wscripts %s",
			      tal_count(matches),
			      min_possible_feerate, max_possible_feerate,
			      type_to_string(tmpctx, struct bitcoin_tx, tx),
			      type_to_string(tmpctx, struct amount_sat,
					     &out->sat),
			      type_to_string(tmpctx, struct bitcoin_signature,
					     out->remote_htlc_sig),
			      cltvs, wscripts);
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
	tx = tx_to_us(out, remote_htlc_to_us, out, 0, cltv_expiry, NULL, 0,
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
				 const struct bitcoin_tx *tx,
				 unsigned int outnum,
				 u8 **htlc_scripts)
{
	size_t *matches = tal_arr(ctx, size_t, 0);
	const u8 *script = bitcoin_tx_output_get_script(tmpctx, tx, outnum);

	/* Must be a p2wsh output */
	if (script == NULL || !is_p2wsh(script, NULL))
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
			       const struct htlc_stub *htlcs,
			       const bool *tell_if_missing,
			       const bool *tell_immediately)
{
	for (size_t i = 0; i < tal_count(htlcs); i++) {
		u8 *msg;

		/* Used. */
		if (!htlc_scripts[i])
			continue;

		/* Doesn't care. */
		if (!tell_if_missing[i])
			continue;

		msg = towire_onchain_missing_htlc_output(missing_htlc_msgs,
							 &htlcs[i]);
		if (tell_immediately[i])
			wire_sync_write(REQ_FD, take(msg));
		else
			tal_arr_expand(&missing_htlc_msgs, msg);
	}
}

static void handle_our_unilateral(const struct bitcoin_tx *tx,
				  u32 tx_blockheight,
				  const struct bitcoin_txid *txid,
				  const struct basepoints basepoints[NUM_SIDES],
				  const struct htlc_stub *htlcs,
				  const bool *tell_if_missing,
				  const bool *tell_immediately,
				  const secp256k1_ecdsa_signature *remote_htlc_sigs,
				  struct tracked_output **outs)
{
	u8 **htlc_scripts;
	u8 *local_wscript, *script[NUM_SIDES];
	struct pubkey local_per_commitment_point;
	struct keyset *ks;
	size_t i;

	init_reply("Tracking our own unilateral close");
	onchain_annotate_txin(txid, 0, TX_CHANNEL_UNILATERAL);

	/* BOLT #5:
	 *
	 * In this case, a node discovers its *local commitment transaction*,
	 * which *resolves* the funding transaction output.
	 */
	resolved_by_other(outs[0], txid, OUR_UNILATERAL);

	/* Figure out what delayed to-us output looks like */
	hsm_get_per_commitment_point(&local_per_commitment_point);

	/* keyset is const, we need a non-const ptr to set it up */
	keyset = ks = tal(tx, struct keyset);
	if (!derive_keyset(&local_per_commitment_point,
			   &basepoints[LOCAL],
			   &basepoints[REMOTE],
			   option_static_remotekey,
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

	local_wscript = to_self_wscript(tmpctx, to_self_delay[LOCAL], keyset);

	/* Figure out what to-us output looks like. */
	script[LOCAL] = scriptpubkey_p2wsh(tmpctx, local_wscript);

	/* Figure out what direct to-them output looks like. */
	script[REMOTE] = scriptpubkey_p2wpkh(tmpctx, &keyset->other_payment_key);

	/* Calculate all the HTLC scripts so we can match them */
	htlc_scripts = derive_htlc_scripts(htlcs, LOCAL);

	status_debug("Script to-me: %u: %s (%s)",
		     to_self_delay[LOCAL],
		     tal_hex(tmpctx, script[LOCAL]),
		     tal_hex(tmpctx, local_wscript));
	status_debug("Script to-them: %s",
		     tal_hex(tmpctx, script[REMOTE]));

	for (i = 0; i < tx->wtx->num_outputs; i++) {
		const u8 *script = bitcoin_tx_output_get_script(tmpctx, tx, i);
		if (script == NULL)
			continue;
		status_debug("Output %zu: %s", i,
			     tal_hex(tmpctx, script));
	}

	for (i = 0; i < tx->wtx->num_outputs; i++) {
		struct tracked_output *out;
		const size_t *matches;
		size_t which_htlc;
		const u8 *oscript = bitcoin_tx_output_get_script(tmpctx, tx, i);
		struct amount_asset asset = bitcoin_tx_output_get_amount(tx, i);
		struct amount_sat amt;

		assert(amount_asset_is_main(&asset));
		amt = amount_asset_to_sat(&asset);

		if (chainparams->is_elements &&
		    (oscript == NULL || tal_bytelen(oscript) == 0)) {
			status_debug("OUTPUT %zu is a fee output", i);
			/* An empty script simply means that that this is a
			 * fee output. */
			out = new_tracked_output(tx->chainparams, &outs,
						 txid, tx_blockheight,
						 OUR_UNILATERAL, i,
						 amt,
						 ELEMENTS_FEE,
						 NULL, NULL, NULL);
			ignore_output(out);
			continue;
		}else if (script[LOCAL]
		    && scripteq(oscript, script[LOCAL])) {
			struct bitcoin_tx *to_us;
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
			out = new_tracked_output(tx->chainparams,
						 &outs, txid, tx_blockheight,
						 OUR_UNILATERAL, i,
						 amt,
						 DELAYED_OUTPUT_TO_US,
						 NULL, NULL, NULL);
			/* BOLT #3:
			 *
			 * The output is spent by a transaction with
			 * `nSequence` field set to `to_self_delay` (which can
			 * only be valid after that duration has passed) and
			 * witness:
			 *
			 *	<local_delayedsig> 0
			 */
			to_us = tx_to_us(out, delayed_payment_to_us, out,
					 to_self_delay[LOCAL], 0, NULL, 0,
					 local_wscript, &tx_type,
					 delayed_to_us_feerate);

			/* BOLT #5:
			 *
			 * Note: if the output is spent (as recommended), the
			 * output is *resolved* by the spending transaction
			 */
			propose_resolution(out, to_us, to_self_delay[LOCAL],
					   tx_type);

			script[LOCAL] = NULL;
			continue;
		}
		if (script[REMOTE]
		    && scripteq(oscript, script[REMOTE])) {
			/* BOLT #5:
			 *
			 *     - MAY ignore the `to_remote` output.
			 *       - Note: No action is required by the local
			 *       node, as `to_remote` is considered *resolved*
			 *       by the commitment transaction itself.
			 */
			out = new_tracked_output(tx->chainparams,
						 &outs, txid, tx_blockheight,
						 OUR_UNILATERAL, i,
						 amt,
						 OUTPUT_TO_THEM,
						 NULL, NULL, NULL);
			ignore_output(out);
			script[REMOTE] = NULL;
			continue;
		}

		matches = match_htlc_output(tmpctx, tx, i, htlc_scripts);
		/* FIXME: limp along when this happens! */
		if (tal_count(matches) == 0) {
			onchain_annotate_txout(txid, i, TX_CHANNEL_PENALTY | TX_THEIRS);
			status_failed(STATUS_FAIL_INTERNAL_ERROR,
				      "Could not find resolution for output %zu",
				      i);
		}

		if (matches_direction(matches, htlcs) == LOCAL) {
			/* BOLT #5:
			 *
			 *     - MUST handle HTLCs offered by itself as specified
			 *       in [HTLC Output Handling: Local Commitment,
			 *       Local Offers]
			 */
			out = new_tracked_output(tx->chainparams,
						 &outs, txid,
						 tx_blockheight,
						 OUR_UNILATERAL, i,
						 amt,
						 OUR_HTLC,
						 NULL, NULL,
						 remote_htlc_sigs);
			/* Tells us which htlc to use */
			which_htlc = resolve_our_htlc_ourcommit(tx->chainparams,
								out, matches,
								htlcs,
								htlc_scripts);
		} else {
			out = new_tracked_output(tx->chainparams,
						 &outs, txid,
						 tx_blockheight,
						 OUR_UNILATERAL, i,
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
			which_htlc = resolve_their_htlc(out, matches, htlcs,
							htlc_scripts);
		}
		out->htlc = htlcs[which_htlc];
		out->wscript = tal_steal(out, htlc_scripts[which_htlc]);

		/* Each of these consumes one HTLC signature */
		remote_htlc_sigs++;
		/* We've matched this HTLC, can't do again. */
		htlc_scripts[which_htlc] = NULL;

	}

	note_missing_htlcs(htlc_scripts, htlcs,
			   tell_if_missing, tell_immediately);
	wait_for_resolved(tx->chainparams, outs);
}

/* We produce individual penalty txs.  It's less efficient, but avoids them
 * using HTLC txs to block our penalties for long enough to pass the CSV
 * delay */
static void steal_to_them_output(struct tracked_output *out)
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
	wscript = bitcoin_wscript_to_local(tmpctx, to_self_delay[REMOTE],
					   &keyset->self_revocation_key,
					   &keyset->self_delayed_payment_key);

	tx = tx_to_us(tmpctx, penalty_to_us, out, 0xFFFFFFFF, 0, &ONE,
		      sizeof(ONE), wscript, &tx_type, penalty_feerate);

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
	tx = tx_to_us(out, penalty_to_us, out, 0xFFFFFFFF, 0, der, sizeof(der),
		      out->wscript, &tx_type, penalty_feerate);

	propose_resolution(out, tx, 0, tx_type);
}

/* Tell wallet that we have discovered a UTXO from a to-remote output,
 * which it can spend with a little additional info we give here. */
static void tell_wallet_to_remote(const struct bitcoin_tx *tx,
				  unsigned int outnum,
				  const struct bitcoin_txid *txid,
				  u32 tx_blockheight,
				  const u8 *scriptpubkey,
				  const struct pubkey *per_commit_point,
				  bool option_static_remotekey)
{
	struct amount_asset asset = bitcoin_tx_output_get_amount(tx, outnum);
	struct amount_sat amt;

	assert(amount_asset_is_main(&asset));
	amt = amount_asset_to_sat(&asset);

	/* A NULL per_commit_point is how we indicate the pubkey doesn't need
	 * changing. */
	if (option_static_remotekey)
		per_commit_point = NULL;

	wire_sync_write(REQ_FD,
			take(towire_onchain_add_utxo(NULL, txid, outnum,
						     per_commit_point,
						     amt,
						     tx_blockheight,
						     scriptpubkey)));
}

/* BOLT #5:
 *
 * If any node tries to cheat by broadcasting an outdated commitment
 * transaction (any previous commitment transaction besides the most current
 * one), the other node in the channel can use its revocation private key to
 * claim all the funds from the channel's original funding transaction.
 */
static void handle_their_cheat(const struct bitcoin_tx *tx,
			       const struct bitcoin_txid *txid,
			       u32 tx_blockheight,
			       const struct secret *revocation_preimage,
			       const struct basepoints basepoints[NUM_SIDES],
			       const struct htlc_stub *htlcs,
			       const bool *tell_if_missing,
			       const bool *tell_immediately,
			       struct tracked_output **outs)
{
	u8 **htlc_scripts;
	u8 *remote_wscript, *script[NUM_SIDES];
	struct keyset *ks;
	struct pubkey *k;
	size_t i;

	init_reply("Tracking their illegal close: taking all funds");
	onchain_annotate_txin(
	    txid, 0, TX_CHANNEL_UNILATERAL | TX_CHANNEL_CHEAT | TX_THEIRS);

	/* BOLT #5:
	 *
	 * Once a node discovers a commitment transaction for which *it* has a
	 * revocation private key, the funding transaction output is *resolved*.
	 */
	resolved_by_other(outs[0], txid, THEIR_REVOKED_UNILATERAL);

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
			   option_static_remotekey,
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
		     " (option_static_remotekey = %i)",
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
		     option_static_remotekey);

	remote_wscript = to_self_wscript(tmpctx, to_self_delay[REMOTE], keyset);

	/* Figure out what to-them output looks like. */
	script[REMOTE] = scriptpubkey_p2wsh(tmpctx, remote_wscript);

	/* Figure out what direct to-us output looks like. */
	script[LOCAL] = scriptpubkey_p2wpkh(tmpctx, &keyset->other_payment_key);

	/* Calculate all the HTLC scripts so we can match them */
	htlc_scripts = derive_htlc_scripts(htlcs, REMOTE);

	status_debug("Script to-them: %u: %s (%s)",
		     to_self_delay[REMOTE],
		     tal_hex(tmpctx, script[REMOTE]),
		     tal_hex(tmpctx, remote_wscript));
	status_debug("Script to-me: %s",
		     tal_hex(tmpctx, script[LOCAL]));

	for (i = 0; i < tx->wtx->num_outputs; i++) {
		const u8 *script = bitcoin_tx_output_get_script(tmpctx, tx, i);
		if (script == NULL)
			continue;
		status_debug("Output %zu: %s", i, tal_hex(tmpctx, script));
	}

	for (i = 0; i < tx->wtx->num_outputs; i++) {
		struct tracked_output *out;
		const size_t *matches;
		size_t which_htlc;
		const u8 *oscript = bitcoin_tx_output_get_script(tmpctx, tx, i);
		struct amount_asset asset = bitcoin_tx_output_get_amount(tx, i);
		struct amount_sat amt;
		assert(amount_asset_is_main(&asset));
		amt = amount_asset_to_sat(&asset);

		if (chainparams->is_elements &&
		    (oscript == NULL || tal_bytelen(oscript) == 0)) {
			/* An empty script simply means that that this is a
			 * fee output. */
			out = new_tracked_output(tx->chainparams,
						 &outs, txid, tx_blockheight,
						 OUR_UNILATERAL, i,
						 amt,
						 ELEMENTS_FEE,
						 NULL, NULL, NULL);
			ignore_output(out);
			continue;
		}

		if (script[LOCAL]
		    && scripteq(oscript, script[LOCAL])) {
			/* BOLT #5:
			 *
			 *   - MAY take no action regarding the _local node's
			 *     main output_, as this is a simple P2WPKH output
			 *     to itself.
			 *     - Note: this output is considered *resolved* by
			 *       the commitment transaction itself.
			 */
			out = new_tracked_output(tx->chainparams,
						 &outs, txid, tx_blockheight,
						 THEIR_REVOKED_UNILATERAL,
						 i, amt,
						 OUTPUT_TO_US, NULL, NULL, NULL);
			ignore_output(out);

			tell_wallet_to_remote(tx, i, txid,
					      tx_blockheight,
					      script[LOCAL],
					      remote_per_commitment_point,
					      option_static_remotekey);
			script[LOCAL] = NULL;
			continue;
		}
		if (script[REMOTE]
		    && scripteq(oscript, script[REMOTE])) {
			/* BOLT #5:
			 *
			 *   - MUST *resolve* the _remote node's main output_ by
			 *     spending it using the revocation private key.
			*/
			out = new_tracked_output(tx->chainparams,
						 &outs, txid, tx_blockheight,
						 THEIR_REVOKED_UNILATERAL, i,
						 amt,
						 DELAYED_OUTPUT_TO_THEM,
						 NULL, NULL, NULL);
			steal_to_them_output(out);
			script[REMOTE] = NULL;
			continue;
		}

		matches = match_htlc_output(tmpctx, tx, i, htlc_scripts);
		if (tal_count(matches) == 0)
			status_failed(STATUS_FAIL_INTERNAL_ERROR,
				      "Could not find resolution for output %zu",
				      i);

		/* In this case, we don't care which HTLC we choose; so pick
		   first one */
		which_htlc = matches[0];
		if (matches_direction(matches, htlcs) == LOCAL) {
			/* BOLT #5:
			 *
			 *   - MUST *resolve* the _local node's offered HTLCs_ in one of three ways:
			 *     * spend the *commitment tx* using the payment revocation private key.
			 *     * spend the *commitment tx* once the HTLC timeout has passed.
			 *     * spend the *HTLC-success tx*, if the remote node has published it.
			 */
			out = new_tracked_output(tx->chainparams,
						 &outs, txid,
						 tx_blockheight,
						 THEIR_REVOKED_UNILATERAL, i,
						 amt,
						 OUR_HTLC,
						 &htlcs[which_htlc],
						 htlc_scripts[which_htlc],
						 NULL);
			steal_htlc(out);
		} else {
			out = new_tracked_output(tx->chainparams,
						 &outs, txid,
						 tx_blockheight,
						 THEIR_REVOKED_UNILATERAL, i,
						 amt,
						 THEIR_HTLC,
						 &htlcs[which_htlc],
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

	note_missing_htlcs(htlc_scripts, htlcs,
			   tell_if_missing, tell_immediately);
	wait_for_resolved(tx->chainparams, outs);
}

static void handle_their_unilateral(const struct bitcoin_tx *tx,
				    u32 tx_blockheight,
				    const struct bitcoin_txid *txid,
				    const struct pubkey *this_remote_per_commitment_point,
				    const struct basepoints basepoints[NUM_SIDES],
				    const struct htlc_stub *htlcs,
				    const bool *tell_if_missing,
				    const bool *tell_immediately,
				    struct tracked_output **outs)
{
	u8 **htlc_scripts;
	u8 *remote_wscript, *script[NUM_SIDES];
	struct keyset *ks;
	size_t i;

	init_reply("Tracking their unilateral close");
	onchain_annotate_txin(txid, 0, TX_CHANNEL_UNILATERAL | TX_THEIRS);

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
	resolved_by_other(outs[0], txid, THEIR_UNILATERAL);

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
			   option_static_remotekey,
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

	remote_wscript = to_self_wscript(tmpctx, to_self_delay[REMOTE], keyset);

	/* Figure out what to-them output looks like. */
	script[REMOTE] = scriptpubkey_p2wsh(tmpctx, remote_wscript);

	/* Figure out what direct to-us output looks like. */
	script[LOCAL] = scriptpubkey_p2wpkh(tmpctx, &keyset->other_payment_key);

	/* Calculate all the HTLC scripts so we can match them */
	htlc_scripts = derive_htlc_scripts(htlcs, REMOTE);

	status_debug("Script to-them: %u: %s (%s)",
		     to_self_delay[REMOTE],
		     tal_hex(tmpctx, script[REMOTE]),
		     tal_hex(tmpctx, remote_wscript));
	status_debug("Script to-me: %s",
		     tal_hex(tmpctx, script[LOCAL]));

	for (i = 0; i < tx->wtx->num_outputs; i++) {
		const u8 *script = bitcoin_tx_output_get_script(tmpctx, tx, i);
		if (script == NULL)
			continue;
		status_debug("Output %zu: %s", i, tal_hex(tmpctx, script));
	}

	for (i = 0; i < tx->wtx->num_outputs; i++) {
		struct tracked_output *out;
		const size_t *matches;
		size_t which_htlc;
		const u8 *oscript = bitcoin_tx_output_get_script(tmpctx, tx, i);
		struct amount_asset asset = bitcoin_tx_output_get_amount(tx, i);
		struct amount_sat amt;
		assert(amount_asset_is_main(&asset));
		amt = amount_asset_to_sat(&asset);

		if (chainparams->is_elements &&
		    (oscript == NULL || tal_bytelen(oscript) == 0)) {
			/* An empty script simply means that that this is a
			 * fee output. */
			out = new_tracked_output(tx->chainparams,
						 &outs, txid, tx_blockheight,
						 OUR_UNILATERAL, i,
						 amt,
						 ELEMENTS_FEE,
						 NULL, NULL, NULL);
			ignore_output(out);
			continue;
		} else if (script[LOCAL] && scripteq(oscript, script[LOCAL])) {
			/* BOLT #5:
			 *
			 * - MAY take no action in regard to the associated
			 *   `to_remote`, which is simply a P2WPKH output to
			 *   the *local node*.
			 *   - Note: `to_remote` is considered *resolved* by the
			 *     commitment transaction itself.
			 */
			out = new_tracked_output(tx->chainparams,
						 &outs, txid, tx_blockheight,
						 THEIR_UNILATERAL,
						 i, amt,
						 OUTPUT_TO_US, NULL, NULL, NULL);
			ignore_output(out);

			tell_wallet_to_remote(tx, i, txid,
					      tx_blockheight,
					      script[LOCAL],
					      remote_per_commitment_point,
					      option_static_remotekey);
			script[LOCAL] = NULL;
			continue;
		}
		if (script[REMOTE]
		    && scripteq(oscript, script[REMOTE])) {
			/* BOLT #5:
			 *
			 * - MAY take no action in regard to the associated
			 *  `to_local`, which is a payment output to the *remote
			 *   node*.
			 *   - Note: `to_local` is considered *resolved* by the
			 *     commitment transaction itself.
			 */
			out = new_tracked_output(tx->chainparams,
						 &outs, txid, tx_blockheight,
						 THEIR_UNILATERAL, i,
						 amt,
						 DELAYED_OUTPUT_TO_THEM,
						 NULL, NULL, NULL);
			ignore_output(out);
			continue;
		}

		matches = match_htlc_output(tmpctx, tx, i, htlc_scripts);
		if (tal_count(matches) == 0)
			status_failed(STATUS_FAIL_INTERNAL_ERROR,
				      "Could not find resolution for output %zu",
				      i);

		if (matches_direction(matches, htlcs) == LOCAL) {
			/* BOLT #5:
			 *
			 * - MUST handle HTLCs offered by itself as specified in
			 *   [HTLC Output Handling: Remote Commitment,
			 *   Local Offers]
			 */
			out = new_tracked_output(tx->chainparams,
						 &outs, txid,
						 tx_blockheight,
						 THEIR_UNILATERAL, i,
						 amt,
						 OUR_HTLC,
						 NULL, NULL,
						 NULL);
			which_htlc = resolve_our_htlc_theircommit(out,
								  matches,
								  htlcs,
								  htlc_scripts);
		} else {
			out = new_tracked_output(tx->chainparams,
						 &outs, txid,
						 tx_blockheight,
						 THEIR_UNILATERAL, i,
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
			which_htlc = resolve_their_htlc(out, matches, htlcs,
							htlc_scripts);
		}
		out->htlc = htlcs[which_htlc];
		out->wscript = tal_steal(out, htlc_scripts[which_htlc]);
		htlc_scripts[which_htlc] = NULL;
	}

	note_missing_htlcs(htlc_scripts, htlcs,
			   tell_if_missing, tell_immediately);
	wait_for_resolved(tx->chainparams, outs);
}

static void handle_unknown_commitment(const struct bitcoin_tx *tx,
				      u32 tx_blockheight,
				      u64 commit_num,
				      const struct bitcoin_txid *txid,
				      const struct pubkey *possible_remote_per_commitment_point,
				      const struct basepoints basepoints[NUM_SIDES],
				      const struct htlc_stub *htlcs,
				      const bool *tell_if_missing,
				      struct tracked_output **outs)
{
	int to_us_output = -1;
	u8 *local_script;

	onchain_annotate_txin(txid, 0, TX_CHANNEL_UNILATERAL | TX_THEIRS);

	resolved_by_other(outs[0], txid, UNKNOWN_UNILATERAL);

	/* If they don't give us a per-commitment point and we rotate keys,
	 * we're out of luck. */
	if (!possible_remote_per_commitment_point
	    && !option_static_remotekey)
		goto search_done;

	if (!option_static_remotekey) {
		struct keyset *ks = tal(tmpctx, struct keyset);
		if (!derive_keyset(possible_remote_per_commitment_point,
				   &basepoints[REMOTE],
				   &basepoints[LOCAL],
				   option_static_remotekey,
				   ks))
			status_failed(STATUS_FAIL_INTERNAL_ERROR,
				      "Deriving keyset for possible_remote_per_commitment_point %s",
				      type_to_string(tmpctx, struct pubkey,
						     possible_remote_per_commitment_point));

		local_script = scriptpubkey_p2wpkh(tmpctx,
						   &ks->other_payment_key);
	} else {
		/* BOLT #3:
		 *
		 * ### `remotepubkey` Derivation
		 *
		 * If `option_static_remotekey` is negotiated the
		 * `remotepubkey` is simply the remote node's
		 * `payment_basepoint`, otherwise it is calculated as above
		 * using the remote node's `payment_basepoint`.
		 */
		local_script = scriptpubkey_p2wpkh(tmpctx,
						   &basepoints[LOCAL].payment);
	}

	for (size_t i = 0; i < tx->wtx->num_outputs; i++) {
		struct tracked_output *out;
		const u8 *oscript = bitcoin_tx_output_get_script(tmpctx, tx, i);
		struct amount_asset asset = bitcoin_tx_output_get_amount(tx, i);
		struct amount_sat amt;
		assert(amount_asset_is_main(&asset));
		amt = amount_asset_to_sat(&asset);

		if (oscript != NULL && local_script
		    && scripteq(oscript, local_script)) {
			/* BOLT #5:
			 *
			 * - MAY take no action in regard to the associated
			 *   `to_remote`, which is simply a P2WPKH output to
			 *   the *local node*.
			 *   - Note: `to_remote` is considered *resolved* by the
			 *     commitment transaction itself.
			 */
			out = new_tracked_output(tx->chainparams,
						 &outs, txid, tx_blockheight,
						 UNKNOWN_UNILATERAL,
						 i, amt,
						 OUTPUT_TO_US, NULL, NULL, NULL);
			ignore_output(out);

			tell_wallet_to_remote(tx, i, txid,
					      tx_blockheight,
					      local_script,
					      possible_remote_per_commitment_point,
					      option_static_remotekey);
			local_script = NULL;
			to_us_output = i;
		}
	}

search_done:
	if (to_us_output == -1) {
		status_broken("FUNDS LOST.  Unknown commitment #%"PRIu64"!",
			      commit_num);
		init_reply("ERROR: FUNDS LOST.  Unknown commitment!");
	} else {
		status_broken("ERROR: Unknown commitment #%"PRIu64
			      ", recovering our funds!",
			      commit_num);
		init_reply("ERROR: Unknown commitment, recovering our funds!");
	}

	/* Tell master to give up on HTLCs immediately. */
	for (size_t i = 0; i < tal_count(htlcs); i++) {
		u8 *msg;

		if (!tell_if_missing[i])
			continue;

		msg = towire_onchain_missing_htlc_output(NULL, &htlcs[i]);
		wire_sync_write(REQ_FD, take(msg));
	}

	wait_for_resolved(tx->chainparams, outs);
}

int main(int argc, char *argv[])
{
	setup_locale();

	const tal_t *ctx = tal(NULL, char);
	u8 *msg;
	struct pubkey remote_per_commit_point, old_remote_per_commit_point;
	enum side funder;
	struct basepoints basepoints[NUM_SIDES];
	struct shachain shachain;
	struct bitcoin_tx *tx;
	struct tracked_output **outs;
	struct bitcoin_txid our_broadcast_txid, txid, tmptxid;
	secp256k1_ecdsa_signature *remote_htlc_sigs;
	struct amount_sat funding;
	u64 num_htlcs;
	u8 *scriptpubkey[NUM_SIDES];
	struct htlc_stub *htlcs;
	bool *tell_if_missing, *tell_immediately;
	u32 tx_blockheight;
	struct pubkey *possible_remote_per_commitment_point;

	subdaemon_setup(argc, argv);

	status_setup_sync(REQ_FD);

	missing_htlc_msgs = tal_arr(ctx, u8 *, 0);

	msg = wire_sync_read(tmpctx, REQ_FD);
	if (!fromwire_onchain_init(tmpctx, msg,
				   &shachain,
				   &chainparams,
				   &funding,
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
				   &funder,
				   &basepoints[LOCAL],
				   &basepoints[REMOTE],
				   &tx,
				   &tx_blockheight,
				   &reasonable_depth,
				   &remote_htlc_sigs,
				   &num_htlcs,
				   &min_possible_feerate,
				   &max_possible_feerate,
				   &possible_remote_per_commitment_point,
				   &option_static_remotekey)) {
		master_badmsg(WIRE_ONCHAIN_INIT, msg);
	}

	tx->chainparams = chainparams;

	status_debug("delayed_to_us_feerate = %u, htlc_feerate = %u, "
		     "penalty_feerate = %u", delayed_to_us_feerate,
		     htlc_feerate, penalty_feerate);
	bitcoin_txid(tx, &txid);
	/* We need to keep tx around, but there's only one: not really a leak */
	tal_steal(ctx, notleak(tx));

	/* FIXME: Filter as we go, don't load them all into mem! */
	htlcs = tal_arr(tmpctx, struct htlc_stub, num_htlcs);
	tell_if_missing = tal_arr(htlcs, bool, num_htlcs);
	tell_immediately = tal_arr(htlcs, bool, num_htlcs);
	if (!htlcs || !tell_if_missing || !tell_immediately)
		status_failed(STATUS_FAIL_INTERNAL_ERROR,
			      "Can't allocate %"PRIu64" htlcs", num_htlcs);

	for (u64 i = 0; i < num_htlcs; i++) {
		msg = wire_sync_read(tmpctx, REQ_FD);
		if (!fromwire_onchain_htlc(msg, &htlcs[i],
					   &tell_if_missing[i],
					   &tell_immediately[i]))
			master_badmsg(WIRE_ONCHAIN_HTLC, msg);
	}

	outs = tal_arr(ctx, struct tracked_output *, 0);
	bitcoin_tx_input_get_txid(tx, 0, &tmptxid);
	new_tracked_output(tx->chainparams, &outs, &tmptxid,
			   0, /* We don't care about funding blockheight */
			   FUNDING_TRANSACTION,
			   tx->wtx->inputs[0].index,
			   funding,
			   FUNDING_OUTPUT, NULL, NULL, NULL);

	status_debug("Remote per-commit point: %s",
		     type_to_string(tmpctx, struct pubkey,
				    &remote_per_commit_point));
	status_debug("Old remote per-commit point: %s",
		     type_to_string(tmpctx, struct pubkey,
				    &old_remote_per_commit_point));

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
		handle_mutual_close(tx->chainparams, &txid, outs);
	else {
		/* BOLT #5:
		 *
		 * 2. The bad way (*unilateral close*): something goes wrong,
		 *    possibly without evil intent on either side. Perhaps one
		 *    party crashed, for instance. One side publishes its
		 *    *latest commitment transaction*.
		 */
		struct secret revocation_preimage;
		commit_num = unmask_commit_number(tx, funder,
						  &basepoints[LOCAL].payment,
						  &basepoints[REMOTE].payment);

		status_debug("commitnum = %"PRIu64
			     ", revocations_received = %"PRIu64,
			     commit_num, revocations_received(&shachain));

		if (is_local_commitment(&txid, &our_broadcast_txid))
			handle_our_unilateral(tx, tx_blockheight, &txid,
					      basepoints,
					      htlcs,
					      tell_if_missing, tell_immediately,
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
			handle_their_cheat(tx, &txid,
					   tx_blockheight,
					   &revocation_preimage,
					   basepoints,
					   htlcs,
					   tell_if_missing, tell_immediately,
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
						&txid,
						&old_remote_per_commit_point,
						basepoints,
						htlcs,
						tell_if_missing,
						tell_immediately,
						outs);
		} else if (commit_num == revocations_received(&shachain) + 1) {
			status_debug("Their unilateral tx, new commit point");
			handle_their_unilateral(tx, tx_blockheight,
						&txid,
						&remote_per_commit_point,
						basepoints,
						htlcs,
						tell_if_missing,
						tell_immediately,
						outs);
		} else {
			handle_unknown_commitment(tx, tx_blockheight,
						  commit_num,
						  &txid,
						  possible_remote_per_commitment_point,
						  basepoints,
						  htlcs,
						  tell_if_missing,
						  outs);
		}
	}

	/* We're done! */
	tal_free(ctx);
	daemon_shutdown();

	return 0;
}
