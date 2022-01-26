/* Commit tx without HTLC support; needed for openingd. */
#ifndef LIGHTNING_COMMON_INITIAL_COMMIT_TX_H
#define LIGHTNING_COMMON_INITIAL_COMMIT_TX_H
#include "config.h"
#include <bitcoin/chainparams.h>
#include <bitcoin/pubkey.h>
#include <bitcoin/tx.h>
#include <common/htlc.h>
#include <common/utils.h>

struct bitcoin_outpoint;
struct keyset;
struct wally_tx_output;

/* BOLT #3:
 *
 * This obscures the number of commitments made on the channel in the
 * case of unilateral close, yet still provides a useful index for
 * both nodes (who know the `payment_basepoint`s) to quickly find a
 * revoked commitment transaction.
 */
u64 commit_number_obscurer(const struct pubkey *opener_payment_basepoint,
			   const struct pubkey *accepter_payment_basepoint);


/* The base weight of a commitment tx */
static inline size_t commit_tx_base_weight(size_t num_untrimmed_htlcs,
					   bool option_anchor_outputs)
{
	size_t weight;

	/* BOLT #3:
	 *
	 * The base fee for a commitment transaction:
	 *  - MUST be calculated to match:
	 *    1. Start with `weight` = 724 (1124 if `option_anchors` applies).
	 */
	if (option_anchor_outputs)
		weight = 1124;
	else
		weight = 724;

	/* BOLT #3:
	 *
	 *    2. For each committed HTLC, if that output is not trimmed as
	 *       specified in [Trimmed Outputs](#trimmed-outputs), add 172
	 *       to `weight`.
	 */
	weight += 172 * num_untrimmed_htlcs;

	/* Extra fields for Elements */
	weight += elements_tx_overhead(chainparams, 1, 1);

	return weight;
}

/* Helper to calculate the base fee if we have this many htlc outputs */
static inline struct amount_sat commit_tx_base_fee(u32 feerate_per_kw,
						   size_t num_untrimmed_htlcs,
						   bool option_anchor_outputs)
{
	return amount_tx_fee(feerate_per_kw,
			     commit_tx_base_weight(num_untrimmed_htlcs,
						   option_anchor_outputs));
}

/**
 * initial_commit_tx: create (unsigned) commitment tx to spend the funding tx output
 * @ctx: context to allocate transaction and @htlc_map from.
 * @funding, @funding_sats: funding outpoint and amount
 * @funding_wscript: scriptPubkey of the funding output
 * @funding_keys: funding bitcoin keys
 * @opener: is the LOCAL or REMOTE paying the fee?
 * @keyset: keys derived for this commit tx.
 * @feerate_per_kw: feerate to use
 * @dust_limit: dust limit below which to trim outputs.
 * @self_pay: amount to pay directly to self
 * @other_pay: amount to pay directly to the other side
 * @self_reserve: reserve the other side insisted we have
 * @obscured_commitment_number: number to encode in commitment transaction
 * @direct_outputs: If non-NULL, fill with pointers to the direct (non-HTLC) outputs (or NULL if none).
 * @side: side to generate commitment transaction for.
 * @option_anchor_outputs: does option_anchor_outputs apply to this channel?
 * @err_reason: When NULL is returned, this will point to a human readable reason.
 *
 * We need to be able to generate the remote side's tx to create signatures,
 * but the BOLT is expressed in terms of generating our local commitment
 * transaction, so we carefully use the terms "self" and "other" here.
 */
struct bitcoin_tx *initial_commit_tx(const tal_t *ctx,
				     const struct bitcoin_outpoint *funding,
				     struct amount_sat funding_sats,
				     const struct pubkey funding_key[NUM_SIDES],
				     enum side opener,
				     u16 to_self_delay,
				     const struct keyset *keyset,
				     u32 feerate_per_kw,
				     struct amount_sat dust_limit,
				     struct amount_msat self_pay,
				     struct amount_msat other_pay,
				     struct amount_sat self_reserve,
				     u64 obscured_commitment_number,
				     struct wally_tx_output *direct_outputs[NUM_SIDES],
				     enum side side,
				     u32 csv_lock,
				     bool option_anchor_outputs,
				     char** err_reason);

/* try_subtract_fee - take away this fee from the opener (and return true), or all if insufficient (and return false). */
bool try_subtract_fee(enum side opener, enum side side,
		      struct amount_sat base_fee,
		      struct amount_msat *self,
		      struct amount_msat *other);

/* Generate the witness script for the to-self output:
 * scriptpubkey_p2wsh(ctx, wscript) gives the scriptpubkey */
u8 *to_self_wscript(const tal_t *ctx,
		    u16 to_self_delay,
		    u32 csv,
		    const struct keyset *keyset);

/* To-other is simply: scriptpubkey_p2wpkh(tx, keyset->other_payment_key) */

/* If we determine we need one, append this anchor output */
void tx_add_anchor_output(struct bitcoin_tx *tx,
			  const struct pubkey *funding_key);

#endif /* LIGHTNING_COMMON_INITIAL_COMMIT_TX_H */
