/* Commit tx without HTLC support; needed for openingd. */
#ifndef LIGHTNING_COMMON_INITIAL_COMMIT_TX_H
#define LIGHTNING_COMMON_INITIAL_COMMIT_TX_H
#include "config.h"
#include <bitcoin/chainparams.h>
#include <bitcoin/pubkey.h>
#include <common/amount.h>
#include <common/htlc.h>
#include <common/utils.h>

struct bitcoin_txid;
struct keyset;

/* BOLT #3:
 *
 * This obscures the number of commitments made on the channel in the
 * case of unilateral close, yet still provides a useful index for
 * both nodes (who know the `payment_basepoint`s) to quickly find a
 * revoked commitment transaction.
 */
u64 commit_number_obscurer(const struct pubkey *opener_payment_basepoint,
			   const struct pubkey *accepter_payment_basepoint);

/* Helper to calculate the base fee if we have this many htlc outputs */
static inline struct amount_sat commit_tx_base_fee(u32 feerate_per_kw,
						   size_t num_untrimmed_htlcs)
{
	u64 weight;

	/* BOLT #3:
	 *
	 * The base fee for a commitment transaction:
	 *  - MUST be calculated to match:
	 *    1. Start with `weight` = 724.
	 */
	weight = 724;

	/* BOLT #3:
	 *
	 *    2. For each committed HTLC, if that output is not trimmed as
	 *       specified in [Trimmed Outputs](#trimmed-outputs), add 172
	 *       to `weight`.
	 */
	weight += 172 * num_untrimmed_htlcs;

	if (chainparams->is_elements) {
		/* Each transaction has surjection and rangeproof (both empty
		 * for us as long as we use unblinded L-BTC transactions). */
		weight += 2 * 4;

		/* Inputs have 6 bytes of blank proofs attached. This TX only
		 * has a single input. */
		weight += 6;

		/* Each direct output has a bit more weight to it */
		weight += (32 + 1 + 1 + 1) * 4 * 2; /* Elements added fields */

		/* Each HTLC output also carries a bit more weight */
		weight += (32 + 1 + 1 + 1) * 4 * num_untrimmed_htlcs;

		/* For elements we also need to add the fee output and the
		 * overhead for rangeproofs into the mix. */
		weight += (8 + 1) * 4; /* Bitcoin style output */
		weight += (32 + 1 + 1 + 1) * 4; /* Elements added fields */
	}

	/* BOLT #3:
	 *
	 *    3. Multiply `feerate_per_kw` by `weight`, divide by 1000 (rounding
	 *    down).
	 */
	return amount_tx_fee(feerate_per_kw, weight);
}

/**
 * initial_commit_tx: create (unsigned) commitment tx to spend the funding tx output
 * @ctx: context to allocate transaction and @htlc_map from.
 * @funding_txid, @funding_out, @funding: funding outpoint.
 * @funder: is the LOCAL or REMOTE paying the fee?
 * @keyset: keys derived for this commit tx.
 * @feerate_per_kw: feerate to use
 * @dust_limit: dust limit below which to trim outputs.
 * @self_pay: amount to pay directly to self
 * @other_pay: amount to pay directly to the other side
 * @self_reserve: reserve the other side insisted we have
 * @obscured_commitment_number: number to encode in commitment transaction
 * @direct_outputs: If non-NULL, fill with pointers to the direct (non-HTLC) outputs (or NULL if none).
 * @side: side to generate commitment transaction for.
 * @err_reason: When NULL is returned, this will point to a human readable reason.
 *
 * We need to be able to generate the remote side's tx to create signatures,
 * but the BOLT is expressed in terms of generating our local commitment
 * transaction, so we carefully use the terms "self" and "other" here.
 */
struct bitcoin_tx *initial_commit_tx(const tal_t *ctx,
				     const struct bitcoin_txid *funding_txid,
				     unsigned int funding_txout,
				     struct amount_sat funding,
				     enum side funder,
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
				     char** err_reason);

/* try_subtract_fee - take away this fee from the funder (and return true), or all if insufficient (and return false). */
bool try_subtract_fee(enum side funder, enum side side,
		      struct amount_sat base_fee,
		      struct amount_msat *self,
		      struct amount_msat *other);

/* Generate the witness script for the to-self output:
 * scriptpubkey_p2wsh(ctx, wscript) gives the scriptpubkey */
u8 *to_self_wscript(const tal_t *ctx,
		    u16 to_self_delay,
		    const struct keyset *keyset);

/* To-other is simply: scriptpubkey_p2wpkh(tx, keyset->other_payment_key) */

#endif /* LIGHTNING_COMMON_INITIAL_COMMIT_TX_H */
