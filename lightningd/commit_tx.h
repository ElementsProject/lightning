#ifndef LIGHTNING_LIGHTNINGD_COMMIT_TX_H
#define LIGHTNING_LIGHTNINGD_COMMIT_TX_H
#include "config.h"
#include <daemon/htlc.h>

struct pubkey;
struct sha256_double;

/* BOLT #3:
 *
 * This obscures the number of commitments made on the channel in the
 * case of unilateral close, yet still provides a useful index for
 * both nodes (who know the `payment_basepoint`s) to quickly find a
 * revoked commitment transaction.
 */
u64 commit_number_obscurer(const struct pubkey *opener_payment_basepoint,
			   const struct pubkey *accepter_payment_basepoint);

/* commit_tx needs to know these so it knows what outputs to trim */
u64 htlc_success_fee(u64 feerate_per_kw);
u64 htlc_timeout_fee(u64 feerate_per_kw);

/**
 * commit_tx_num_untrimmed: how many of these htlc outputs will commit tx have?
 * @htlcs: tal_arr of HTLCs
 * @feerate_per_kw: feerate to use
 * @dust_limit_satoshis: dust limit below which to trim outputs.
 * @side: from which side's point of view
 *
 * We need @side because HTLC fees are different for offered and
 * received HTLCs.
 */
size_t commit_tx_num_untrimmed(const struct htlc **htlcs,
			       u64 feerate_per_kw, u64 dust_limit_satoshis,
			       enum side side);

/* Helper to calculate the base fee if we add this extra htlc */
u64 commit_tx_base_fee(u64 feerate_per_kw, size_t num_untrimmed_htlcs);

/**
 * commit_tx: create (unsigned) commitment tx to spend the funding tx output
 * @ctx: context to allocate transaction and @htlc_map from.
 * @funding_txid, @funding_out, @funding_satoshis: funding outpoint.
 * @funder: is the LOCAL or REMOTE paying the fee?
 * @revocation_pubkey: revocation pubkey for this @side
 * @self_delayedey: pubkey for delayed payments to this @side
 * @selfkey: pubkey for HTLC payments to this @side
 * @otherkey: pubkey for direct and HTLC payments to other side @side
 * @feerate_per_kw: feerate to use
 * @dust_limit_satoshis: dust limit below which to trim outputs.
 * @self_pay_msat: amount to pay directly to self
 * @other_pay_msat: amount to pay directly to the other side
 * @htlcs: tal_arr of htlcs committed by transaction (some may be trimmed)
 * @htlc_map: outputed map of outnum->HTLC (NULL for direct outputs), or NULL.
 * @obscured_commitment_number: number to encode in commitment transaction
 * @side: side to generate commitment transaction for.
 *
 * We need to be able to generate the remote side's tx to create signatures,
 * but the BOLT is expressed in terms of generating our local commitment
 * transaction, so we carefully use the terms "self" and "other" here.
 */
struct bitcoin_tx *commit_tx(const tal_t *ctx,
			     const struct sha256_double *funding_txid,
			     unsigned int funding_txout,
			     u64 funding_satoshis,
			     enum side funder,
			     u16 to_self_delay,
			     const struct pubkey *revocation_pubkey,
			     const struct pubkey *self_delayedkey,
			     const struct pubkey *selfkey,
			     const struct pubkey *otherkey,
			     u64 feerate_per_kw,
			     u64 dust_limit_satoshis,
			     u64 self_pay_msat,
			     u64 other_pay_msat,
			     const struct htlc **htlcs,
			     const struct htlc ***htlcmap,
			     u64 obscured_commitment_number,
			     enum side side);
#endif /* LIGHTNING_LIGHTNINGD_COMMIT_TX_H */
