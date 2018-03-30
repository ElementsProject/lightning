#ifndef LIGHTNING_CHANNELD_COMMIT_TX_H
#define LIGHTNING_CHANNELD_COMMIT_TX_H
#include "config.h"
#include <bitcoin/pubkey.h>
#include <channeld/channeld_htlc.h>
#include <common/htlc.h>
#include <common/initial_commit_tx.h>

struct keyset;

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
			       u32 feerate_per_kw, u64 dust_limit_satoshis,
			       enum side side);

/**
 * commit_tx: create (unsigned) commitment tx to spend the funding tx output
 * @ctx: context to allocate transaction and @htlc_map from.
 * @funding_txid, @funding_out, @funding_satoshis: funding outpoint.
 * @funder: is the LOCAL or REMOTE paying the fee?
 * @keyset: keys derived for this commit tx.
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
			     const struct bitcoin_txid *funding_txid,
			     unsigned int funding_txout,
			     u64 funding_satoshis,
			     enum side funder,
			     u16 to_self_delay,
			     const struct keyset *keyset,
			     u32 feerate_per_kw,
			     u64 dust_limit_satoshis,
			     u64 self_pay_msat,
			     u64 other_pay_msat,
			     const struct htlc **htlcs,
			     const struct htlc ***htlcmap,
			     u64 obscured_commitment_number,
			     enum side side);

#endif /* LIGHTNING_CHANNELD_COMMIT_TX_H */
