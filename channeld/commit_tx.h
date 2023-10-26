#ifndef LIGHTNING_CHANNELD_COMMIT_TX_H
#define LIGHTNING_CHANNELD_COMMIT_TX_H
#include "config.h"
#include <channeld/channeld_htlc.h>
#include <common/initial_commit_tx.h>

struct keyset;

/**
 * commit_tx_num_untrimmed: how many of these htlc outputs will commit tx have?
 * @htlcs: tal_arr of HTLCs
 * @feerate_per_kw: feerate to use
 * @dust_limit: dust limit below which to trim outputs.
 * @option_anchor_outputs: does option_anchor_outputs apply to this channel?
 * @side: from which side's point of view
 * @option_anchor_outputs: does option_anchor_outputs apply to this channel?
 * @option_anchors_zero_fee_htlc_tx: does option_anchors_zero_fee_htlc_tx apply to this channel?
 *
 * We need @side because HTLC fees are different for offered and
 * received HTLCs.
 */
size_t commit_tx_num_untrimmed(const struct htlc **htlcs,
			       u32 feerate_per_kw,
			       struct amount_sat dust_limit,
			       bool option_anchors_zero_fee_htlc_tx,
			       bool option_anchor_outputs,
			       enum side side);

/**
 * commit_tx_amount_trimmed: what's the sum of trimmed htlc amounts?
 * @htlcs: tal_arr of HTLCs
 * @feerate_per_kw: feerate to use
 * @dust_limit: dust limit below which to trim outputs.
 * @option_anchor_outputs: does option_anchor_outputs apply to this channel?
 * @side: from which side's point of view
 * @amt: returned, total value trimmed from this commitment
 *
 * We need @side because HTLC fees are different for offered and
 * received HTLCs.
 *
 * Returns false if unable to calculate amount trimmed.
 */
bool commit_tx_amount_trimmed(const struct htlc **htlcs,
			      u32 feerate_per_kw,
			      struct amount_sat dust_limit,
			      bool option_anchor_outputs,
			      bool option_anchors_zero_fee_htlc_tx,
			      enum side side,
			      struct amount_msat *amt);
/**
 * commit_tx: create (unsigned) commitment tx to spend the funding tx output
 * @ctx: context to allocate transaction and @htlc_map from.
 * @funding, @funding_sats: funding outpoint and amount
 * @local_funding_key, @remote_funding_key: keys for funding input.
 * @opener: is the LOCAL or REMOTE paying the fee?
 * @keyset: keys derived for this commit tx.
 * @feerate_per_kw: feerate to use
 * @dust_limit: dust limit below which to trim outputs.
 * @self_pay: amount to pay directly to self
 * @other_pay: amount to pay directly to the other side
 * @htlcs: tal_arr of htlcs committed by transaction (some may be trimmed)
 * @htlc_map: outputed map of outnum->HTLC (NULL for direct outputs).
 * @obscured_commitment_number: number to encode in commitment transaction
 * @direct_outputs: If non-NULL, fill with pointers to the direct (non-HTLC) outputs (or NULL if none).
 * @option_anchor_outputs: does option_anchor_outputs apply to this channel?
 * @option_anchors_zero_fee_htlc_tx: does option_anchors_zero_fee_htlc_tx apply to this channel?
 * @side: side to generate commitment transaction for.
 * @anchor_outnum: set to index of local anchor, or -1 if none.
 *
 * We need to be able to generate the remote side's tx to create signatures,
 * but the BOLT is expressed in terms of generating our local commitment
 * transaction, so we carefully use the terms "self" and "other" here.
 */
struct bitcoin_tx *commit_tx(const tal_t *ctx,
			     const struct bitcoin_outpoint *funding,
			     struct amount_sat funding_sats,
			     const struct pubkey *local_funding_key,
			     const struct pubkey *remote_funding_key,
			     enum side opener,
			     u16 to_self_delay,
			     u32 lease_expiry,
			     u32 blockheight,
			     const struct keyset *keyset,
			     u32 feerate_per_kw,
			     struct amount_sat dust_limit,
			     struct amount_msat self_pay,
			     struct amount_msat other_pay,
			     const struct htlc **htlcs,
			     const struct htlc ***htlcmap,
			     struct wally_tx_output *direct_outputs[NUM_SIDES],
			     u64 obscured_commitment_number,
			     bool option_anchor_outputs,
			     bool option_anchors_zero_fee_htlc_tx,
			     enum side side,
			     int *anchor_outnum);

#endif /* LIGHTNING_CHANNELD_COMMIT_TX_H */
