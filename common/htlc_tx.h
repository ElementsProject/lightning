#ifndef LIGHTNING_COMMON_HTLC_TX_H
#define LIGHTNING_COMMON_HTLC_TX_H
#include "config.h"
#include <bitcoin/chainparams.h>
#include <bitcoin/tx.h>
#include <common/htlc.h>
#include <common/utils.h>

struct bitcoin_signature;
struct bitcoin_outpoint;
struct keyset;
struct preimage;
struct pubkey;
struct ripemd160;

static inline struct amount_sat htlc_timeout_fee(u32 feerate_per_kw,
						 bool option_anchor_outputs,
						 bool option_anchors_zero_fee_htlc_tx)
{
	/* BOLT #3:
	 *
	 * The fee for an HTLC-timeout transaction:
	 * - If `option_anchors_zero_fee_htlc_tx` applies:
	 *   1. MUST be 0.
	 * - Otherwise, MUST be calculated to match:
	 *   1. Multiply `feerate_per_kw` by 663 and divide by 1000 (rounding down).
	 */
	u32 base;

	if (option_anchors_zero_fee_htlc_tx)
		return AMOUNT_SAT(0);

	/* FIXME: Older bolt had "(666 if `option_anchor_outputs` applies)" */
	if (option_anchor_outputs)
		base = 666;
	else
		base = 663;
	return amount_tx_fee(base + elements_tx_overhead(chainparams, 1, 1),
			     feerate_per_kw);
}

static inline struct amount_sat htlc_success_fee(u32 feerate_per_kw,
						 bool option_anchor_outputs,
						 bool option_anchors_zero_fee_htlc_tx)
{
	/* BOLT #3:
	 *
	 * The fee for an HTLC-success transaction:
	 * - If `option_anchors_zero_fee_htlc_tx` applies:
	 *   1. MUST be 0.
	 * - Otherwise, MUST be calculated to match:
	 *   1. Multiply `feerate_per_kw` by 703 and divide by 1000 (rounding down).
	 */
	u32 base;

	if (option_anchors_zero_fee_htlc_tx)
		return AMOUNT_SAT(0);

	/* FIXME: older bolt used to say "(706 if `option_anchor_outputs` applies) */
	if (option_anchor_outputs)
		base = 706;
	else
		base = 703;
	return amount_tx_fee(base + elements_tx_overhead(chainparams, 1, 1),
			     feerate_per_kw);
}

/* Create HTLC-success tx to spend a received HTLC commitment tx
 * output; doesn't fill in input witness. */
struct bitcoin_tx *htlc_success_tx(const tal_t *ctx,
				   const struct chainparams *chainparams,
				   const struct bitcoin_outpoint *commit,
				   const u8 *commit_wscript,
				   struct amount_msat htlc_msatoshi,
				   u16 to_self_delay,
				   u32 feerate_per_kw,
				   const struct keyset *keyset,
				   bool option_anchor_outputs,
				   bool option_anchors_zero_fee_htlc_tx);

/* Fill in the witness for HTLC-success tx produced above. */
void htlc_success_tx_add_witness(struct bitcoin_tx *htlc_success,
				 const struct abs_locktime *htlc_abstimeout,
				 const struct pubkey *localkey,
				 const struct pubkey *remotekey,
				 const struct bitcoin_signature *localsig,
				 const struct bitcoin_signature *remotesig,
				 const struct preimage *payment_preimage,
				 const struct pubkey *revocationkey,
				 bool option_anchor_outputs,
				 bool option_anchors_zero_fee_htlc_tx);

/* Create HTLC-timeout tx to spend an offered HTLC commitment tx
 * output; doesn't fill in input witness. */
struct bitcoin_tx *htlc_timeout_tx(const tal_t *ctx,
				   const struct chainparams *chainparams,
				   const struct bitcoin_outpoint *commit,
				   const u8 *commit_wscript,
				   struct amount_msat htlc_msatoshi,
				   u32 cltv_expiry,
				   u16 to_self_delay,
				   u32 feerate_per_kw,
				   const struct keyset *keyset,
				   bool option_anchor_outputs,
				   bool option_anchors_zero_fee_htlc_tx);

/* Fill in the witness for HTLC-timeout tx produced above. */
void htlc_timeout_tx_add_witness(struct bitcoin_tx *htlc_timeout,
				 const struct pubkey *localkey,
				 const struct pubkey *remotekey,
				 const struct sha256 *payment_hash,
				 const struct pubkey *revocationkey,
				 const struct bitcoin_signature *localsig,
				 const struct bitcoin_signature *remotesig,
				 bool option_anchor_outputs,
				 bool option_anchors_zero_fee_htlc_tx);

/* Generate the witness script for an HTLC the other side offered:
 * scriptpubkey_p2wsh(ctx, wscript) gives the scriptpubkey */
u8 *htlc_received_wscript(const tal_t *ctx,
			  const struct ripemd160 *ripemd,
			  const struct abs_locktime *expiry,
			  const struct keyset *keyset,
			  bool option_anchor_outputs,
			  bool option_anchors_zero_fee_htlc_tx);

/* Generate the witness script for an HTLC this side offered:
 * scriptpubkey_p2wsh(ctx, wscript) gives the scriptpubkey */
u8 *htlc_offered_wscript(const tal_t *ctx,
			 const struct ripemd160 *ripemd,
			 const struct keyset *keyset,
			 bool option_anchor_outputs,
			 bool option_anchors_zero_fee_htlc_tx);

/* Low-level HTLC tx creator */
struct bitcoin_tx *htlc_tx(const tal_t *ctx,
			   const struct chainparams *chainparams,
			   const struct bitcoin_outpoint *commit,
			   const u8 *commit_wscript,
			   struct amount_sat amount,
			   const u8 *htlc_tx_wscript,
			   struct amount_sat htlc_fee,
			   u32 locktime,
			   bool option_anchor_outputs,
			   bool option_anchors_zero_fee_htlc_tx);
#endif /* LIGHTNING_COMMON_HTLC_TX_H */
