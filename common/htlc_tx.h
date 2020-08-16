#ifndef LIGHTNING_COMMON_HTLC_TX_H
#define LIGHTNING_COMMON_HTLC_TX_H
#include "config.h"
#include <bitcoin/chainparams.h>
#include <common/amount.h>
#include <common/htlc.h>
#include <common/utils.h>

struct bitcoin_signature;
struct bitcoin_txid;
struct keyset;
struct preimage;
struct pubkey;
struct ripemd160;

/** Attempt to compute the elements overhead given a base bitcoin size.
 *
 * The overhead consists of 2 empty proofs for the transaction, 6 bytes of
 * proofs per input and 35 bytes per output. In addition the explicit fee
 * output will add 9 bytes and the per output overhead as well.
 */
static inline size_t elements_add_overhead(size_t weight, size_t incount,
					   size_t outcount)
{
	if (chainparams->is_elements) {
		/* Each transaction has surjection and rangeproof (both empty
		 * for us as long as we use unblinded L-BTC transactions). */
		weight += 2 * 4;
		/* For elements we also need to add the fee output and the
		 * overhead for rangeproofs into the mix. */
		weight += (8 + 1) * 4; /* Bitcoin style output */

		/* All outputs have a bit of elements overhead */
		weight += (32 + 1 + 1 + 1) * 4 * (outcount + 1); /* Elements added fields */

		/* Inputs have 6 bytes of blank proofs attached. */
		weight += 6 * incount;
	}
	return weight;
}

static inline struct amount_sat htlc_timeout_fee(u32 feerate_per_kw)
{
	/* BOLT #3:
	 *
	 * The fee for an HTLC-timeout transaction:
	 *  - MUST BE calculated to match:
	 *    1. Multiply `feerate_per_kw` by 663 and divide by 1000 (rounding
	 *       down).
	 */
	return amount_tx_fee(elements_add_overhead(663, 1, 1), feerate_per_kw);
}

static inline struct amount_sat htlc_success_fee(u32 feerate_per_kw)
{
	/* BOLT #3:
	 *
	 * The fee for an HTLC-success transaction:
	 *   - MUST BE calculated to match:
	 *     1. Multiply `feerate_per_kw` by 703 and divide by 1000 (rounding
	 *     down).
	 */
	return amount_tx_fee(elements_add_overhead(703, 1, 1), feerate_per_kw);
}

/* Create HTLC-success tx to spend a received HTLC commitment tx
 * output; doesn't fill in input witness. */
struct bitcoin_tx *htlc_success_tx(const tal_t *ctx,
				   const struct chainparams *chainparams,
				   const struct bitcoin_txid *commit_txid,
				   unsigned int commit_output_number,
				   const u8 *commit_wscript,
				   struct amount_msat htlc_msatoshi,
				   u16 to_self_delay,
				   u32 feerate_per_kw,
				   const struct keyset *keyset);

/* Fill in the witness for HTLC-success tx produced above. */
void htlc_success_tx_add_witness(struct bitcoin_tx *htlc_success,
				 const struct abs_locktime *htlc_abstimeout,
				 const struct pubkey *localkey,
				 const struct pubkey *remotekey,
				 const struct bitcoin_signature *localsig,
				 const struct bitcoin_signature *remotesig,
				 const struct preimage *payment_preimage,
				 const struct pubkey *revocationkey);

/* Create HTLC-timeout tx to spend an offered HTLC commitment tx
 * output; doesn't fill in input witness. */
struct bitcoin_tx *htlc_timeout_tx(const tal_t *ctx,
				   const struct chainparams *chainparams,
				   const struct bitcoin_txid *commit_txid,
				   unsigned int commit_output_number,
				   const u8 *commit_wscript,
				   struct amount_msat htlc_msatoshi,
				   u32 cltv_expiry,
				   u16 to_self_delay,
				   u32 feerate_per_kw,
				   const struct keyset *keyset);

/* Fill in the witness for HTLC-timeout tx produced above. */
void htlc_timeout_tx_add_witness(struct bitcoin_tx *htlc_timeout,
				 const struct pubkey *localkey,
				 const struct pubkey *remotekey,
				 const struct sha256 *payment_hash,
				 const struct pubkey *revocationkey,
				 const struct bitcoin_signature *localsig,
				 const struct bitcoin_signature *remotesig);


/* Generate the witness script for an HTLC the other side offered:
 * scriptpubkey_p2wsh(ctx, wscript) gives the scriptpubkey */
u8 *htlc_received_wscript(const tal_t *ctx,
			  const struct ripemd160 *ripemd,
			  const struct abs_locktime *expiry,
			  const struct keyset *keyset);

/* Generate the witness script for an HTLC this side offered:
 * scriptpubkey_p2wsh(ctx, wscript) gives the scriptpubkey */
u8 *htlc_offered_wscript(const tal_t *ctx,
			 const struct ripemd160 *ripemd,
			 const struct keyset *keyset);

#endif /* LIGHTNING_COMMON_HTLC_TX_H */
