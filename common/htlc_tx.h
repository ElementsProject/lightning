#ifndef LIGHTNING_COMMON_HTLC_TX_H
#define LIGHTNING_COMMON_HTLC_TX_H
#include "config.h"
#include <common/amount.h>
#include <common/htlc.h>

struct keyset;
struct preimage;
struct pubkey;

static inline struct amount_sat htlc_timeout_fee(u32 feerate_per_kw)
{
	/* BOLT #3:
	 *
	 * The fee for an HTLC-timeout transaction:
	 *  - MUST BE calculated to match:
	 *    1. Multiply `feerate_per_kw` by 663 and divide by 1000 (rounding
	 *       down).
	 */
	return amount_tx_fee(663, feerate_per_kw);
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
	return amount_tx_fee(703, feerate_per_kw);
}

/* Create HTLC-success tx to spend a received HTLC commitment tx
 * output; doesn't fill in input witness. */
struct bitcoin_tx *htlc_success_tx(const tal_t *ctx,
				   const struct bitcoin_txid *commit_txid,
				   unsigned int commit_output_number,
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
				   const struct bitcoin_txid *commit_txid,
				   unsigned int commit_output_number,
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
