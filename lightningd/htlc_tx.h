#ifndef LIGHTNING_LIGHTNINGD_HTLC_TX_H
#define LIGHTNING_LIGHTNINGD_HTLC_TX_H
#include "config.h"
#include <daemon/htlc.h>

struct preimage;
struct pubkey;
struct sha256_double;

/* Create HTLC-success tx to spend a received HTLC commitment tx
 * output; doesn't fill in input witness. */
struct bitcoin_tx *htlc_success_tx(const tal_t *ctx,
				   const struct sha256_double *commit_txid,
				   unsigned int commit_output_number,
				   const struct htlc *received_htlc,
				   u16 to_self_delay,
				   const struct pubkey *revocation_pubkey,
				   const struct pubkey *local_delayedkey,
				   u64 feerate_per_kw);

/* Fill in the witness for HTLC-success tx produced above. */
void htlc_success_tx_add_witness(struct bitcoin_tx *htlc_success,
				 const struct abs_locktime *htlc_abstimeout,
				 const struct pubkey *localkey,
				 const struct pubkey *remotekey,
				 const secp256k1_ecdsa_signature *localsig,
				 const secp256k1_ecdsa_signature *remotesig,
				 const struct preimage *payment_preimage,
				 const struct pubkey *revocationkey);

/* Create HTLC-timeout tx to spend an offered HTLC commitment tx
 * output; doesn't fill in input witness. */
struct bitcoin_tx *htlc_timeout_tx(const tal_t *ctx,
				   const struct sha256_double *commit_txid,
				   unsigned int commit_output_number,
				   const struct htlc *offered_htlc,
				   u16 to_self_delay,
				   const struct pubkey *revocation_pubkey,
				   const struct pubkey *local_delayedkey,
				   u64 feerate_per_kw);

/* Fill in the witness for HTLC-timeout tx produced above. */
void htlc_timeout_tx_add_witness(struct bitcoin_tx *htlc_timeout,
				 const struct pubkey *localkey,
				 const struct pubkey *remotekey,
				 const struct sha256 *payment_hash,
				 const struct pubkey *revocationkey,
				 const secp256k1_ecdsa_signature *localsig,
				 const secp256k1_ecdsa_signature *remotesig);

#endif /* LIGHTNING_LIGHTNINGD_HTLC_TX_H */
