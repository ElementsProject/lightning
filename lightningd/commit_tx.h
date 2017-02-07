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
 * both nodes (who know the payment-basepoints) to quickly find a
 * revoked commitment transaction.
 */
u64 commit_number_obscurer(const struct pubkey *opener_payment_basepoint,
			   const struct pubkey *accepter_payment_basepoint);

/* commit_tx needs to know these so it knows what outputs to trim */
u64 htlc_success_fee(u64 feerate_per_kw);
u64 htlc_timeout_fee(u64 feerate_per_kw);

/* Create commitment tx to spend the funding tx output; doesn't fill in
 * input scriptsig. */
struct bitcoin_tx *commit_tx(const tal_t *ctx,
			     const struct sha256_double *funding_txid,
			     unsigned int funding_txout,
			     u64 funding_satoshis,
			     enum side funder,
			     u16 to_self_delay,
			     const struct pubkey *revocation_pubkey,
			     const struct pubkey *local_delayedkey,
			     const struct pubkey *localkey,
			     const struct pubkey *remotekey,
			     u64 feerate_per_kw,
			     u64 dust_limit_satoshis,
			     u64 local_pay_msat,
			     u64 remote_pay_msat,
			     const struct htlc **htlcs,
			     const struct htlc ***htlcmap,
			     u64 commit_number_obscurer);
#endif /* LIGHTNING_LIGHTNINGD_COMMIT_TX_H */
