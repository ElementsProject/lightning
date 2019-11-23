#ifndef LIGHTNING_LIGHTNINGD_INVOICE_H
#define LIGHTNING_LIGHTNINGD_INVOICE_H
#include "config.h"
#include <wire/gen_onion_wire.h>

struct amount_msat;
struct htlc_in;
struct lightningd;
struct sha256;

/**
 * invoice_try_pay - process payment for this payment_hash, amount msat.
 * @ld: lightningd
 * @hin: the input HTLC which is offering to pay.
 * @payment_hash: hash of preimage they want.
 * @msat: amount they offer to pay.
 * @payment_secret: they payment secret they sent, if any.
 *
 * Either calls fulfill_htlc() or fail_htlcs().
 */
void invoice_try_pay(struct lightningd *ld,
		     struct htlc_in *hin,
		     const struct sha256 *payment_hash,
		     const struct amount_msat msat,
		     const struct secret *payment_secret);

#endif /* LIGHTNING_LIGHTNINGD_INVOICE_H */
