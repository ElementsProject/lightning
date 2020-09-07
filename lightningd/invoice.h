#ifndef LIGHTNING_LIGHTNINGD_INVOICE_H
#define LIGHTNING_LIGHTNINGD_INVOICE_H
#include "config.h"
#include <wire/onion_wire.h>

struct amount_msat;
struct htlc_set;
struct lightningd;
struct sha256;


/**
 * invoice_check_payment - check if this payment would be valid
 * @ctx: tal context to allocate return off
 * @ld: lightningd
 * @payment_hash: hash of preimage they want.
 * @msat: amount they offer to pay.
 * @payment_secret: they payment secret they sent, if any.
 *
 * Returns NULL if there's a problem, otherwise returns the invoice details.
 */
const struct invoice_details *
invoice_check_payment(const tal_t *ctx,
		      struct lightningd *ld,
		      const struct sha256 *payment_hash,
		      const struct amount_msat msat,
		      const struct secret *payment_secret);

/**
 * invoice_try_pay - process payment for these incoming payments.
 * @ld: lightningd
 * @set: the htlc_set used to pay this.
 * @details: returned from successful invoice_check_payment.
 *
 * Either calls fulfill_htlc_set() or fail_htlc_set().
 */
void invoice_try_pay(struct lightningd *ld,
		     struct htlc_set *set,
		     const struct invoice_details *details);

#endif /* LIGHTNING_LIGHTNINGD_INVOICE_H */
