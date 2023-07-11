#ifndef LIGHTNING_LIGHTNINGD_INVOICE_H
#define LIGHTNING_LIGHTNINGD_INVOICE_H
#include "config.h"
#include <wallet/wallet.h>
#include <wire/onion_wire.h>

struct amount_msat;
struct htlc_set;
struct lightningd;
struct sha256;

/* The information about an invoice */
struct invoice_details {
	/* Current invoice state */
	enum invoice_status state;
	/* Preimage for this invoice */
	struct preimage r;
	/* Hash of preimage r */
	struct sha256 rhash;
	/* Label assigned by user */
	const struct json_escape *label;
	/* NULL if they specified "any" */
	struct amount_msat *msat;
	/* Absolute UNIX epoch time this will expire */
	u64 expiry_time;
	/* Set if state == PAID; order to be returned by waitanyinvoice */
	u64 pay_index;
	/* Set if state == PAID; amount received */
	struct amount_msat received;
	/* Set if state == PAID; time paid */
	u64 paid_timestamp;
	/* BOLT11 or BOLT12 encoding for this invoice */
	const char *invstring;

	/* The description of the payment. */
	char *description;
	/* The features, if any (tal_arr) */
	u8 *features;
	/* The offer this refers to, if any. */
	struct sha256 *local_offer_id;
};

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

/* Simple enum -> string converter for JSON fields */
const char *invoice_status_str(enum invoice_status state);

#endif /* LIGHTNING_LIGHTNINGD_INVOICE_H */
