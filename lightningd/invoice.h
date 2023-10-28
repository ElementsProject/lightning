#ifndef LIGHTNING_LIGHTNINGD_INVOICE_H
#define LIGHTNING_LIGHTNINGD_INVOICE_H
#include "config.h"
#include <wallet/wallet.h>
#include <wire/onion_wire.h>

struct amount_msat;
struct htlc_set;
struct json_escape;
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
	/* Set if state == PAID and invoice paid on chain; outpoint containing the payment */
	const struct bitcoin_outpoint *paid_outpoint;
	/* BOLT11 or BOLT12 encoding for this invoice */
	const char *invstring;

	/* The description of the payment. */
	char *description;
	/* The features, if any (tal_arr) */
	u8 *features;
	/* The offer this refers to, if any. */
	struct sha256 *local_offer_id;
	/* Index values */
	u64 created_index, updated_index;
};

/**
 * invoice_check_payment - check if this payment would be valid
 * @ctx: tal context to allocate return off
 * @ld: lightningd
 * @payment_hash: hash of preimage they want.
 * @msat: amount they offer to pay.
 * @payment_secret: they payment secret they sent, if any.
 * @err: error string if it returns NULL.
 *
 * Returns NULL if there's a problem, otherwise returns the invoice details.
 */
const struct invoice_details *invoice_check_payment(const tal_t *ctx,
						    struct lightningd *ld,
						    const struct sha256 *payment_hash,
						    const struct amount_msat msat,
						    const struct secret *payment_secret,
						    const char **err);

/**
 * invoice_check_onchain_payment - check if this on-chain payment would be valid
 * @ld: the lightning context
 * @scriptPubKey: fallback script with which to search for invoices
 * @sat: output amount
 * @outpoint: the outpoint which paid it.
 */
void invoice_check_onchain_payment(struct lightningd *ld,
				   const u8 *scriptPubKey,
				   struct amount_sat sat,
				   const struct bitcoin_outpoint *outpoint);

/**
 * invoice_try_pay - process payment for these incoming payments.
 * @ld: lightningd
 * @set: the htlc_set used to pay this (NULL if onchain)
 * @details: returned from successful invoice_check_payment.
 * @msat: the amount of the output or htlc_set
 * @outpoint: the onchain outpoint (iff onchain).
 *
 * If @set is not NULL, either calls fulfill_htlc_set() or fail_htlc_set().
 */
void invoice_try_pay(struct lightningd *ld,
		     struct htlc_set *set,
		     const struct invoice_details *details,
		     struct amount_msat msat,
		     const struct bitcoin_outpoint *outpoint);

/* Simple enum -> string converter for JSON fields */
const char *invoice_status_str(enum invoice_status state);

#endif /* LIGHTNING_LIGHTNINGD_INVOICE_H */
