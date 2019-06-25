#ifndef LIGHTNING_LIGHTNINGD_PAY_H
#define LIGHTNING_LIGHTNINGD_PAY_H
#include "config.h"

struct htlc_out;
struct lightningd;
struct preimage;
struct sha256;
struct json_stream;
struct wallet_payment;

void payment_succeeded(struct lightningd *ld, struct htlc_out *hout,
		       const struct preimage *rval);

void payment_failed(struct lightningd *ld, const struct htlc_out *hout,
		    const char *localfail);

/* Inform payment system to save the payment. */
void payment_store(struct lightningd *ld, const struct sha256 *payment_hash);

/* This json will be also used in 'sendpay_success' notifictaion. */
void json_add_payment_fields(struct json_stream *response,
			     const struct wallet_payment *t);

#endif /* LIGHTNING_LIGHTNINGD_PAY_H */
