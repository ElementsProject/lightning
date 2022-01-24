#ifndef LIGHTNING_LIGHTNINGD_PAY_H
#define LIGHTNING_LIGHTNINGD_PAY_H
#include "config.h"
#include <common/errcode.h>

struct htlc_out;
struct lightningd;
struct onionreply;
struct preimage;
struct sha256;
struct json_stream;
struct wallet_payment;
struct routing_failure;

void payment_succeeded(struct lightningd *ld, struct htlc_out *hout,
		       const struct preimage *rval);

/* hout->failmsg or hout->failonion must be set. */
void payment_failed(struct lightningd *ld, const struct htlc_out *hout,
		    const char *localfail);

/* Inform payment system to save the payment. */
void payment_store(struct lightningd *ld, struct wallet_payment *payment);

/* This json will be also used in 'sendpay_success' notifictaion. */
void json_add_payment_fields(struct json_stream *response,
			     const struct wallet_payment *t);

/* This json will be also used in 'sendpay_failure' notifictaion. */
void json_sendpay_fail_fields(struct json_stream *js,
			      const struct wallet_payment *t,
			      errcode_t pay_errcode,
			      const struct onionreply *onionreply,
			      const struct routing_failure *fail);

#endif /* LIGHTNING_LIGHTNINGD_PAY_H */
