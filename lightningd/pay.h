#ifndef LIGHTNING_LIGHTNINGD_PAY_H
#define LIGHTNING_LIGHTNINGD_PAY_H
#include "config.h"
#include <bitcoin/preimage.h>
#include <bitcoin/pubkey.h>
#include <bitcoin/short_channel_id.h>
#include <wire/gen_onion_wire.h>

struct htlc_out;
struct json_result;
struct lightningd;
struct route_hop;
struct sha256;
struct wallet_payment;

/* Routing failure object */
struct routing_failure {
	unsigned int erring_index;
	enum onion_type failcode;
	struct pubkey erring_node;
	struct short_channel_id erring_channel;
	u8 *channel_update;
};

/* Result of send_payment */
struct sendpay_result {
	/* Did the payment succeed? */
	bool succeeded;
	/* Preimage. Only loaded if payment succeeded. */
	struct preimage preimage;
	/* Error code, one of the PAY_* macro in jsonrpc_errors.h.
	 * Only loaded if payment failed. */
	int errorcode;
	/* Pointer to the payment. Only loaded if payment
	 * succeeded or if error is PAY_IN_PROGRESS */
	const struct wallet_payment *payment;
	/* Unparseable onion reply. Only loaded if payment failed,
	 * and errorcode == PAY_UNPARSEABLE_ONION. */
	const u8* onionreply;
	/* Routing failure object. Only loaded if payment failed,
	 * and errorcode == PAY_DESTINATION_PERM_FAIL or
	 * errorcode == PAY_TRY_OTHER_ROUTE */
	struct routing_failure* routing_failure;
	/* Error message. Only loaded if payment failed. */
	const char *details;
};

/* Initiate a payment.  Return true if the callback will be
 * scheduled for later, or false if the callback has already
 * been called. If the given context is freed before the
 * callback is called, then the callback will no longer be
 * called.
 *
 * This will call the callback "soon" in 10ms or less.
 *
 * Typically the callback will be called with a failed
 * sendpay_result indicating an error code of PAY_IN_PROGRESS.
 * It will only call the callback with successful sendpay_result
 * if the payment has already completed with the same amount
 * and destination before.
 *
 * The msatoshi given is what is recorded in the payment. */
bool send_payment(const tal_t *ctx,
		  struct lightningd* ld,
		  const struct sha256 *rhash,
		  const struct route_hop *route,
		  u64 msatoshi,
		  const char *description TAKES,
		  void (*cb)(const struct sendpay_result *, void*),
		  void *cbarg);

/* Wait for a previous send_payment to complete in definite
 * success or failure. If the given context is freed before
 * the callback is called, then the callback will no longer
 * be called.
 *
 * Return true if the payment is still pending on return, or
 * false if the callback was already invoked before this
 * function returned. */
bool wait_payment(const tal_t *ctx,
		  struct lightningd* ld,
		  const struct sha256 *payment_hash,
		  void (*cb)(const struct sendpay_result *, void *cbarg),
		  void *cbarg);

void payment_succeeded(struct lightningd *ld, struct htlc_out *hout,
		       const struct preimage *rval);

void payment_failed(struct lightningd *ld, const struct htlc_out *hout,
		    const char *localfail);

/* Inform payment system to save the payment. */
void payment_store(struct lightningd *ld, const struct sha256 *payment_hash);

/* Output the fields of a payment. Caller should have put the
 * response within a JSON object and is responsible for
 * closing the object. */
void json_add_payment_fields(struct json_result *response,
			     const struct wallet_payment *t);

#endif /* LIGHTNING_LIGHTNINGD_PAY_H */
