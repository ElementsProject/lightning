#ifndef LIGHTNING_LIGHTNINGD_PAY_H
#define LIGHTNING_LIGHTNINGD_PAY_H
#include "config.h"
#include <bitcoin/preimage.h>
#include <bitcoin/pubkey.h>
#include <bitcoin/short_channel_id.h>
#include <wire/gen_onion_wire.h>

struct htlc_out;
struct lightningd;
struct route_hop;
struct sha256;

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

bool send_payment(const tal_t *ctx,
		  struct lightningd* ld,
		  const struct sha256 *rhash,
		  const struct route_hop *route,
		  void (*cb)(const struct sendpay_result*, void*),
		  void *cbarg);

void payment_succeeded(struct lightningd *ld, struct htlc_out *hout,
		       const struct preimage *rval);

void payment_failed(struct lightningd *ld, const struct htlc_out *hout,
		    const char *localfail);

#endif /* LIGHTNING_LIGHTNINGD_PAY_H */
