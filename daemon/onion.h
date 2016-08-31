#ifndef LIGHTNING_DAEMON_ONION_H
#define LIGHTNING_DAEMON_ONION_H
#include "config.h"
#include "lightning.pb-c.h"
#include <ccan/short_types/short_types.h>
#include <secp256k1.h>

struct peer;
struct node_connection;

/* Decode next step in the route, and fill out the onion to send onwards. */
RouteStep *onion_unwrap(struct peer *peer,
			const void *data, size_t len, const u8 **next);

/* Create an onion for sending msatoshi down path, paying fees. */
const u8 *onion_create(const tal_t *ctx,
		       secp256k1_context *secpctx,
		       const struct pubkey *ids,
		       const u64 *amounts,
		       size_t num_hops);
#endif /* LIGHTNING_DAEMON_ONION_H */
