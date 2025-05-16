#ifndef LIGHTNING_COMMON_ONIONREPLY_H
#define LIGHTNING_COMMON_ONIONREPLY_H
#include "config.h"
#include <ccan/short_types/short_types.h>
#include <ccan/tal/tal.h>

/* A separate type for an onion reply, to differentiate from a wire msg. */
struct onionreply {
	u8 *contents;
	u8 *htlc_hold_time;
	u8 *truncated_hmac;
};

/**
 * Wire marshalling routines for onionreply
 */
void towire_onionreply(u8 **cursor, const struct onionreply *r);
struct onionreply *fromwire_onionreply(const tal_t *ctx,
				       const u8 **cursor, size_t *max);


struct onionreply *dup_onionreply(const tal_t *ctx,
				  const struct onionreply *r TAKES);

struct onionreply *new_onionreply(const tal_t *ctx, const u8 *contents TAKES, const u8 htlc_hold_time[80] TAKES, const u8 truncated_hmac[840] TAKES);
#endif /* LIGHTNING_COMMON_ONIONREPLY_H */
