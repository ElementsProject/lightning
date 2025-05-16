#ifndef LIGHTNING_COMMON_ONIONREPLY_H
#define LIGHTNING_COMMON_ONIONREPLY_H
#include "config.h"
#include <ccan/short_types/short_types.h>
#include <ccan/tal/tal.h>

/* Sizes for the attribution_data TLV value (see BOLT #4 attributable errors).
 * On the wire and in memory the value is one contiguous blob:
 *   [ATTR_HOLD_TIMES_SIZE bytes: htlc_hold_times] ||
 *   [ATTR_HMAC_SIZE       bytes: truncated_hmacs] */
#define ATTR_HOLD_TIMES_SIZE 80
#define ATTR_HMAC_SIZE 840
#define ATTR_HMAC_OFFSET ATTR_HOLD_TIMES_SIZE
#define ATTR_DATA_SIZE (ATTR_HOLD_TIMES_SIZE + ATTR_HMAC_SIZE)

struct attribution_data {
	u8 data[ATTR_DATA_SIZE];
};

/* A separate type for an onion reply, to differentiate from a wire msg. */
struct onionreply {
	u8 *contents;
	struct attribution_data *attr_data;
};

/**
 * Wire marshalling routines for onionreply
 */
void towire_onionreply(u8 **cursor, const struct onionreply *r);
struct onionreply *fromwire_onionreply(const tal_t *ctx,
				       const u8 **cursor, size_t *max);


struct onionreply *dup_onionreply(const tal_t *ctx,
				  const struct onionreply *r TAKES);

struct onionreply *new_onionreply(const tal_t *ctx, const u8 *contents TAKES, const struct attribution_data *attr_data);
#endif /* LIGHTNING_COMMON_ONIONREPLY_H */
