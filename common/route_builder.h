#ifndef LIGHTNING_COMMON_ROUTE_BUILDER_H
#define LIGHTNING_COMMON_ROUTE_BUILDER_H
#include "config.h"
#include <bitcoin/pubkey.h>
#include <bitcoin/short_channel_id.h>
#include <ccan/short_types/short_types.h>
#include <stddef.h>

/* Standard route hop understood by send_payment. */
struct route_hop {
	struct short_channel_id channel_id;
	struct pubkey nodeid;
	u64 amount;
	u32 delay;
};

/* Fields are not intended to be accessed and are
 * subject to change without notice.
 * Only put it here so compiler can optimize storage. */
struct route_builder {
	struct route_hop *begin;
	struct route_hop *end;
	u64 amount;
	u32 delay;
	struct pubkey next;
};
/* Routes are built backwards. This function starts the
 * building of a route array. */
void route_builder_init(struct route_builder *builder,
			struct route_hop *hops,
			size_t n_hops,
			const struct pubkey *destination,
			u64 msatoshi,
			u32 min_final_cltv_expiry);
/* Must be called starting with the last hop, as routes
 * must be built backwards. */
void route_builder_step(struct route_builder *builder,
			/* Who will pay to the next pubkey. */
			const struct pubkey *source,
			/* What channel the source will use to pay the
			 * next pubkey. */
			const struct short_channel_id *channel,
			/* Fees of the channel. */
			u32 fee_base_msat,
			u32 fee_proportional_millionths,
			/* Delay added by the channel. */
			u32 cltv_expiry_delta);
/* Call when the entire route has been loaded. */
void route_builder_complete(struct route_builder *builder);

/* Modify the given amount according to a channel fee. */
void add_fees(u64 *amount,
	      u32 fee_base_msat, u32 fee_proportional_millionths);

#endif /* LIGHTNING_COMMON_ROUTE_BUILDER_H */
