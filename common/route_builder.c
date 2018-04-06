#include "route_builder.h"
#include <assert.h>

void
route_builder_init(struct route_builder *builder,
		   struct route_hop *hops,
		   size_t n_hops,
		   const struct pubkey *destination,
		   u64 msatoshi,
		   u32 min_final_cltv_expiry)
{
	builder->begin = hops;
	builder->end = hops + n_hops;
	builder->amount = msatoshi;
	builder->delay = min_final_cltv_expiry;
	builder->next = *destination;
}

void
route_builder_step(struct route_builder *builder,
		   const struct pubkey *source,
		   const struct short_channel_id *channel,
		   u32 fixed,
		   u32 prop,
		   u32 delay)
{
	struct route_hop *hop = --builder->end;

	/* Mostly load from current state. */
	hop->channel_id = *channel;
	hop->nodeid = builder->next;
	hop->amount = builder->amount;
	hop->delay = builder->delay;

	/* Update these afterwards. */
	add_fees(&builder->amount, fixed, prop);
	builder->delay += delay;
	builder->next = *source;
}

void
route_builder_complete(struct route_builder *builder)
{
	assert(builder->begin == builder->end);
}

void
add_fees(u64 *amount, u32 fixed, u32 prop)
{
	*amount += *amount * prop / 1000000;
	*amount += fixed;
}
