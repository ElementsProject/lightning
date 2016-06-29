#include "log.h"
#include "onion.h"
#include "peer.h"
#include "protobuf_convert.h"
#include "routing.h"
#include <string.h>

/* FIXME: http://www.cypherpunks.ca/~iang/pubs/Sphinx_Oakland09.pdf */

/* Frees r */
static const u8 *to_onion(const tal_t *ctx, const Route *r)
{
	u8 *onion = tal_arr(ctx, u8, route__get_packed_size(r));
	route__pack(r, onion);
	tal_free(r);
	return onion;
}

/* Create an onion for sending msatoshi_with_fees down path. */
const u8 *onion_create(const tal_t *ctx,
		       struct node_connection **path,
		       u64 msatoshi, s64 fees)
{
	Route *r = tal(ctx, Route);
	int i;
	u64 amount = msatoshi;

	route__init(r);
	r->n_steps = tal_count(path) + 1;
	r->steps = tal_arr(r, RouteStep *, r->n_steps);

	/* Create backwards, so we can get fees correct. */
	for (i = tal_count(path) - 1; i >= 0; i--) {
		r->steps[i] = tal(r, RouteStep);
		route_step__init(r->steps[i]);
		r->steps[i]->next_case = ROUTE_STEP__NEXT_BITCOIN;
		r->steps[i]->bitcoin = pubkey_to_proto(r, &path[i]->dst->id);
		r->steps[i]->amount = amount;
		amount += connection_fee(path[i], amount);
	}

	/* Now the stop marker. */
	i = tal_count(path);
	r->steps[i] = tal(r, RouteStep);
	route_step__init(r->steps[i]);
	r->steps[i]->next_case = ROUTE_STEP__NEXT_END;
	r->steps[i]->end = true;
	r->steps[i]->amount = 0;

	assert(amount == msatoshi + fees);
	
	return to_onion(ctx, r);
}

static void *proto_tal_alloc(void *allocator_data, size_t size)
{
	return tal_arr(allocator_data, char, size);
}

static void proto_tal_free(void *allocator_data, void *pointer)
{
	tal_free(pointer);
}
	
/* Decode next step in the route, and fill out the onion to send onwards. */
RouteStep *onion_unwrap(struct peer *peer,
			const void *data, size_t len, const u8 **next)
{
	struct ProtobufCAllocator prototal;
	Route *r;
	RouteStep *step;

	/* De-protobuf it. */
	prototal.alloc = proto_tal_alloc;
	prototal.free = proto_tal_free;
	prototal.allocator_data = tal(peer, char);

	r = route__unpack(&prototal, len, data);
	if (!r || r->n_steps == 0) { 
		log_unusual(peer->log, "Failed to unwrap onion");
		tal_free(prototal.allocator_data);
		return NULL;
	}

	/* Remove first step. */
	step = r->steps[0];
	/* Make sure that step owns the rest */
	tal_steal(peer, step);
	tal_steal(step, prototal.allocator_data);

	/* Re-pack with remaining steps. */
	r->n_steps--;
	memmove(r->steps, r->steps + 1, sizeof(*r->steps) * r->n_steps);

	if (!r->n_steps) {
		*next = NULL;
		tal_free(r);
	} else
		*next = to_onion(peer, r);

	return step;
}
