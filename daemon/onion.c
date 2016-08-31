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

/* Create an onion for this path. */
const u8 *onion_create(const tal_t *ctx,
		       secp256k1_context *secpctx,
		       const struct pubkey *ids,
		       const u64 *amounts,
		       size_t num_hops)
{
	Route *r = tal(ctx, Route);
	size_t i;

	route__init(r);
	r->n_steps = num_hops + 1;
	r->steps = tal_arr(r, RouteStep *, r->n_steps);

	for (i = 0; i < num_hops; i++) {
		r->steps[i] = tal(r, RouteStep);
		route_step__init(r->steps[i]);
		r->steps[i]->next_case = ROUTE_STEP__NEXT_BITCOIN;
		r->steps[i]->bitcoin = pubkey_to_proto(r, secpctx, &ids[i]);
		r->steps[i]->amount = amounts[i];
	}

	/* Now the stop marker. */
	r->steps[i] = tal(r, RouteStep);
	route_step__init(r->steps[i]);
	r->steps[i]->next_case = ROUTE_STEP__NEXT_END;
	r->steps[i]->end = true;
	r->steps[i]->amount = 0;

	return to_onion(ctx, r);
}

/* Decode next step in the route, and fill out the onion to send onwards. */
RouteStep *onion_unwrap(struct peer *peer,
			const void *data, size_t len, const u8 **next)
{
	struct ProtobufCAllocator *prototal = make_prototal(peer);
	Route *r;
	RouteStep *step;

	r = route__unpack(prototal, len, data);
	if (!r || r->n_steps == 0) { 
		log_unusual(peer->log, "Failed to unwrap onion");
		tal_free(prototal);
		return NULL;
	}

	/* Remove first step. */
	step = r->steps[0];
	/* Make sure that step owns the rest */
	steal_from_prototal(peer, prototal, step);

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
