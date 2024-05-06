#include "config.h"
#include <plugins/renepay/route.h>

struct route *new_route(const tal_t *ctx, u32 groupid,
			u32 partid, struct sha256 payment_hash,
			struct amount_msat amount,
			struct amount_msat amount_sent)
{
	struct route *route = tal(ctx, struct route);
	route->key.partid = partid;
	route->key.groupid = groupid;
	route->key.payment_hash = payment_hash;

	route->final_error = LIGHTNINGD;
	route->final_msg = NULL;
	route->hops = NULL;
	route->success_prob = 0.0;
	route->result = NULL;

	route->amount = amount;
	route->amount_sent = amount_sent;
	return route;
}

/* Construct a route from a flow.
 *
 * @ctx: allocator
 * @groupid, @partid, @payment_hash: unique identification keys for this route
 * @final_cltv: final delay required by the payment
 * @gossmap: global gossmap
 * @flow: the flow to convert to route */
struct route *flow_to_route(const tal_t *ctx,
			    u32 groupid, u32 partid, struct sha256 payment_hash,
			    u32 final_cltv, struct gossmap *gossmap,
			    struct flow *flow)
{
	struct route *route =
	    new_route(ctx, groupid, partid, payment_hash,
		      AMOUNT_MSAT(0), AMOUNT_MSAT(0));

	size_t pathlen = tal_count(flow->path);
	route->hops = tal_arr(route, struct route_hop, pathlen);

	for (size_t i = 0; i < pathlen; i++) {
		struct route_hop *hop = &route->hops[i];
		struct gossmap_node *n;
		n = gossmap_nth_node(gossmap, flow->path[i], !flow->dirs[i]);
		gossmap_node_get_id(gossmap, n, &hop->node_id);

		hop->scid = gossmap_chan_scid(gossmap, flow->path[i]);
		hop->direction = flow->dirs[i];
	}

	/* Calculate cumulative delays (backwards) */
	route->hops[pathlen - 1].delay = final_cltv;
	route->hops[pathlen - 1].amount = flow->amount;

	for (int i = (int)pathlen - 2; i >= 0; i--) {
		const struct half_chan *h = flow_edge(flow, i + 1);

		route->hops[i].delay = route->hops[i + 1].delay + h->delay;
		route->hops[i].amount = route->hops[i + 1].amount;
		if (!amount_msat_add_fee(&route->hops[i].amount, h->base_fee,
					 h->proportional_fee))
			goto function_fail;
	}
	route->success_prob = flow->success_prob;
	route->amount = route->hops[pathlen - 1].amount;
	route->amount_sent = route->hops[0].amount;
	return route;

function_fail:
	return tal_free(route);
}

struct route **flows_to_routes(const tal_t *ctx,
			       u32 groupid, u32 partid,
			       struct sha256 payment_hash, u32 final_cltv,
			       struct gossmap *gossmap, struct flow **flows)
{
	assert(gossmap);
	assert(flows);
	const size_t N = tal_count(flows);
	struct route **routes = tal_arr(ctx, struct route *, N);
	for (size_t i = 0; i < N; i++) {
		routes[i] =
		    flow_to_route(routes, groupid, partid++,
				  payment_hash, final_cltv, gossmap, flows[i]);
		if (!routes[i])
			goto function_fail;
	}
	return routes;

function_fail:
	return tal_free(routes);
}

const char *fmt_route_path(const tal_t *ctx, const struct route *route)
{
	tal_t *this_ctx = tal(ctx, tal_t);
	char *s = tal_strdup(ctx, "");
	const size_t pathlen = tal_count(route->hops);
	for (size_t i = 0; i < pathlen; i++) {
		const struct short_channel_id_dir scidd =
		    hop_to_scidd(&route->hops[i]);
		tal_append_fmt(&s, "%s%s", i ? "->" : "",
			       fmt_short_channel_id(this_ctx, scidd.scid));
	}
	tal_free(this_ctx);
	return s;
}
