#include "config.h"
#include <plugins/renepay/route.h>

struct route *new_route(const tal_t *ctx, u64 groupid,
			u64 partid, struct sha256 payment_hash,
			struct amount_msat amount_deliver,
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

	route->amount_deliver = amount_deliver;
	route->amount_sent = amount_sent;
	route->path_num = -1;
	route->shared_secrets = NULL;
	route->unreserve_action = NULL;
	return route;
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
