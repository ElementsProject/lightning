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

	// FIXME: assuming jsonrpc_errcode == 0 means no error
	route->final_error = 0;
	route->final_msg = NULL;
	route->hops = NULL;
	route->success_prob = 0.0;
	route->result = NULL;
	route->is_reserved = false;

	route->amount = amount;
	route->amount_sent = amount_sent;
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
