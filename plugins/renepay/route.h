#ifndef LIGHTNING_PLUGINS_RENEPAY_ROUTE_H
#define LIGHTNING_PLUGINS_RENEPAY_ROUTE_H

#include "config.h"
#include <assert.h>
#include <bitcoin/preimage.h>
#include <bitcoin/tx.h>
#include <ccan/htable/htable_type.h>
#include <ccan/tal/str/str.h>
#include <common/json_parse_simple.h>
#include <common/route.h>
#include <common/utils.h>
#include <inttypes.h>
#include <plugins/renepay/flow.h>
#include <wire/onion_wiregen.h>

struct payment;

/* States returned by listsendpays, waitsendpay, etc. */
enum sendpay_result_status {
	SENDPAY_PENDING,
	SENDPAY_COMPLETE,
	SENDPAY_FAILED
};

/* A parsed version of the possible outcomes that a sendpay / payment may
 * result in. It excludes the redundant fields such as payment_hash and partid
 * which are already present in the `struct payment` itself. */
struct payment_result {
	/* DB internal id */
	// TODO check all this variables
	u64 id;
	struct preimage *payment_preimage;
	enum sendpay_result_status status;
	struct amount_msat amount_sent;
	enum jsonrpc_errcode code;
	const char *failcodename;
	enum onion_wire failcode;
	const u8 *raw_message;
	const char *message;
	u32 *erring_index;
	struct node_id *erring_node;
	struct short_channel_id *erring_channel;
	int *erring_direction;
};

/* Describes a payment route. It points to a unique sendpay and payment. */
struct route {
	enum jsonrpc_errcode final_error;
	const char *final_msg;

	/* So we can be an independent object for callbacks. */
	struct payment *payment;

	/* Information to link this flow to a unique sendpay. */
	struct routekey {
		struct sha256 payment_hash;
		u64 groupid;
		u64 partid;
	} key;

	/* The series of channels and nodes to traverse. */
	struct route_hop *hops;

	/* amounts are redundant here if we know the hops, however sometimes we
	 * don't know the hops, eg. by calling listsendpays */
	struct amount_msat amount, amount_sent;

	/* Probability estimate (0-1) */
	double success_prob;

	/* result of waitsenday */
	struct payment_result *result;
};

static inline struct routekey routekey(const struct sha256 *hash, u64 groupid,
				       u64 partid)
{
	struct routekey k = {*hash, groupid, partid};
	return k;
}

static inline const char *fmt_routekey(const tal_t *ctx,
				       const struct routekey *k)
{
	char *str = tal_fmt(
	    ctx,
	    "key: groupid=%" PRIu64 ", partid=%" PRIu64 ", payment_hash=%s",
	    k->groupid, k->partid,
	    fmt_sha256(ctx, &k->payment_hash));
	return str;
}

static inline const struct routekey *route_get_key(const struct route *route)
{
	return &route->key;
}

static inline size_t routekey_hash(const struct routekey *k)
{
	return k->payment_hash.u.u32[0] ^ (k->groupid << 32) ^ k->partid;
}

static inline bool routekey_equal(const struct route *route,
				  const struct routekey *k)
{
	return route->key.partid == k->partid &&
	       route->key.groupid == k->groupid &&
	       sha256_eq(&route->key.payment_hash, &k->payment_hash);
}

HTABLE_DEFINE_TYPE(struct route, route_get_key, routekey_hash, routekey_equal,
		   route_map);

struct route *new_route(const tal_t *ctx, struct payment *payment, u32 groupid,
			u32 partid, struct sha256 payment_hash,
			struct amount_msat amount,
			struct amount_msat amount_sent);

struct route *flow_to_route(const tal_t *ctx, struct payment *payment,
			    u32 groupid, u32 partid, struct sha256 payment_hash,
			    u32 final_cltv, struct gossmap *gossmap,
			    struct flow *flow);

struct route **flows_to_routes(const tal_t *ctx, struct payment *payment,
			       u32 groupid, u32 partid,
			       struct sha256 payment_hash, u32 final_cltv,
			       struct gossmap *gossmap, struct flow **flows);

static inline struct short_channel_id_dir
hop_to_scidd(const struct route_hop *hop)
{
	struct short_channel_id_dir scidd;
	scidd.scid = hop->scid;
	scidd.dir = hop->direction;
	return scidd;
}

const char *fmt_route_path(const tal_t *ctx, const struct route *route);

static inline struct amount_msat route_delivers(const struct route *route)
{
	assert(route);
	if (route->hops && tal_count(route->hops) > 0)
		assert(amount_msat_eq(
		    route->amount,
		    route->hops[tal_count(route->hops) - 1].amount));
	return route->amount;
}
static inline struct amount_msat route_sends(const struct route *route)
{
	assert(route);
	if (route->hops && tal_count(route->hops) > 0)
		assert(
		    amount_msat_eq(route->amount_sent, route->hops[0].amount));
	return route->amount_sent;
}
static inline struct amount_msat route_fees(const struct route *route)
{
	struct amount_msat fees;
	if (!amount_msat_sub(&fees, route_sends(route),
			     route_delivers(route))) {
		assert(0 && "route sends is greater than delivers");
	}
	return fees;
}
static inline u32 route_delay(const struct route *route)
{
	assert(route);
	assert(route->hops);
	assert(tal_count(route->hops) > 0);
	const size_t pathlen = tal_count(route->hops);
	assert(route->hops[0].delay >= route->hops[pathlen - 1].delay);
	return route->hops[0].delay - route->hops[pathlen - 1].delay;
}

#endif /* LIGHTNING_PLUGINS_RENEPAY_ROUTE_H */
