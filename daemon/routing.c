#include "jsonrpc.h"
#include "lightningd.h"
#include "log.h"
#include "overflows.h"
#include "peer.h"
#include "pseudorand.h"
#include "routing.h"
#include <ccan/array_size/array_size.h>
#include <ccan/crypto/siphash24/siphash24.h>
#include <ccan/htable/htable_type.h>
#include <ccan/structeq/structeq.h>
#include <inttypes.h>

static const secp256k1_pubkey *keyof_node(const struct node *n)
{
	return &n->id.pubkey;
}

static size_t hash_key(const secp256k1_pubkey *key)
{
	return siphash24(siphash_seed(), key, sizeof(key));
}

static bool node_eq(const struct node *n, const secp256k1_pubkey *key)
{
	return structeq(&n->id.pubkey, key);
}
HTABLE_DEFINE_TYPE(struct node, keyof_node, hash_key, node_eq, node_map);

struct node_map *empty_node_map(struct lightningd_state *dstate)
{
	struct node_map *map = tal(dstate, struct node_map);
	node_map_init(map);
	return map;
}

struct node *get_node(struct lightningd_state *dstate,
		      const struct pubkey *id)
{
	return node_map_get(dstate->nodes, &id->pubkey);
}

struct node *new_node(struct lightningd_state *dstate,
		      const struct pubkey *id)
{
	struct node *n;

	assert(!get_node(dstate, id));

	n = tal(dstate, struct node);
	n->id = *id;
	n->conns = tal_arr(n, struct node_connection, 0);
	node_map_add(dstate->nodes, n);

	return n;
}

static struct node_connection *
get_or_make_connection(struct lightningd_state *dstate,
		       struct node *from, struct node *to)
{
	size_t i, n = tal_count(to->conns);

	for (i = 0; i < n; i++) {
		if (to->conns[i].src == from) {
			log_debug_struct(dstate->base_log,
					 "Updating existing route from %s",
					 struct pubkey, &from->id);
			log_add_struct(dstate->base_log, " to %s",
				       struct pubkey, &to->id);
			return &to->conns[i];
		}
	}

	log_debug_struct(dstate->base_log, "Creating new route from %s",
			 struct pubkey, &from->id);
	log_add_struct(dstate->base_log, " to %s", struct pubkey, &to->id);

	tal_resize(&to->conns, i+1);
	to->conns[i].src = from;
	to->conns[i].dst = to;
	return &to->conns[i];
}

/* Updates existing route if required. */
struct node_connection *add_connection(struct lightningd_state *dstate,
				       struct node *from, struct node *to,
				       u32 base_fee, s32 proportional_fee,
				       u32 delay, u32 min_blocks)
{
	struct node_connection *c = get_or_make_connection(dstate, from, to);
	c->base_fee = base_fee;
	c->proportional_fee = proportional_fee;
	c->delay = delay;
	c->min_blocks = min_blocks;
	return c;
}

/* Too big to reach, but don't overflow if added. */
#define INFINITE 0x3FFFFFFFFFFFFFFFULL

static void clear_bfg(struct node_map *nodes)
{
	struct node *n;
	struct node_map_iter it;

	for (n = node_map_first(nodes, &it); n; n = node_map_next(nodes, &it)) {
		size_t i;
		for (i = 0; i < ARRAY_SIZE(n->bfg); i++)
			n->bfg[i].total = INFINITE;
	}
}

s64 connection_fee(const struct node_connection *c, u64 msatoshi)
{
	s64 fee;

	if (mul_overflows_s64(c->proportional_fee, msatoshi))
		return INFINITE;
	fee = (c->proportional_fee * msatoshi) / 1000000;
	/* This can't overflow: c->base_fee is a u32 */
	return c->base_fee + fee;
}

/* We track totals, rather than costs.  That's because the fee depends
 * on the current amount passing through. */
static void bfg_one_edge(struct node *node, size_t edgenum)
{
	struct node_connection *c = &node->conns[edgenum];
	size_t h;

	assert(c->dst == node);
	for (h = 0; h < ROUTING_MAX_HOPS; h++) {
		/* FIXME: Bias towards smaller expiry values. */
		/* FIXME: Bias against smaller channels. */
		s64 fee = connection_fee(c, node->bfg[h].total);
		if (node->bfg[h].total + fee < c->src->bfg[h+1].total) {
			c->src->bfg[h+1].total = node->bfg[h].total + fee;
			c->src->bfg[h+1].prev = c;
		}
	}
}

struct peer *find_route(struct lightningd_state *dstate,
			const struct pubkey *to,
			u64 msatoshi, s64 *fee,
			struct node_connection ***route)
{
	struct node *n, *src, *dst;
	struct node_map_iter it;
	struct peer *first;
	int runs, i, best;

	/* Note: we map backwards, since we know the amount of satoshi we want
	 * at the end, and need to derive how much we need to send. */
	dst = get_node(dstate, &dstate->id);
	src = get_node(dstate, to);
	if (!src) {
		log_info_struct(dstate->base_log, "find_route: cannot find %s",
				struct pubkey, to);
		return NULL;
	}

	/* Reset all the information. */
	clear_bfg(dstate->nodes);

	/* Bellman-Ford-Gibson: like Bellman-Ford, but keep values for
	 * every path length. */
	src->bfg[0].total = msatoshi;

	for (runs = 0; runs < ROUTING_MAX_HOPS; runs++) {
		/* Run through every edge. */
		for (n = node_map_first(dstate->nodes, &it);
		     n;
		     n = node_map_next(dstate->nodes, &it)) {
			size_t num_edges = tal_count(n->conns);
			for (i = 0; i < num_edges; i++) {
				bfg_one_edge(n, i);
			}
		}
	}

	best = 0;
	for (i = 1; i <= ROUTING_MAX_HOPS; i++) {
		if (dst->bfg[i].total < dst->bfg[best].total)
			best = i;
	}

	/* No route? */
	if (dst->bfg[best].total >= INFINITE) {
		log_info_struct(dstate->base_log, "find_route: No route to %s",
				struct pubkey, to);
		return NULL;
	}

	/* Save route from *next* hop (we return first hop as peer).
	 * Note that we take our own fees into account for routing, even
	 * though we don't pay them: it presumably effects preference. */
	dst = dst->bfg[best].prev->dst;
	best--;

	*fee = dst->bfg[best].total - msatoshi;
	*route = tal_arr(dstate, struct node_connection *, best);
	for (i = 0, n = dst;
	     i < best;
	     n = n->bfg[best-i].prev->dst, i++) {
		(*route)[i] = n->bfg[best-i].prev;
	}
	assert(n == src);

	/* We should only add routes if we have a peer. */
	first = find_peer(dstate, &(*route)[0]->src->id);
	if (!first) {
		log_broken_struct(dstate->base_log, "No peer %s?",
				  struct pubkey, &(*route)[0]->src->id);
		return NULL;
	}

	msatoshi += *fee;
	log_info(dstate->base_log, "find_route:");
	log_add_struct(dstate->base_log, "via %s", struct pubkey, &first->id);
	for (i = 0; i < best; i++) {
		log_add_struct(dstate->base_log, " %s",
			       struct pubkey, &(*route)[i]->dst->id);
		log_add(dstate->base_log, "(%i+%i=%"PRIu64")",
			(*route)[i]->base_fee,
			(*route)[i]->proportional_fee,
			connection_fee((*route)[i], msatoshi));
		msatoshi -= connection_fee((*route)[i], msatoshi);
	}
	log_add(dstate->base_log, "=%"PRIi64"(%+"PRIi64")",
		(*route)[best-1]->dst->bfg[best-1].total, *fee);

	return first;
}

static void json_add_route(struct command *cmd,
			   const char *buffer, const jsmntok_t *params)
{
	jsmntok_t *srctok, *dsttok, *basetok, *vartok, *delaytok, *minblockstok;
	struct pubkey src, dst;
	struct node *from, *to;
	u32 base, var, delay, minblocks;

	if (!json_get_params(buffer, params,
			    "src", &srctok,
			    "dst", &dsttok,
			    "base", &basetok,
			    "var", &vartok,
			    "delay", &delaytok,
			    "minblocks", &minblockstok,
			    NULL)) {
		command_fail(cmd, "Need src, dst, base, var, delay & minblocks");
		return;
	}

	if (!pubkey_from_hexstr(cmd->dstate->secpctx,
				buffer + srctok->start,
				srctok->end - srctok->start, &src)) {
		command_fail(cmd, "src %.*s not valid",
			     srctok->end - srctok->start,
			     buffer + srctok->start);
		return;
	}

	if (!pubkey_from_hexstr(cmd->dstate->secpctx,
				buffer + dsttok->start,
				dsttok->end - dsttok->start, &dst)) {
		command_fail(cmd, "dst %.*s not valid",
			     dsttok->end - dsttok->start,
			     buffer + dsttok->start);
		return;
	}

	if (!json_tok_number(buffer, basetok, &base)
	    || !json_tok_number(buffer, vartok, &var)
	    || !json_tok_number(buffer, delaytok, &delay)
	    || !json_tok_number(buffer, minblockstok, &minblocks)) {
		command_fail(cmd,
			     "base, var, delay and minblocks must be numbers");
		return;
	}

	from = get_node(cmd->dstate, &src);
	if (!from)
		from = new_node(cmd->dstate, &src);
	to = get_node(cmd->dstate, &dst);
	if (!to)
		to = new_node(cmd->dstate, &dst);

	add_connection(cmd->dstate, from, to, base, var, delay, minblocks);
	command_success(cmd, null_response(cmd));
}
	
const struct json_command add_route_command = {
	"add-route",
	json_add_route,
	"Add route from {src} to {dst}, {base} rate in msatoshi, {var} rate in msatoshi, {delay} blocks delay and {minblocks} minimum timeout",
	"Returns an empty result on success"
};

static void json_routefail(struct command *cmd,
			   const char *buffer, const jsmntok_t *params)
{
	jsmntok_t *enabletok;
	bool enable;

	if (!json_get_params(buffer, params,
			     "enable", &enabletok,
			     NULL)) {
		command_fail(cmd, "Need enable");
		return;
	}

	if (!json_tok_bool(buffer, enabletok, &enable)) {
		command_fail(cmd, "enable must be true or false");
		return;
	}

	log_debug(cmd->dstate->base_log, "dev-routefail: routefail %s",
		  enable ? "enabled" : "disabled");
	cmd->dstate->dev_never_routefail = !enable;

	command_success(cmd, null_response(cmd));
}
const struct json_command routefail_command = {
	"dev-routefail",
	json_routefail,
	"FAIL htlcs that we can't route if {enable}",
	"Returns an empty result on success"
};


