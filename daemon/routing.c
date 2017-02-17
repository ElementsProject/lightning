#include "lightningd.h"
#include "log.h"
#include "overflows.h"
#include "packets.h"
#include "pseudorand.h"
#include "routing.h"
#include "wire/gen_peer_wire.h"
#include <arpa/inet.h>
#include <ccan/array_size/array_size.h>
#include <ccan/crypto/siphash24/siphash24.h>
#include <ccan/endian/endian.h>
#include <ccan/structeq/structeq.h>
#include <ccan/tal/str/str.h>
#include <inttypes.h>

/* 365.25 * 24 * 60 / 10 */
#define BLOCKS_PER_YEAR 52596

struct routing_state *new_routing_state(const tal_t *ctx, struct log *base_log)
{
	struct routing_state *rstate = tal(ctx, struct routing_state);
	rstate->base_log = base_log;
	rstate->nodes = empty_node_map(rstate);
	rstate->broadcasts = new_broadcast_state(rstate);
	return rstate;
}


const secp256k1_pubkey *node_map_keyof_node(const struct node *n)
{
	return &n->id.pubkey;
}

size_t node_map_hash_key(const secp256k1_pubkey *key)
{
	return siphash24(siphash_seed(), key, sizeof(*key));
}

bool node_map_node_eq(const struct node *n, const secp256k1_pubkey *key)
{
	return structeq(&n->id.pubkey, key);
}

struct node_map *empty_node_map(const tal_t *ctx)
{
	struct node_map *map = tal(ctx, struct node_map);
	node_map_init(map);
	return map;
}

struct node *get_node(struct routing_state *rstate,
		      const struct pubkey *id)
{
	return node_map_get(rstate->nodes, &id->pubkey);
}

static void destroy_node(struct node *node)
{
	/* These remove themselves from the array. */
	while (tal_count(node->in))
		tal_free(node->in[0]);
	while (tal_count(node->out))
		tal_free(node->out[0]);
}

struct node *new_node(struct routing_state *rstate,
		      const struct pubkey *id)
{
	struct node *n;

	assert(!get_node(rstate, id));

	n = tal(rstate, struct node);
	n->id = *id;
	n->in = tal_arr(n, struct node_connection *, 0);
	n->out = tal_arr(n, struct node_connection *, 0);
	n->port = 0;
	n->alias = NULL;
	n->hostname = NULL;
	n->node_announcement = NULL;
	node_map_add(rstate->nodes, n);
	tal_add_destructor(n, destroy_node);

	return n;
}

struct node *add_node(
	struct routing_state *rstate,
	const struct pubkey *pk,
	char *hostname,
	int port)
{
	struct node *n = get_node(rstate, pk);
	if (!n) {
		n = new_node(rstate, pk);
		log_debug_struct(rstate->base_log, "Creating new node %s",
				 struct pubkey, pk);
	} else {
		log_debug_struct(rstate->base_log, "Update existing node %s",
				 struct pubkey, pk);
	}
	n->hostname = tal_steal(n, hostname);
	n->port = port;
	return n;
}

static bool remove_conn_from_array(struct node_connection ***conns,
				   struct node_connection *nc)
{
	size_t i, n;

	n = tal_count(*conns);
	for (i = 0; i < n; i++) {
		if ((*conns)[i] != nc)
			continue;
		n--;
		memmove(*conns + i, *conns + i + 1, sizeof(**conns) * (n - i));
		tal_resize(conns, n);
		return true;
	}
	return false;
}

static void destroy_connection(struct node_connection *nc)
{
	if (!remove_conn_from_array(&nc->dst->in, nc)
	    || !remove_conn_from_array(&nc->src->out, nc))
		fatal("Connection not found in array?!");
}

struct node_connection * get_connection(struct routing_state *rstate,
					const struct pubkey *from_id,
					const struct pubkey *to_id)
{
	int i, n;
	struct node *from, *to;
	from = get_node(rstate, from_id);
	to = get_node(rstate, to_id);
	if (!from || ! to)
		return NULL;

	n = tal_count(to->in);
	for (i = 0; i < n; i++) {
		if (to->in[i]->src == from)
			return to->in[i];
	}
	return NULL;
}

struct node_connection *get_connection_by_cid(const struct routing_state *rstate,
					      const struct channel_id *chanid,
					      const u8 direction)
{
	struct node *n;
	int i, num_conn;
	struct node_map *nodes = rstate->nodes;
	struct node_connection *c;
	struct node_map_iter it;

	//FIXME(cdecker) We probably want to speed this up by indexing by chanid.
	for (n = node_map_first(nodes, &it); n; n = node_map_next(nodes, &it)) {
	        num_conn = tal_count(n->out);
		for (i = 0; i < num_conn; i++){
			c = n->out[i];
			if (structeq(&c->channel_id, chanid) &&
			    (c->flags&0x1) == direction)
			    return c;
		}
	}
	return NULL;
}

static struct node_connection *
get_or_make_connection(struct routing_state *rstate,
		       const struct pubkey *from_id,
		       const struct pubkey *to_id)
{
	size_t i, n;
	struct node *from, *to;
	struct node_connection *nc;

	from = get_node(rstate, from_id);
	if (!from)
		from = new_node(rstate, from_id);
	to = get_node(rstate, to_id);
	if (!to)
		to = new_node(rstate, to_id);

	n = tal_count(to->in);
	for (i = 0; i < n; i++) {
		if (to->in[i]->src == from) {
			log_debug_struct(rstate->base_log,
					 "Updating existing route from %s",
					 struct pubkey, &from->id);
			log_add_struct(rstate->base_log, " to %s",
				       struct pubkey, &to->id);
			return to->in[i];
		}
	}

	log_debug_struct(rstate->base_log, "Creating new route from %s",
			 struct pubkey, &from->id);
	log_add_struct(rstate->base_log, " to %s", struct pubkey, &to->id);

	nc = tal(rstate, struct node_connection);
	nc->src = from;
	nc->dst = to;
	nc->channel_announcement = NULL;
	nc->channel_update = NULL;
	log_add(rstate->base_log, " = %p (%p->%p)", nc, from, to);

	/* Hook it into in/out arrays. */
	i = tal_count(to->in);
	tal_resize(&to->in, i+1);
	to->in[i] = nc;
	i = tal_count(from->out);
	tal_resize(&from->out, i+1);
	from->out[i] = nc;

	tal_add_destructor(nc, destroy_connection);
	return nc;
}

struct node_connection *half_add_connection(struct routing_state *rstate,
					    const struct pubkey *from,
					    const struct pubkey *to,
					    const struct channel_id *chanid,
					    const u16 flags
	)
{
	struct node_connection *nc;
	nc = get_or_make_connection(rstate, from, to);
	memcpy(&nc->channel_id, chanid, sizeof(nc->channel_id));
	nc->active = false;
	nc->last_timestamp = 0;
	nc->flags = flags;
	nc->min_blocks = 0;
	nc->proportional_fee = 0;
	nc->base_fee = 0;
	nc->delay = 0;
	return nc;
}



/* Updates existing route if required. */
struct node_connection *add_connection(struct routing_state *rstate,
				       const struct pubkey *from,
				       const struct pubkey *to,
				       u32 base_fee, s32 proportional_fee,
				       u32 delay, u32 min_blocks)
{
	struct node_connection *c = get_or_make_connection(rstate, from, to);
	c->base_fee = base_fee;
	c->proportional_fee = proportional_fee;
	c->delay = delay;
	c->min_blocks = min_blocks;
	c->active = true;
	c->last_timestamp = 0;
	memset(&c->channel_id, 0, sizeof(c->channel_id));
	c->flags = pubkey_cmp(from, to) > 0;
	return c;
}

void remove_connection(struct routing_state *rstate,
		       const struct pubkey *src, const struct pubkey *dst)
{
	struct node *from, *to;
	size_t i, num_edges;

	log_debug_struct(rstate->base_log, "Removing route from %s",
			 struct pubkey, src);
	log_add_struct(rstate->base_log, " to %s", struct pubkey, dst);

	from = get_node(rstate, src);
	to = get_node(rstate, dst);
	if (!from || !to) {
		log_debug(rstate->base_log, "Not found: src=%p dst=%p",
			  from, to);
		return;
	}

	num_edges = tal_count(from->out);

	for (i = 0; i < num_edges; i++) {
		if (from->out[i]->dst != to)
			continue;

		log_add(rstate->base_log, " Matched route %zu of %zu",
			i, num_edges);
		/* Destructor makes it delete itself */
		tal_free(from->out[i]);
		return;
	}
	log_add(rstate->base_log, " None of %zu routes matched", num_edges);
}

/* Too big to reach, but don't overflow if added. */
#define INFINITE 0x3FFFFFFFFFFFFFFFULL

static void clear_bfg(struct node_map *nodes)
{
	struct node *n;
	struct node_map_iter it;

	for (n = node_map_first(nodes, &it); n; n = node_map_next(nodes, &it)) {
		size_t i;
		for (i = 0; i < ARRAY_SIZE(n->bfg); i++) {
			n->bfg[i].total = INFINITE;
			n->bfg[i].risk = 0;
		}
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

/* Risk of passing through this channel.  We insert a tiny constant here
 * in order to prefer shorter routes, all things equal. */
static u64 risk_fee(s64 amount, u32 delay, double riskfactor)
{
	/* If fees are so negative we're making money, ignore risk. */
	if (amount < 0)
		return 1;

	return 1 + amount * delay * riskfactor / BLOCKS_PER_YEAR / 10000;
}

/* We track totals, rather than costs.  That's because the fee depends
 * on the current amount passing through. */
static void bfg_one_edge(struct node *node, size_t edgenum, double riskfactor)
{
	struct node_connection *c = node->in[edgenum];
	size_t h;

	assert(c->dst == node);
	for (h = 0; h < ROUTING_MAX_HOPS; h++) {
		/* FIXME: Bias against smaller channels. */
		s64 fee = connection_fee(c, node->bfg[h].total);
		u64 risk = node->bfg[h].risk + risk_fee(node->bfg[h].total + fee,
							c->delay, riskfactor);
		if (node->bfg[h].total + (s64)fee + (s64)risk
		    < c->src->bfg[h+1].total + (s64)c->src->bfg[h+1].risk) {
			c->src->bfg[h+1].total = node->bfg[h].total + fee;
			c->src->bfg[h+1].risk = risk;
			c->src->bfg[h+1].prev = c;
		}
	}
}

struct pubkey *find_route(const tal_t *ctx,
			struct routing_state *rstate,
			const struct pubkey *from,
			const struct pubkey *to,
			u64 msatoshi,
			double riskfactor,
			s64 *fee,
			struct node_connection ***route)
{
	struct node *n, *src, *dst;
	struct node_map_iter it;
	struct pubkey *first;
	int runs, i, best;

	/* Note: we map backwards, since we know the amount of satoshi we want
	 * at the end, and need to derive how much we need to send. */
	dst = get_node(rstate, from);
	src = get_node(rstate, to);

	if (!src) {
		log_info_struct(rstate->base_log, "find_route: cannot find %s",
				struct pubkey, to);
		return NULL;
	} else if (dst == src) {
		log_info_struct(rstate->base_log, "find_route: this is %s, refusing to create empty route",
				struct pubkey, to);
		return NULL;
	}

	/* Reset all the information. */
	clear_bfg(rstate->nodes);

	/* Bellman-Ford-Gibson: like Bellman-Ford, but keep values for
	 * every path length. */
	src->bfg[0].total = msatoshi;
	src->bfg[0].risk = 0;

	for (runs = 0; runs < ROUTING_MAX_HOPS; runs++) {
		log_debug(rstate->base_log, "Run %i", runs);
		/* Run through every edge. */
		for (n = node_map_first(rstate->nodes, &it);
		     n;
		     n = node_map_next(rstate->nodes, &it)) {
			size_t num_edges = tal_count(n->in);
			for (i = 0; i < num_edges; i++) {
				if (!n->in[i]->active)
					continue;
				bfg_one_edge(n, i, riskfactor);
				log_debug(rstate->base_log, "We seek %p->%p, this is %p -> %p",
					  dst, src, n->in[i]->src, n->in[i]->dst);
				log_debug_struct(rstate->base_log,
						 "Checking from %s",
						 struct pubkey,
						 &n->in[i]->src->id);
				log_add_struct(rstate->base_log,
					       " to %s",
					       struct pubkey,
					       &n->in[i]->dst->id);
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
		log_info_struct(rstate->base_log, "find_route: No route to %s",
				struct pubkey, to);
		return NULL;
	}

	/* Save route from *next* hop (we return first hop as peer).
	 * Note that we take our own fees into account for routing, even
	 * though we don't pay them: it presumably effects preference. */
	dst = dst->bfg[best].prev->dst;
	best--;

	first = &dst->id;

	*fee = dst->bfg[best].total - msatoshi;
	*route = tal_arr(ctx, struct node_connection *, best);
	for (i = 0, n = dst;
	     i < best;
	     n = n->bfg[best-i].prev->dst, i++) {
		(*route)[i] = n->bfg[best-i].prev;
	}
	assert(n == src);

	msatoshi += *fee;
	log_info(rstate->base_log, "find_route:");
	log_add_struct(rstate->base_log, "via %s", struct pubkey, first);
	/* If there are intermidiaries, dump them, and total fees. */
	if (best != 0) {
		for (i = 0; i < best; i++) {
			log_add_struct(rstate->base_log, " %s",
				       struct pubkey, &(*route)[i]->dst->id);
			log_add(rstate->base_log, "(%i+%i=%"PRIu64")",
				(*route)[i]->base_fee,
				(*route)[i]->proportional_fee,
				connection_fee((*route)[i], msatoshi));
			msatoshi -= connection_fee((*route)[i], msatoshi);
		}
		log_add(rstate->base_log, "=%"PRIi64"(%+"PRIi64")",
			(*route)[best-1]->dst->bfg[best-1].total, *fee);
	}
	return first;
}

static bool get_slash_u32(const char **arg, u32 *v)
{
	size_t len;
	char *endp;

	if (**arg != '/')
		return false;
	(*arg)++;
	len = strcspn(*arg, "/");
	*v = strtoul(*arg, &endp, 10);
	(*arg) += len;
	return (endp == *arg);
}

/* srcid/dstid/base/var/delay/minblocks */
char *opt_add_route(const char *arg, struct lightningd_state *dstate)
{
	size_t len;
	struct pubkey src, dst;
	u32 base, var, delay, minblocks;

	len = strcspn(arg, "/");
	if (!pubkey_from_hexstr(arg, len, &src))
		return "Bad src pubkey";
	arg += len + 1;
	len = strcspn(arg, "/");
	if (!pubkey_from_hexstr(arg, len, &dst))
		return "Bad dst pubkey";
	arg += len;

	if (!get_slash_u32(&arg, &base)
	    || !get_slash_u32(&arg, &var)
	    || !get_slash_u32(&arg, &delay)
	    || !get_slash_u32(&arg, &minblocks))
		return "Bad base/var/delay/minblocks";
	if (*arg)
		return "Data after minblocks";

	add_connection(dstate->rstate, &src, &dst, base, var, delay, minblocks);
	return NULL;
}

bool add_channel_direction(struct routing_state *rstate,
			   const struct pubkey *from,
			   const struct pubkey *to,
			   const int direction,
			   const struct channel_id *channel_id,
			   const u8 *announcement)
{
	struct node_connection *c = get_connection(rstate, from, to);
	if (c){
		/* Do not clobber connections added otherwise */
		memcpy(&c->channel_id, channel_id, sizeof(c->channel_id));
		c->flags = direction;
		return false;
	}else if(get_connection_by_cid(rstate, channel_id, direction)) {
		return false;
	}

	c = half_add_connection(rstate, from, to, channel_id, direction);

	/* Remember the announcement so we can forward it to new peers */
	tal_free(c->channel_announcement);
	c->channel_announcement = tal_dup_arr(c, u8, announcement,
					      tal_count(announcement), 0);
	return true;
}

/* BOLT #7:
 *
 * The following `address descriptor` types are defined:
 *
 * 1. `0`: padding.  data = none (length 0).
 * 1. `1`: IPv4. data = `[4:ipv4-addr][2:port]` (length 6)
 * 2. `2`: IPv6. data = `[16:ipv6-addr][2:port]` (length 18)
 */

/* FIXME: Don't just take first one, depends whether we have IPv6 ourselves */
/* Returns false iff it was malformed */
bool read_ip(const tal_t *ctx, const u8 *addresses, char **hostname,
		    int *port)
{
	size_t len = tal_count(addresses);
	const u8 *p = addresses;
	char tempaddr[INET6_ADDRSTRLEN];
	be16 portnum;

	*hostname = NULL;
	while (len) {
		u8 type = *p;
		p++;
		len--;

		switch (type) {
		case 0:
			break;
		case 1:
			/* BOLT #7:
			 *
			 * The receiving node SHOULD fail the connection if
			 * `addrlen` is insufficient to hold the address
			 * descriptors of the known types.
			 */
			if (len < 6)
				return false;
			inet_ntop(AF_INET, p, tempaddr, sizeof(tempaddr));
			memcpy(&portnum, p + 4, sizeof(portnum));
			*hostname = tal_strdup(ctx, tempaddr);
			*port = be16_to_cpu(portnum);
			return true;
		case 2:
			if (len < 18)
				return false;
			inet_ntop(AF_INET6, p, tempaddr, sizeof(tempaddr));
			memcpy(&portnum, p + 16, sizeof(portnum));
			*hostname = tal_strdup(ctx, tempaddr);
			*port = be16_to_cpu(portnum);
			return true;
		default:
			/* BOLT #7:
			 *
			 * The receiving node SHOULD ignore the first `address
			 * descriptor` which does not match the types defined
			 * above.
			 */
			return true;
		}
	}

	/* Not a fatal error. */
	return true;
}

/* BOLT #7:
 *
 * The creating node SHOULD fill `addresses` with an address descriptor for
 * each public network address which expects incoming connections, and MUST
 * set `addrlen` to the number of bytes in `addresses`.  Non-zero typed
 * address descriptors MUST be placed in ascending order; any number of
 * zero-typed address descriptors MAY be placed anywhere, but SHOULD only be
 * used for aligning fields following `addresses`.
 *
 * The creating node MUST NOT create a type 1 or type 2 address descriptor
 * with `port` equal to zero, and SHOULD ensure `ipv4-addr` and `ipv6-addr`
 * are routable addresses.  The creating node MUST NOT include more than one
 * `address descriptor` of the same type.
 */
/* FIXME: handle case where we have both ipv6 and ipv4 addresses! */
u8 *write_ip(const tal_t *ctx, const char *srcip, int port)
{
	u8 *address;
	be16 portnum = cpu_to_be16(port);

	if (!port)
		return tal_arr(ctx, u8, 0);

	if (!strchr(srcip, ':')) {
		address = tal_arr(ctx, u8, 7);
		address[0] = 1;
		inet_pton(AF_INET, srcip, address+1);
		memcpy(address + 5, &portnum, sizeof(portnum));
		return address;
	} else {
		address = tal_arr(ctx, u8, 18);
		address[0] = 2;
		inet_pton(AF_INET6, srcip, address+1);
		memcpy(address + 17, &portnum, sizeof(portnum));
		return address;
	}
}

void handle_channel_announcement(
	struct routing_state *rstate,
	const u8 *announce, size_t len)
{
	u8 *serialized;
	bool forward = false;
	secp256k1_ecdsa_signature node_signature_1;
	secp256k1_ecdsa_signature node_signature_2;
	struct channel_id channel_id;
	secp256k1_ecdsa_signature bitcoin_signature_1;
	secp256k1_ecdsa_signature bitcoin_signature_2;
	struct pubkey node_id_1;
	struct pubkey node_id_2;
	struct pubkey bitcoin_key_1;
	struct pubkey bitcoin_key_2;
	const tal_t *tmpctx = tal_tmpctx(rstate);
	u8 *features;

	serialized = tal_dup_arr(tmpctx, u8, announce, len, 0);
	if (!fromwire_channel_announcement(tmpctx, serialized, NULL,
					   &node_signature_1, &node_signature_2,
					   &bitcoin_signature_1,
					   &bitcoin_signature_2,
					   &channel_id,
					   &node_id_1, &node_id_2,
					   &bitcoin_key_1, &bitcoin_key_2,
					   &features)) {
		tal_free(tmpctx);
		return;
	}

	// FIXME: Check features!
	//FIXME(cdecker) Check signatures, when the spec is settled
	//FIXME(cdecker) Check chain topology for the anchor TX

	log_debug(rstate->base_log,
		  "Received channel_announcement for channel %d:%d:%d",
		  channel_id.blocknum,
		  channel_id.txnum,
		  channel_id.outnum
		);

	forward |= add_channel_direction(rstate, &node_id_1,
					 &node_id_2, 0, &channel_id,
					 serialized);
	forward |= add_channel_direction(rstate, &node_id_2,
					 &node_id_1, 1, &channel_id,
					 serialized);
	if (!forward){
		log_debug(rstate->base_log, "Not forwarding channel_announcement");
		tal_free(tmpctx);
		return;
	}

	u8 *tag = tal_arr(tmpctx, u8, 0);
	towire_channel_id(&tag, &channel_id);
	queue_broadcast(rstate->broadcasts, WIRE_CHANNEL_ANNOUNCEMENT,
			tag, serialized);

	tal_free(tmpctx);
}

void handle_channel_update(struct routing_state *rstate, const u8 *update, size_t len)
{
	u8 *serialized;
	struct node_connection *c;
	secp256k1_ecdsa_signature signature;
	struct channel_id channel_id;
	u32 timestamp;
	u16 flags;
	u16 expiry;
	u32 htlc_minimum_msat;
	u32 fee_base_msat;
	u32 fee_proportional_millionths;
	const tal_t *tmpctx = tal_tmpctx(rstate);

	serialized = tal_dup_arr(tmpctx, u8, update, len, 0);
	if (!fromwire_channel_update(serialized, NULL, &signature, &channel_id,
				     &timestamp, &flags, &expiry,
				     &htlc_minimum_msat, &fee_base_msat,
				     &fee_proportional_millionths)) {
		tal_free(tmpctx);
		return;
	}


	log_debug(rstate->base_log, "Received channel_update for channel %d:%d:%d(%d)",
		  channel_id.blocknum,
		  channel_id.txnum,
		  channel_id.outnum,
		  flags & 0x01
		);

	c = get_connection_by_cid(rstate, &channel_id, flags & 0x1);

	if (!c) {
		log_debug(rstate->base_log, "Ignoring update for unknown channel %d:%d:%d",
			  channel_id.blocknum,
			  channel_id.txnum,
			  channel_id.outnum
			);
		tal_free(tmpctx);
		return;
	} else if (c->last_timestamp >= timestamp) {
		log_debug(rstate->base_log, "Ignoring outdated update.");
		tal_free(tmpctx);
		return;
	}

	//FIXME(cdecker) Check signatures
	c->last_timestamp = timestamp;
	c->delay = expiry;
	c->htlc_minimum_msat = htlc_minimum_msat;
	c->base_fee = fee_base_msat;
	c->proportional_fee = fee_proportional_millionths;
	c->active = true;
	log_debug(rstate->base_log, "Channel %d:%d:%d(%d) was updated.",
		  channel_id.blocknum,
		  channel_id.txnum,
		  channel_id.outnum,
		  flags
		);

	u8 *tag = tal_arr(tmpctx, u8, 0);
	towire_channel_id(&tag, &channel_id);
	queue_broadcast(rstate->broadcasts,
			WIRE_CHANNEL_UPDATE,
			tag,
			serialized);

	tal_free(c->channel_update);
	c->channel_update = tal_steal(c, serialized);
	tal_free(tmpctx);
}

void handle_node_announcement(
	struct routing_state *rstate, const u8 *node_ann, size_t len)
{
	u8 *serialized;
	struct sha256_double hash;
	struct node *node;
	secp256k1_ecdsa_signature signature;
	u32 timestamp;
	struct pubkey node_id;
	u8 rgb_color[3];
	u8 alias[32];
	u8 *features, *addresses;
	const tal_t *tmpctx = tal_tmpctx(rstate);

	serialized = tal_dup_arr(tmpctx, u8, node_ann, len, 0);
	if (!fromwire_node_announcement(tmpctx, serialized, NULL,
					&signature, &timestamp,
					&node_id, rgb_color, alias, &features,
					&addresses)) {
		tal_free(tmpctx);
		return;
	}

	// FIXME: Check features!
	log_debug_struct(rstate->base_log,
			 "Received node_announcement for node %s",
			 struct pubkey, &node_id);

	sha256_double(&hash, serialized + 66, tal_count(serialized) - 66);
	if (!check_signed_hash(&hash, &signature, &node_id)) {
		log_debug(rstate->base_log,
			  "Ignoring node announcement, signature verification failed.");
		tal_free(tmpctx);
		return;
	}
	node = get_node(rstate, &node_id);

	if (!node) {
		log_debug(rstate->base_log,
			  "Node not found, was the node_announcement preceeded by at least channel_announcement?");
		tal_free(tmpctx);
		return;
	} else if (node->last_timestamp >= timestamp) {
		log_debug(rstate->base_log,
			  "Ignoring node announcement, it's outdated.");
		tal_free(tmpctx);
		return;
	}

	node->last_timestamp = timestamp;
	node->hostname = tal_free(node->hostname);
	if (!read_ip(node, addresses, &node->hostname, &node->port)) {
		/* FIXME: SHOULD fail connection here. */
		tal_free(serialized);
		return;
	}
	memcpy(node->rgb_color, rgb_color, 3);

	u8 *tag = tal_arr(tmpctx, u8, 0);
	towire_pubkey(&tag, &node_id);
	queue_broadcast(rstate->broadcasts,
			WIRE_NODE_ANNOUNCEMENT,
			tag,
			serialized);
	tal_free(node->node_announcement);
	node->node_announcement = tal_steal(node, serialized);
	tal_free(tmpctx);
}
