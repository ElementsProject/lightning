#include "routing.h"
#include <arpa/inet.h>
#include <bitcoin/block.h>
#include <ccan/array_size/array_size.h>
#include <ccan/crypto/siphash24/siphash24.h>
#include <ccan/endian/endian.h>
#include <ccan/structeq/structeq.h>
#include <ccan/tal/str/str.h>
#include <common/overflows.h>
#include <common/pseudorand.h>
#include <common/status.h>
#include <common/type_to_string.h>
#include <inttypes.h>
#include <wire/gen_peer_wire.h>

/* 365.25 * 24 * 60 / 10 */
#define BLOCKS_PER_YEAR 52596

struct routing_state *new_routing_state(const tal_t *ctx,
					const struct sha256_double *chain_hash)
{
	struct routing_state *rstate = tal(ctx, struct routing_state);
	rstate->nodes = empty_node_map(rstate);
	rstate->broadcasts = new_broadcast_state(rstate);
	rstate->chain_hash = *chain_hash;
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
	tal_add_destructor(map, node_map_clear);
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
	n->alias = NULL;
	n->node_announcement = NULL;
	n->addresses = tal_arr(n, struct ipaddr, 0);
	node_map_add(rstate->nodes, n);
	tal_add_destructor(n, destroy_node);

	return n;
}

struct node *add_node(
	struct routing_state *rstate,
	const struct pubkey *pk)
{
	struct node *n = get_node(rstate, pk);
	if (!n) {
		n = new_node(rstate, pk);
		status_trace("Creating new node %s",
			     type_to_string(trc, struct pubkey, pk));
	} else {
		status_trace("Update existing node %s",
			     type_to_string(trc, struct pubkey, pk));
	}
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
		/* FIXME! */
		abort();
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

struct node_connection *get_connection_by_scid(const struct routing_state *rstate,
					      const struct short_channel_id *schanid,
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
			if (short_channel_id_eq(&c->short_channel_id, schanid) &&
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
			status_trace("Updating existing route from %s to %s",
				     type_to_string(trc, struct pubkey,
						    &from->id),
				     type_to_string(trc, struct pubkey,
						    &to->id));
			return to->in[i];
		}
	}

	status_trace("Creating new route from %s to %s",
		     type_to_string(trc, struct pubkey, &from->id),
		     type_to_string(trc, struct pubkey, &to->id));

	nc = tal(rstate, struct node_connection);
	nc->src = from;
	nc->dst = to;
	nc->channel_announcement = NULL;
	nc->channel_update = NULL;

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
					    const struct short_channel_id *schanid,
					    const u16 flags
	)
{
	struct node_connection *nc;
	nc = get_or_make_connection(rstate, from, to);
	nc->short_channel_id = *schanid;
	nc->active = false;
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
	memset(&c->short_channel_id, 0, sizeof(c->short_channel_id));
	c->flags = get_channel_direction(from, to);
	return c;
}

void remove_connection(struct routing_state *rstate,
		       const struct pubkey *src, const struct pubkey *dst)
{
	struct node *from, *to;
	size_t i, num_edges;

	status_trace("Removing route from %s to %s",
		     type_to_string(trc, struct pubkey, src),
		     type_to_string(trc, struct pubkey, dst));

	from = get_node(rstate, src);
	to = get_node(rstate, dst);
	if (!from || !to) {
		status_trace("Not found: src=%p dst=%p", from, to);
		return;
	}

	num_edges = tal_count(from->out);

	for (i = 0; i < num_edges; i++) {
		if (from->out[i]->dst != to)
			continue;

		status_trace("Matched route %zu of %zu", i, num_edges);
		/* Destructor makes it delete itself */
		tal_free(from->out[i]);
		return;
	}
	status_trace(" None of %zu routes matched", num_edges);
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
		s64 fee;
		u64 risk;

		if (node->bfg[h].total == INFINITE)
			continue;

		fee = connection_fee(c, node->bfg[h].total);
		risk = node->bfg[h].risk + risk_fee(node->bfg[h].total + fee,
						    c->delay, riskfactor);
		if (node->bfg[h].total + (s64)fee + (s64)risk
		    < c->src->bfg[h+1].total + (s64)c->src->bfg[h+1].risk) {
			status_trace("...%s can reach here in hoplen %zu total %"PRIu64,
				     type_to_string(trc, struct pubkey,
						    &c->src->id),
				     h, node->bfg[h].total + fee);
			c->src->bfg[h+1].total = node->bfg[h].total + fee;
			c->src->bfg[h+1].risk = risk;
			c->src->bfg[h+1].prev = c;
		}
	}
}

struct node_connection *
find_route(const tal_t *ctx, struct routing_state *rstate,
	   const struct pubkey *from, const struct pubkey *to, u64 msatoshi,
	   double riskfactor, s64 *fee, struct node_connection ***route)
{
	struct node *n, *src, *dst;
	struct node_map_iter it;
	struct node_connection *first_conn;
	int runs, i, best;

	/* Note: we map backwards, since we know the amount of satoshi we want
	 * at the end, and need to derive how much we need to send. */
	dst = get_node(rstate, from);
	src = get_node(rstate, to);

	if (!src) {
		status_trace("find_route: cannot find %s",
			     type_to_string(trc, struct pubkey, to));
		return NULL;
	} else if (!dst) {
		status_trace("find_route: cannot find myself (%s)",
			     type_to_string(trc, struct pubkey, to));
		return NULL;
	} else if (dst == src) {
		status_trace("find_route: this is %s, refusing to create empty route",
			     type_to_string(trc, struct pubkey, to));
		return NULL;
	}

	/* Reset all the information. */
	clear_bfg(rstate->nodes);

	/* Bellman-Ford-Gibson: like Bellman-Ford, but keep values for
	 * every path length. */
	src->bfg[0].total = msatoshi;
	src->bfg[0].risk = 0;

	for (runs = 0; runs < ROUTING_MAX_HOPS; runs++) {
		status_trace("Run %i", runs);
		/* Run through every edge. */
		for (n = node_map_first(rstate->nodes, &it);
		     n;
		     n = node_map_next(rstate->nodes, &it)) {
			size_t num_edges = tal_count(n->in);
			for (i = 0; i < num_edges; i++) {
				status_trace("Node %s edge %i/%zu",
					     type_to_string(trc, struct pubkey,
							    &n->id),
					     i, num_edges);
				if (!n->in[i]->active) {
					status_trace("...inactive");
					continue;
				}
				bfg_one_edge(n, i, riskfactor);
				status_trace("...done");
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
		status_trace("find_route: No route to %s",
			     type_to_string(trc, struct pubkey, to));
		return NULL;
	}

	/* Save route from *next* hop (we return first hop as peer).
	 * Note that we take our own fees into account for routing, even
	 * though we don't pay them: it presumably effects preference. */
	first_conn = dst->bfg[best].prev;
	dst = dst->bfg[best].prev->dst;
	best--;

	*fee = dst->bfg[best].total - msatoshi;
	*route = tal_arr(ctx, struct node_connection *, best);
	for (i = 0, n = dst;
	     i < best;
	     n = n->bfg[best-i].prev->dst, i++) {
		(*route)[i] = n->bfg[best-i].prev;
	}
	assert(n == src);

	msatoshi += *fee;
	status_trace("find_route: via %s",
		     type_to_string(trc, struct pubkey, &first_conn->dst->id));
	/* If there are intermidiaries, dump them, and total fees. */
	if (best != 0) {
		for (i = 0; i < best; i++) {
			status_trace(" %s (%i+%i=%"PRIu64")",
				     type_to_string(trc, struct pubkey,
						    &(*route)[i]->dst->id),
				     (*route)[i]->base_fee,
				     (*route)[i]->proportional_fee,
				     connection_fee((*route)[i], msatoshi));
			msatoshi -= connection_fee((*route)[i], msatoshi);
		}
		status_trace(" =%"PRIi64"(%+"PRIi64")",
			     (*route)[best-1]->dst->bfg[best-1].total, *fee);
	}
	return first_conn;
}

bool add_channel_direction(struct routing_state *rstate,
			   const struct pubkey *from,
			   const struct pubkey *to,
			   const struct short_channel_id *short_channel_id,
			   const u8 *announcement)
{
	struct node_connection *c = get_connection(rstate, from, to);
	u16 direction = get_channel_direction(from, to);
	if (c){
		/* Do not clobber connections added otherwise */
		memcpy(&c->short_channel_id, short_channel_id,
		       sizeof(c->short_channel_id));
		c->flags = direction;
		return false;
	}else if(get_connection_by_scid(rstate, short_channel_id, direction)) {
		return false;
	}

	c = half_add_connection(rstate, from, to, short_channel_id, direction);

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
 * * `0`: padding.  data = none (length 0).
 * * `1`: ipv4. data = `[4:ipv4_addr][2:port]` (length 6)
 * * `2`: ipv6. data = `[16:ipv6_addr][2:port]` (length 18)
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
 * with `port` equal to zero, and SHOULD ensure `ipv4_addr` and `ipv6_addr`
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

/* Verify the signature of a channel_update message */
static bool check_channel_update(const struct pubkey *node_key,
				 const secp256k1_ecdsa_signature *node_sig,
				 const u8 *update)
{
	/* 2 byte msg type + 64 byte signatures */
	int offset = 66;
	struct sha256_double hash;
	sha256_double(&hash, update + offset, tal_len(update) - offset);

	return check_signed_hash(&hash, node_sig, node_key);
}

static bool check_channel_announcement(
    const struct pubkey *node1_key, const struct pubkey *node2_key,
    const struct pubkey *bitcoin1_key, const struct pubkey *bitcoin2_key,
    const secp256k1_ecdsa_signature *node1_sig,
    const secp256k1_ecdsa_signature *node2_sig,
    const secp256k1_ecdsa_signature *bitcoin1_sig,
    const secp256k1_ecdsa_signature *bitcoin2_sig, const u8 *announcement)
{
	/* 2 byte msg type + 256 byte signatures */
	int offset = 258;
	struct sha256_double hash;
	sha256_double(&hash, announcement + offset,
		      tal_len(announcement) - offset);

	return check_signed_hash(&hash, node1_sig, node1_key) &&
	       check_signed_hash(&hash, node2_sig, node2_key) &&
	       check_signed_hash(&hash, bitcoin1_sig, bitcoin1_key) &&
	       check_signed_hash(&hash, bitcoin2_sig, bitcoin2_key);
}

void handle_channel_announcement(
	struct routing_state *rstate,
	const u8 *announce, size_t len)
{
	u8 *serialized;
	bool forward = false;
	secp256k1_ecdsa_signature node_signature_1;
	secp256k1_ecdsa_signature node_signature_2;
	struct short_channel_id short_channel_id;
	secp256k1_ecdsa_signature bitcoin_signature_1;
	secp256k1_ecdsa_signature bitcoin_signature_2;
	struct pubkey node_id_1;
	struct pubkey node_id_2;
	struct pubkey bitcoin_key_1;
	struct pubkey bitcoin_key_2;
	struct sha256_double chain_hash;
	const tal_t *tmpctx = tal_tmpctx(rstate);
	u8 *features;

	serialized = tal_dup_arr(tmpctx, u8, announce, len, 0);
	if (!fromwire_channel_announcement(tmpctx, serialized, NULL,
					   &node_signature_1, &node_signature_2,
					   &bitcoin_signature_1,
					   &bitcoin_signature_2,
					   &features,
					   &chain_hash,
					   &short_channel_id,
					   &node_id_1, &node_id_2,
					   &bitcoin_key_1, &bitcoin_key_2)) {
		tal_free(tmpctx);
		return;
	}

	/* BOLT #7:
	 *
	 * The receiving node MUST ignore the message if the specified
	 * `chain_hash` is unknown to the receiver.
	 */
	if (!structeq(&chain_hash, &rstate->chain_hash)) {
		status_trace("Received channel_announcement for unknown chain"
			     " %s",
			     type_to_string(tmpctx, struct sha256_double,
					    &chain_hash));
		tal_free(tmpctx);
		return;
	}

	// FIXME: Check features!
	//FIXME(cdecker) Check chain topology for the anchor TX

	status_trace("Received channel_announcement for channel %s",
		     type_to_string(trc, struct short_channel_id,
				    &short_channel_id));

	if (!check_channel_announcement(&node_id_1, &node_id_2, &bitcoin_key_1,
					&bitcoin_key_2, &node_signature_1,
					&node_signature_2, &bitcoin_signature_1,
					&bitcoin_signature_2, serialized)) {
		status_trace(
		    "Signature verification of channel announcement failed");
		tal_free(tmpctx);
		return;
	}

	forward |= add_channel_direction(rstate, &node_id_1, &node_id_2,
					 &short_channel_id, serialized);
	forward |= add_channel_direction(rstate, &node_id_2, &node_id_1,
					 &short_channel_id, serialized);
	if (!forward) {
		status_trace("Not forwarding channel_announcement");
		tal_free(tmpctx);
		return;
	}

	u8 *tag = tal_arr(tmpctx, u8, 0);
	towire_short_channel_id(&tag, &short_channel_id);
	queue_broadcast(rstate->broadcasts, WIRE_CHANNEL_ANNOUNCEMENT,
			tag, serialized);

	tal_free(tmpctx);
}

void handle_channel_update(struct routing_state *rstate, const u8 *update, size_t len)
{
	u8 *serialized;
	struct node_connection *c;
	secp256k1_ecdsa_signature signature;
	struct short_channel_id short_channel_id;
	u32 timestamp;
	u16 flags;
	u16 expiry;
	u64 htlc_minimum_msat;
	u32 fee_base_msat;
	u32 fee_proportional_millionths;
	const tal_t *tmpctx = tal_tmpctx(rstate);
	struct sha256_double chain_hash;

	serialized = tal_dup_arr(tmpctx, u8, update, len, 0);
	if (!fromwire_channel_update(serialized, NULL, &signature,
				     &chain_hash, &short_channel_id,
				     &timestamp, &flags, &expiry,
				     &htlc_minimum_msat, &fee_base_msat,
				     &fee_proportional_millionths)) {
		tal_free(tmpctx);
		return;
	}

	/* BOLT #7:
	 *
	 * The receiving node MUST ignore the channel update if the specified
	 * `chain_hash` value is unknown, meaning it isn't active on the
	 * specified chain. */
	if (!structeq(&chain_hash, &rstate->chain_hash)) {
		status_trace("Received channel_update for unknown chain %s",
			     type_to_string(tmpctx, struct sha256_double,
					    &chain_hash));
		tal_free(tmpctx);
		return;
	}

	status_trace("Received channel_update for channel %s(%d)",
		     type_to_string(trc, struct short_channel_id,
				    &short_channel_id),
		     flags & 0x01);

	c = get_connection_by_scid(rstate, &short_channel_id, flags & 0x1);

	if (!c) {
		status_trace("Ignoring update for unknown channel %s",
			     type_to_string(trc, struct short_channel_id,
					    &short_channel_id));
		tal_free(tmpctx);
		return;
	} else if (c->channel_update && c->last_timestamp >= timestamp) {
		status_trace("Ignoring outdated update.");
		tal_free(tmpctx);
		return;
	} else if (!check_channel_update(&c->src->id, &signature, serialized)) {
		status_trace("Signature verification failed.");
		tal_free(tmpctx);
		return;
	}

	//FIXME(cdecker) Check signatures
	c->last_timestamp = timestamp;
	c->delay = expiry;
	c->htlc_minimum_msat = htlc_minimum_msat;
	c->base_fee = fee_base_msat;
	c->proportional_fee = fee_proportional_millionths;
	c->active = (flags & ROUTING_FLAGS_DISABLED) == 0;
	status_trace("Channel %s(%d) was updated.",
		     type_to_string(trc, struct short_channel_id,
				    &short_channel_id),
		     flags);

	u8 *tag = tal_arr(tmpctx, u8, 0);
	towire_short_channel_id(&tag, &short_channel_id);
	towire_u16(&tag, flags & 0x1);
	queue_broadcast(rstate->broadcasts,
			WIRE_CHANNEL_UPDATE,
			tag,
			serialized);

	tal_free(c->channel_update);
	c->channel_update = tal_steal(c, serialized);
	tal_free(tmpctx);
}

static struct ipaddr *read_addresses(const tal_t *ctx, u8 *ser)
{
	const u8 *cursor = ser;
	size_t max = tal_len(ser);
	struct ipaddr *ipaddrs = tal_arr(ctx, struct ipaddr, 0);
	int numaddrs = 0;
	while (cursor < ser + max) {
		numaddrs++;
		tal_resize(&ipaddrs, numaddrs);
		fromwire_ipaddr(&cursor, &max, &ipaddrs[numaddrs-1]);
		if (cursor == NULL) {
			/* Parsing address failed */
			return tal_free(ipaddrs);
		}
	}
	return ipaddrs;
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
	struct ipaddr *ipaddrs;

	serialized = tal_dup_arr(tmpctx, u8, node_ann, len, 0);
	if (!fromwire_node_announcement(tmpctx, serialized, NULL,
					&signature, &features, &timestamp,
					&node_id, rgb_color, alias,
					&addresses)) {
		tal_free(tmpctx);
		return;
	}

	// FIXME: Check features!
	status_trace("Received node_announcement for node %s",
		     type_to_string(trc, struct pubkey, &node_id));

	sha256_double(&hash, serialized + 66, tal_count(serialized) - 66);
	if (!check_signed_hash(&hash, &signature, &node_id)) {
		status_trace("Ignoring node announcement, signature verification failed.");
		tal_free(tmpctx);
		return;
	}
	node = get_node(rstate, &node_id);

	if (!node) {
		status_trace("Node not found, was the node_announcement preceeded by at least channel_announcement?");
		tal_free(tmpctx);
		return;
	} else if (node->node_announcement && node->last_timestamp >= timestamp) {
		status_trace("Ignoring node announcement, it's outdated.");
		tal_free(tmpctx);
		return;
	}

	ipaddrs = read_addresses(tmpctx, addresses);
	if (!ipaddrs) {
		status_trace("Unable to parse addresses.");
		tal_free(serialized);
		return;
	}
	tal_free(node->addresses);
	node->addresses = tal_steal(node, ipaddrs);

	node->last_timestamp = timestamp;

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

struct route_hop *get_route(tal_t *ctx, struct routing_state *rstate,
			    const struct pubkey *source,
			    const struct pubkey *destination,
			    const u32 msatoshi, double riskfactor)
{
	struct node_connection **route;
	u64 total_amount;
	unsigned int total_delay;
	s64 fee;
	struct route_hop *hops;
	int i;
	struct node_connection *first_conn;

	first_conn = find_route(ctx, rstate, source, destination, msatoshi,
				riskfactor, &fee, &route);

	if (!first_conn) {
		return NULL;
	}

	/* Fees, delays need to be calculated backwards along route. */
	hops = tal_arr(ctx, struct route_hop, tal_count(route) + 1);
	total_amount = msatoshi;
	total_delay = 0;

	for (i = tal_count(route) - 1; i >= 0; i--) {
		hops[i + 1].channel_id = route[i]->short_channel_id;
		hops[i + 1].nodeid = route[i]->dst->id;
		hops[i + 1].amount = total_amount;
		total_amount += connection_fee(route[i], total_amount);

		total_delay += route[i]->delay;
		if (total_delay < route[i]->min_blocks)
			total_delay = route[i]->min_blocks;
		hops[i + 1].delay = total_delay;
	}
	/* Backfill the first hop manually */
	hops[0].channel_id = first_conn->short_channel_id;
	hops[0].nodeid = first_conn->dst->id;
	/* We don't charge ourselves any fees. */
	hops[0].amount = total_amount;
	/* We do require delay though. */
	total_delay += first_conn->delay;
	hops[0].delay = total_delay;
	return hops;
}
