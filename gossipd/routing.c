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
#include <common/wireaddr.h>
#include <inttypes.h>
#include <wire/gen_peer_wire.h>

/* 365.25 * 24 * 60 / 10 */
#define BLOCKS_PER_YEAR 52596

static struct node_map *empty_node_map(const tal_t *ctx)
{
	struct node_map *map = tal(ctx, struct node_map);
	node_map_init(map);
	tal_add_destructor(map, node_map_clear);
	return map;
}

struct routing_state *new_routing_state(const tal_t *ctx,
					const struct sha256_double *chain_hash,
					const struct pubkey *local_id)
{
	struct routing_state *rstate = tal(ctx, struct routing_state);
	rstate->nodes = empty_node_map(rstate);
	rstate->broadcasts = new_broadcast_state(rstate);
	rstate->chain_hash = *chain_hash;
	rstate->local_id = *local_id;
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

static void destroy_node(struct node *node)
{
	/* These remove themselves from the array. */
	while (tal_count(node->in))
		tal_free(node->in[0]);
	while (tal_count(node->out))
		tal_free(node->out[0]);
}

static struct node *get_node(struct routing_state *rstate,
		      const struct pubkey *id)
{
	return node_map_get(rstate->nodes, &id->pubkey);
}

static struct node *new_node(struct routing_state *rstate,
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
	n->last_timestamp = -1;
	n->addresses = tal_arr(n, struct wireaddr, 0);
	node_map_add(rstate->nodes, n);
	tal_add_destructor(n, destroy_node);

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

static struct node_connection * get_connection(struct routing_state *rstate,
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
	nc->last_timestamp = -1;
	return nc;
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

static struct node_connection *
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
	/* If there are intermediaries, dump them, and total fees. */
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

static bool add_channel_direction(struct routing_state *rstate,
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

bool handle_channel_announcement(
	struct routing_state *rstate,
	const u8 *announce, size_t len)
{
	u8 *serialized;
	bool forward = false, local, sigfail;
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
		return false;
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
		return false;
	}

	// FIXME: Check features!
	//FIXME(cdecker) Check chain topology for the anchor TX

	status_trace("Received channel_announcement for channel %s",
		     type_to_string(trc, struct short_channel_id,
				    &short_channel_id));

	local = pubkey_eq(&node_id_1, &rstate->local_id) ||
		pubkey_eq(&node_id_2, &rstate->local_id);
	sigfail = !check_channel_announcement(
	    &node_id_1, &node_id_2, &bitcoin_key_1, &bitcoin_key_2,
	    &node_signature_1, &node_signature_2, &bitcoin_signature_1,
	    &bitcoin_signature_2, serialized);

	if (sigfail && !local) {
		status_trace(
		    "Signature verification of channel announcement failed");
		tal_free(tmpctx);
		return false;
	}

	forward |= add_channel_direction(rstate, &node_id_1, &node_id_2,
					 &short_channel_id, serialized);
	forward |= add_channel_direction(rstate, &node_id_2, &node_id_1,
					 &short_channel_id, serialized);

	if (!forward) {
		status_trace("Not forwarding channel_announcement");
		tal_free(tmpctx);
		/* This will not be forwarded so we do not want to
		 * announce the node either, others might drop it. */
		return false;
	}

	u8 *tag = tal_arr(tmpctx, u8, 0);
	towire_short_channel_id(&tag, &short_channel_id);
	queue_broadcast(rstate->broadcasts, WIRE_CHANNEL_ANNOUNCEMENT,
			tag, serialized);

	tal_free(tmpctx);
	return local;
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
	} else if (c->last_timestamp >= timestamp) {
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

static struct wireaddr *read_addresses(const tal_t *ctx, const u8 *ser)
{
	const u8 *cursor = ser;
	size_t max = tal_len(ser);
	struct wireaddr *wireaddrs = tal_arr(ctx, struct wireaddr, 0);
	int numaddrs = 0;
	while (cursor && cursor < ser + max) {
		struct wireaddr wireaddr;

		/* Skip any padding */
		while (max && cursor[0] == ADDR_TYPE_PADDING)
			fromwire_u8(&cursor, &max);

		/* BOLT #7:
		 *
		 * The receiving node SHOULD ignore the first `address
		 * descriptor` which does not match the types defined
		 * above.
		 */
		if (!fromwire_wireaddr(&cursor, &max, &wireaddr)) {
			if (!cursor)
				/* Parsing address failed */
				return tal_free(wireaddrs);
			/* Unknown type, stop there. */
			break;
		}

		tal_resize(&wireaddrs, numaddrs+1);
		wireaddrs[numaddrs] = wireaddr;
		numaddrs++;
	}
	return wireaddrs;
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
	struct wireaddr *wireaddrs;

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
		status_trace("Node not found, was the node_announcement preceded by at least channel_announcement?");
		tal_free(tmpctx);
		return;
	} else if (node->last_timestamp >= timestamp) {
		status_trace("Ignoring node announcement, it's outdated.");
		tal_free(tmpctx);
		return;
	}

	wireaddrs = read_addresses(tmpctx, addresses);
	if (!wireaddrs) {
		status_trace("Unable to parse addresses.");
		tal_free(serialized);
		return;
	}
	tal_free(node->addresses);
	node->addresses = tal_steal(node, wireaddrs);

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
			    const u32 msatoshi, double riskfactor,
			    u32 final_cltv)
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
	total_delay = final_cltv;

	for (i = tal_count(route) - 1; i >= 0; i--) {
		hops[i + 1].channel_id = route[i]->short_channel_id;
		hops[i + 1].nodeid = route[i]->dst->id;
		hops[i + 1].amount = total_amount;
		total_amount += connection_fee(route[i], total_amount);

		hops[i + 1].delay = total_delay;
		total_delay += route[i]->delay;
	}
	/* Backfill the first hop manually */
	hops[0].channel_id = first_conn->short_channel_id;
	hops[0].nodeid = first_conn->dst->id;
	/* We don't charge ourselves any fees, nor require delay */
	hops[0].amount = total_amount;
	hops[0].delay = total_delay;

	/* FIXME: Shadow route! */
	return hops;
}
