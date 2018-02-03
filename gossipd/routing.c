#include "routing.h"
#include <arpa/inet.h>
#include <bitcoin/block.h>
#include <bitcoin/script.h>
#include <ccan/array_size/array_size.h>
#include <ccan/crypto/siphash24/siphash24.h>
#include <ccan/endian/endian.h>
#include <ccan/structeq/structeq.h>
#include <ccan/tal/str/str.h>
#include <ccan/time/time.h>
#include <common/features.h>
#include <common/pseudorand.h>
#include <common/status.h>
#include <common/type_to_string.h>
#include <common/wireaddr.h>
#include <inttypes.h>
#include <wire/gen_onion_wire.h>
#include <wire/gen_peer_wire.h>

#ifndef SUPERVERBOSE
#define SUPERVERBOSE(...)
#endif

/* 365.25 * 24 * 60 / 10 */
#define BLOCKS_PER_YEAR 52596

/* For overflow avoidance, we never deal with msatoshi > 40 bits. */
#define MAX_MSATOSHI (1ULL << 40)

/* Proportional fee must be less than 24 bits, so never overflows. */
#define MAX_PROPORTIONAL_FEE (1 << 24)

/* We've unpacked and checked its signatures, now we wait for master to tell
 * us the txout to check */
struct pending_cannouncement {
	/* Unpacked fields here */
	struct short_channel_id short_channel_id;
	struct pubkey node_id_1;
	struct pubkey node_id_2;
	struct pubkey bitcoin_key_1;
	struct pubkey bitcoin_key_2;

	/* The raw bits */
	const u8 *announce;

	/* Deferred updates, if we received them while waiting for
	 * this (one for each direction) */
	const u8 *updates[2];

	/* Only ever replace with newer updates */
	u32 update_timestamps[2];
};

struct pending_node_announce {
	struct pubkey nodeid;
	u8 *node_announcement;
	u32 timestamp;
};

static const secp256k1_pubkey *
pending_node_announce_keyof(const struct pending_node_announce *a)
{
	return &a->nodeid.pubkey;
}

static bool pending_node_announce_eq(const struct pending_node_announce *pna,
				     const secp256k1_pubkey *key)
{
	return structeq(&pna->nodeid.pubkey, key);
}

HTABLE_DEFINE_TYPE(struct pending_node_announce, pending_node_announce_keyof,
		   node_map_hash_key, pending_node_announce_eq,
		   pending_node_map);

/**
 * routing_channel keeps track of the indices in the broadcast queue
 * for the corresponding messages. This way we always know exactly
 * which broadcast to replace, and don't have to search for it */
enum gossip_msg_indexes {
	MSG_INDEX_CUPDATE_0,
	MSG_INDEX_CUPDATE_1,
	MSG_INDEX_CANNOUNCE
};

static struct node_map *empty_node_map(const tal_t *ctx)
{
	struct node_map *map = tal(ctx, struct node_map);
	node_map_init(map);
	tal_add_destructor(map, node_map_clear);
	return map;
}

struct routing_state *new_routing_state(const tal_t *ctx,
					const struct bitcoin_blkid *chain_hash,
					const struct pubkey *local_id)
{
	struct routing_state *rstate = tal(ctx, struct routing_state);
	rstate->nodes = empty_node_map(rstate);
	rstate->broadcasts = new_broadcast_state(rstate);
	rstate->chain_hash = *chain_hash;
	rstate->local_id = *local_id;
	list_head_init(&rstate->pending_cannouncement);
	uintmap_init(&rstate->channels);

	rstate->pending_node_map = tal(ctx, struct pending_node_map);
	pending_node_map_init(rstate->pending_node_map);

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
	n->announcement_idx = 0;
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
	u64 scid = short_channel_id_to_uint(schanid);
	struct routing_channel *chan = uintmap_get(&rstate->channels, scid);

	if (chan == NULL)
		return NULL;
	else
		return chan->connections[direction];
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

	SUPERVERBOSE("Creating new route from %s to %s",
		     type_to_string(trc, struct pubkey, &from->id),
		     type_to_string(trc, struct pubkey, &to->id));

	nc = tal(rstate, struct node_connection);
	nc->src = from;
	nc->dst = to;
	nc->channel_announcement = NULL;
	nc->channel_update = NULL;
	nc->unroutable_until = 0;

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

static void delete_connection(struct routing_state *rstate,
			      const struct node_connection *connection)
{
	tal_free(connection);
}

struct node_connection *half_add_connection(
					    struct routing_state *rstate,
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

static u64 connection_fee(const struct node_connection *c, u64 msatoshi)
{
	u64 fee;

	assert(msatoshi < MAX_MSATOSHI);
	assert(c->proportional_fee < MAX_PROPORTIONAL_FEE);

	fee = (c->proportional_fee * msatoshi) / 1000000;
	/* This can't overflow: c->base_fee is a u32 */
	return c->base_fee + fee;
}

/* Risk of passing through this channel.  We insert a tiny constant here
 * in order to prefer shorter routes, all things equal. */
static u64 risk_fee(u64 amount, u32 delay, double riskfactor)
{
	return 1 + amount * delay * riskfactor;
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
		u64 fee;
		u64 risk;

		if (node->bfg[h].total == INFINITE)
			continue;

		fee = connection_fee(c, node->bfg[h].total);
		risk = node->bfg[h].risk + risk_fee(node->bfg[h].total + fee,
						    c->delay, riskfactor);

		if (node->bfg[h].total + fee + risk >= MAX_MSATOSHI) {
			SUPERVERBOSE("...extreme %"PRIu64
				     " + fee %"PRIu64
				     " + risk %"PRIu64" ignored",
				     node->bfg[h].total, fee, risk);
			continue;
		}

		if (node->bfg[h].total + fee + risk
		    < c->src->bfg[h+1].total + c->src->bfg[h+1].risk) {
			SUPERVERBOSE("...%s can reach here in hoplen %zu total %"PRIu64,
				     type_to_string(trc, struct pubkey,
						    &c->src->id),
				     h, node->bfg[h].total + fee);
			c->src->bfg[h+1].total = node->bfg[h].total + fee;
			c->src->bfg[h+1].risk = risk;
			c->src->bfg[h+1].prev = c;
		}
	}
}

/* Determine if the given node_connection is routable */
static bool nc_is_routable(const struct node_connection *nc, time_t now)
{
	return nc->active && nc->unroutable_until < now;
}

/* riskfactor is already scaled to per-block amount */
static struct node_connection *
find_route(const tal_t *ctx, struct routing_state *rstate,
	   const struct pubkey *from, const struct pubkey *to, u64 msatoshi,
	   double riskfactor, u64 *fee, struct node_connection ***route)
{
	struct node *n, *src, *dst;
	struct node_map_iter it;
	struct node_connection *first_conn;
	int runs, i, best;
	/* Call time_now() once at the start, so that our tight loop
	 * does not keep calling into operating system for the
	 * current time */
	time_t now = time_now().ts.tv_sec;

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

	if (msatoshi >= MAX_MSATOSHI) {
		status_trace("find_route: can't route huge amount %"PRIu64,
			     msatoshi);
		return NULL;
	}

	/* Reset all the information. */
	clear_bfg(rstate->nodes);

	/* Bellman-Ford-Gibson: like Bellman-Ford, but keep values for
	 * every path length. */
	src->bfg[0].total = msatoshi;
	src->bfg[0].risk = 0;

	for (runs = 0; runs < ROUTING_MAX_HOPS; runs++) {
		SUPERVERBOSE("Run %i", runs);
		/* Run through every edge. */
		for (n = node_map_first(rstate->nodes, &it);
		     n;
		     n = node_map_next(rstate->nodes, &it)) {
			size_t num_edges = tal_count(n->in);
			for (i = 0; i < num_edges; i++) {
				SUPERVERBOSE("Node %s edge %i/%zu",
					     type_to_string(trc, struct pubkey,
							    &n->id),
					     i, num_edges);
				if (!nc_is_routable(n->in[i], now)) {
					SUPERVERBOSE("...unroutable");
					continue;
				}
				bfg_one_edge(n, i, riskfactor);
				SUPERVERBOSE("...done");
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

static struct node_connection *
add_channel_direction(struct routing_state *rstate, const struct pubkey *from,
		      const struct pubkey *to,
		      const struct short_channel_id *short_channel_id,
		      const u8 *announcement)
{
	struct node_connection *c1, *c2, *c;
	u16 direction = get_channel_direction(from, to);

	c1 = get_connection(rstate, from, to);
	c2 = get_connection_by_scid(rstate, short_channel_id, direction);
	if(c2) {
		/* We already know the channel by its scid, just
		 * update the announcement below */
		c = c2;
	} else if (c1) {
		/* We found the channel by its endpoints, not by scid,
		 * so update its scid */
		memcpy(&c1->short_channel_id, short_channel_id,
		       sizeof(c->short_channel_id));
		c1->flags = direction;
		c = c1;
	} else {
		/* We don't know this channel at all, create it */
		c = half_add_connection(rstate, from, to, short_channel_id, direction);
	}

	/* Remember the announcement so we can forward it to new peers */
	if (announcement) {
		tal_free(c->channel_announcement);
		c->channel_announcement = tal_dup_arr(c, u8, announcement,
						      tal_count(announcement), 0);
	}

	return c;
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

struct routing_channel *routing_channel_new(const tal_t *ctx,
					    struct short_channel_id *scid)
{
	struct routing_channel *chan = tal(ctx, struct routing_channel);
	chan->scid = *scid;
	chan->connections[0] = chan->connections[1] = NULL;
	chan->nodes[0] = chan->nodes[1] = NULL;
	chan->txout_script = NULL;
	chan->state = TXOUT_FETCHING;
	chan->public = false;
	memset(&chan->msg_indexes, 0, sizeof(chan->msg_indexes));
	return chan;
}

static void remove_connection_from_channel(struct node_connection *nc,
					   struct routing_state *rstate)
{
	struct routing_channel *chan = uintmap_get(
	    &rstate->channels, short_channel_id_to_uint(&nc->short_channel_id));
	struct node_connection *c = chan->connections[nc->flags & 0x1];
	if (c == NULL)
		return;
	/* If we found a channel it should be the same */
	assert(nc == c);
	chan->connections[nc->flags & 0x1] = NULL;
}

void channel_add_connection(struct routing_state *rstate,
			    struct routing_channel *chan,
			    struct node_connection *nc)
{
	int direction = get_channel_direction(&nc->src->id, &nc->dst->id);
	assert(chan != NULL);
	chan->connections[direction] = nc;
	tal_add_destructor2(nc, remove_connection_from_channel, rstate);
}

static void add_pending_node_announcement(struct routing_state *rstate, struct pubkey *nodeid)
{
	struct pending_node_announce *pna = tal(rstate, struct pending_node_announce);
	pna->nodeid = *nodeid;
	pna->node_announcement = NULL;
	pna->timestamp = 0;
	pending_node_map_add(rstate->pending_node_map, pna);
}

static void process_pending_node_announcement(struct routing_state *rstate,
					      struct pubkey *nodeid)
{
	struct pending_node_announce *pna = pending_node_map_get(rstate->pending_node_map, &nodeid->pubkey);
	if (!pna)
		return;

	if (pna->node_announcement) {
		status_trace("Processing deferred node_announcement for node %s", type_to_string(pna, struct pubkey, nodeid));
		handle_node_announcement(rstate, pna->node_announcement);
	}
	pending_node_map_del(rstate->pending_node_map, pna);
	tal_free(pna);
}

const struct short_channel_id *handle_channel_announcement(
	struct routing_state *rstate,
	const u8 *announce TAKES)
{
	struct pending_cannouncement *pending;
	struct bitcoin_blkid chain_hash;
	u8 *features;
	secp256k1_ecdsa_signature node_signature_1, node_signature_2;
	secp256k1_ecdsa_signature bitcoin_signature_1, bitcoin_signature_2;
	u64 scid;
	struct routing_channel *chan;

	pending = tal(rstate, struct pending_cannouncement);
	pending->updates[0] = NULL;
	pending->updates[1] = NULL;
	pending->announce = tal_dup_arr(pending, u8,
					announce, tal_len(announce), 0);
	pending->update_timestamps[0] = pending->update_timestamps[1] = 0;

	if (!fromwire_channel_announcement(pending, pending->announce, NULL,
					   &node_signature_1,
					   &node_signature_2,
					   &bitcoin_signature_1,
					   &bitcoin_signature_2,
					   &features,
					   &chain_hash,
					   &pending->short_channel_id,
					   &pending->node_id_1,
					   &pending->node_id_2,
					   &pending->bitcoin_key_1,
					   &pending->bitcoin_key_2)) {
		tal_free(pending);
		return NULL;
	}

	scid = short_channel_id_to_uint(&pending->short_channel_id);

	/* Check if we know the channel already (no matter in what
	 * state, we stop here if yes). */
	chan = uintmap_get(&rstate->channels, scid);
	if (chan != NULL && chan->public) {
		return tal_free(pending);
	}
        /* FIXME: Handle duplicates as per BOLT #7 */

	/* BOLT #7:
	 *
	 * If there is an unknown even bit in the `features` field the
	 * receiving node MUST NOT parse the remainder of the message
	 * and MUST NOT add the channel to its local network view, and
	 * SHOULD NOT forward the announcement.
	 */
	if (unsupported_features(features, NULL)) {
		status_trace("Ignoring channel announcement, unsupported features %s.",
			     tal_hex(pending, features));
		tal_free(pending);
		return NULL;
	}

	/* BOLT #7:
	 *
	 * The receiving node MUST ignore the message if the specified
	 * `chain_hash` is unknown to the receiver.
	 */
	if (!structeq(&chain_hash, &rstate->chain_hash)) {
		status_trace(
		    "Received channel_announcement %s for unknown chain %s",
		    type_to_string(pending, struct short_channel_id,
				   &pending->short_channel_id),
		    type_to_string(pending, struct bitcoin_blkid, &chain_hash));
		tal_free(pending);
		return NULL;
	}

	if (!check_channel_announcement(&pending->node_id_1, &pending->node_id_2,
					&pending->bitcoin_key_1,
					&pending->bitcoin_key_2,
					&node_signature_1,
					&node_signature_2,
					&bitcoin_signature_1,
					&bitcoin_signature_2,
					pending->announce)) {
		status_trace("Signature verification of channel_announcement"
			     " for %s failed",
			     type_to_string(pending, struct short_channel_id,
					    &pending->short_channel_id));
		tal_free(pending);
		return NULL;
	}

	status_trace("Received channel_announcement for channel %s",
		     type_to_string(pending, struct short_channel_id,
				    &pending->short_channel_id));

	/* So you're new in town, ey? Let's find you a room in the Inn. */
	if (chan == NULL)
		chan = routing_channel_new(rstate, &pending->short_channel_id);
	chan->pending = tal_steal(chan, pending);

	/* The channel will be public if we complete the verification */
	chan->public = true;
	uintmap_add(&rstate->channels, scid, chan);

	/* Add both endpoints to the pending_node_map so we can stash
	 * node_announcements while we wait for the txout check */
	add_pending_node_announcement(rstate, &pending->node_id_1);
	add_pending_node_announcement(rstate, &pending->node_id_2);

	return &pending->short_channel_id;
}

bool handle_pending_cannouncement(struct routing_state *rstate,
				  const struct short_channel_id *scid,
				  const u8 *outscript)
{
	bool forward, local;
	struct node_connection *c0, *c1;
	u8 *tag;
	const u8 *s;
	struct pending_cannouncement *pending;
	struct routing_channel *chan;
	u64 uscid = short_channel_id_to_uint(scid);

	chan = uintmap_get(&rstate->channels, uscid);
	assert(chan);

	pending = chan->pending;
	assert(pending);
	chan->pending = NULL;

	tag = tal_arr(pending, u8, 0);
	towire_short_channel_id(&tag, scid);

	/* BOLT #7:
	 *
	 * The receiving node MUST ignore the message if this output is spent.
	 */
	if (tal_len(outscript) == 0) {
		status_trace("channel_announcement: no unspent txout %s",
			     type_to_string(pending, struct short_channel_id,
					    scid));
		tal_free(pending);
		return false;
	}

	/* BOLT #7:
	 *
	 * The receiving node MUST ignore the message if the output
	 * specified by `short_channel_id` does not correspond to a
	 * P2WSH using `bitcoin_key_1` and `bitcoin_key_2` as
	 * specified in [BOLT
	 * #3](03-transactions.md#funding-transaction-output).
	 */
	s = scriptpubkey_p2wsh(pending,
			       bitcoin_redeem_2of2(pending,
						   &pending->bitcoin_key_1,
						   &pending->bitcoin_key_2));

	if (!scripteq(s, outscript)) {
		status_trace("channel_announcement: txout %s expectes %s, got %s",
			     type_to_string(pending, struct short_channel_id,
					    scid),
			     tal_hex(trc, s), tal_hex(trc, outscript));
		tal_free(pending);
		return false;
	}

	/* Is this a new connection? It is if we don't know the
	 * channel yet, or do not have a matching announcement in the
	 * case of side-loaded channels*/
	c0 = get_connection(rstate, &pending->node_id_2, &pending->node_id_1);
	c1 = get_connection(rstate, &pending->node_id_1, &pending->node_id_2);
	forward = !c0 || !c1 || !c0->channel_announcement || !c1->channel_announcement;

	c0 = add_channel_direction(rstate, &pending->node_id_1, &pending->node_id_2,
				   &pending->short_channel_id, pending->announce);
	c1 = add_channel_direction(rstate, &pending->node_id_2, &pending->node_id_1,
				   &pending->short_channel_id, pending->announce);

	channel_add_connection(rstate, chan, c0);
	channel_add_connection(rstate, chan, c1);

	if (forward) {
		if (replace_broadcast(rstate->broadcasts,
				      &chan->msg_indexes[MSG_INDEX_CANNOUNCE],
				      WIRE_CHANNEL_ANNOUNCEMENT,
				      (u8*)tag, pending->announce))
			status_failed(STATUS_FAIL_INTERNAL_ERROR,
				      "Announcement %s was replaced?",
				      tal_hex(trc, pending->announce));
	}

	local = pubkey_eq(&pending->node_id_1, &rstate->local_id) ||
		pubkey_eq(&pending->node_id_2, &rstate->local_id);

	/* Did we have an update waiting?  If so, apply now. */
	if (pending->updates[0])
		handle_channel_update(rstate, pending->updates[0]);
	if (pending->updates[1])
		handle_channel_update(rstate, pending->updates[1]);

	process_pending_node_announcement(rstate, &pending->node_id_1);
	process_pending_node_announcement(rstate, &pending->node_id_2);

	tal_free(pending);
	return local && forward;
}

/* Return true if this is an update to a pending announcement (and queue it) */
static bool update_to_pending(struct routing_state *rstate,
			      const struct short_channel_id *scid,
			      u32 timestamp, const u8 *update,
			      const u8 direction)
{
	u64 uscid = short_channel_id_to_uint(scid);
	struct routing_channel *chan = uintmap_get(&rstate->channels, uscid);
	struct pending_cannouncement *pending = chan?chan->pending:NULL;

	if (!pending)
		return false;

	if (pending->update_timestamps[direction] < timestamp) {
		if (pending->updates[direction]) {
			status_trace("Replacing existing update");
			tal_free(pending->updates[direction]);
		}
		pending->updates[direction] = tal_dup_arr(pending, u8, update, tal_len(update), 0);
		pending->update_timestamps[direction] = timestamp;
	}
	return true;
}

void handle_channel_update(struct routing_state *rstate, const u8 *update)
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
	struct bitcoin_blkid chain_hash;
	struct routing_channel *chan;
	u8 direction;
	size_t len = tal_len(update);

	serialized = tal_dup_arr(tmpctx, u8, update, len, 0);
	if (!fromwire_channel_update(serialized, NULL, &signature,
				     &chain_hash, &short_channel_id,
				     &timestamp, &flags, &expiry,
				     &htlc_minimum_msat, &fee_base_msat,
				     &fee_proportional_millionths)) {
		tal_free(tmpctx);
		return;
	}
	direction = flags & 0x1;

	/* BOLT #7:
	 *
	 * The receiving node MUST ignore the channel update if the specified
	 * `chain_hash` value is unknown, meaning it isn't active on the
	 * specified chain. */
	if (!structeq(&chain_hash, &rstate->chain_hash)) {
		status_trace("Received channel_update for unknown chain %s",
			     type_to_string(tmpctx, struct bitcoin_blkid,
					    &chain_hash));
		tal_free(tmpctx);
		return;
	}

	if (update_to_pending(rstate, &short_channel_id, timestamp,serialized, direction)) {
		SUPERVERBOSE("Deferring update for pending channel %s(%d)",
			     type_to_string(trc, struct short_channel_id,
					    &short_channel_id), direction);
		tal_free(tmpctx);
		return;
	}

	c = get_connection_by_scid(rstate, &short_channel_id, direction);
	chan = uintmap_get(&rstate->channels,
			   short_channel_id_to_uint(&short_channel_id));

	if (!c) {
		SUPERVERBOSE("Ignoring update for unknown channel %s",
			     type_to_string(trc, struct short_channel_id,
					    &short_channel_id));
		tal_free(tmpctx);
		return;
	} else if (c->last_timestamp >= timestamp) {
		SUPERVERBOSE("Ignoring outdated update.");
		tal_free(tmpctx);
		return;
	} else if (!check_channel_update(&c->src->id, &signature, serialized)) {
		status_trace("Signature verification failed.");
		tal_free(tmpctx);
		return;
	}

	status_trace("Received channel_update for channel %s(%d)",
		     type_to_string(trc, struct short_channel_id,
				    &short_channel_id),
		     flags & 0x01);

	c->last_timestamp = timestamp;
	c->delay = expiry;
	c->htlc_minimum_msat = htlc_minimum_msat;
	c->base_fee = fee_base_msat;
	c->proportional_fee = fee_proportional_millionths;
	c->active = (flags & ROUTING_FLAGS_DISABLED) == 0;
	c->unroutable_until = 0;
	SUPERVERBOSE("Channel %s(%d) was updated.",
		     type_to_string(trc, struct short_channel_id,
				    &short_channel_id),
		     direction);

	if (c->proportional_fee >= MAX_PROPORTIONAL_FEE) {
		status_trace("Channel %s(%d) massive proportional fee %u:"
			     " disabling.",
			     type_to_string(trc, struct short_channel_id,
					    &short_channel_id),
			     direction,
			     fee_proportional_millionths);
		c->active = false;
	}

	u8 *tag = tal_arr(tmpctx, u8, 0);
	towire_short_channel_id(&tag, &short_channel_id);
	towire_u16(&tag, direction);
	replace_broadcast(rstate->broadcasts,
			&chan->msg_indexes[MSG_INDEX_CUPDATE_0 | direction],
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
	struct routing_state *rstate, const u8 *node_ann)
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
	size_t len = tal_len(node_ann);

	serialized = tal_dup_arr(tmpctx, u8, node_ann, len, 0);
	if (!fromwire_node_announcement(tmpctx, serialized, NULL,
					&signature, &features, &timestamp,
					&node_id, rgb_color, alias,
					&addresses)) {
		tal_free(tmpctx);
		return;
	}

	/* BOLT #7:
	 *
	 * If the `features` field contains unknown even bits the
	 * receiving node MUST NOT parse the remainder of the message
	 * and MAY discard the message altogether.
	 */
	if (unsupported_features(features, NULL)) {
		status_trace("Ignoring node announcement for node %s, unsupported features %s.",
			     type_to_string(tmpctx, struct pubkey, &node_id),
			     tal_hex(tmpctx, features));
		tal_free(tmpctx);
		return;
	}

	sha256_double(&hash, serialized + 66, tal_count(serialized) - 66);
	if (!check_signed_hash(&hash, &signature, &node_id)) {
		status_trace("Ignoring node announcement, signature verification failed.");
		tal_free(tmpctx);
		return;
	}

	node = get_node(rstate, &node_id);

	/* Check if we are currently verifying the txout for a
	 * matching channel */
	struct pending_node_announce *pna = pending_node_map_get(rstate->pending_node_map, &node_id.pubkey);
	if (!node && pna) {
		if (pna->timestamp < timestamp) {
			status_trace("Deferring node_announcement for node %s", type_to_string(tmpctx, struct pubkey, &node_id));
			pna->timestamp = timestamp;
			tal_free(pna->node_announcement);
			pna->node_announcement = tal_dup_arr(pna, u8, node_ann, tal_len(node_ann), 0);
		}
		tal_free(tmpctx);
		return;
	}

	if (!node) {
		SUPERVERBOSE("Node not found, was the node_announcement for "
			     "node %s preceded by at least "
			     "channel_announcement?",
			     type_to_string(tmpctx, struct pubkey, &node_id));
		tal_free(tmpctx);
		return;
	} else if (node->last_timestamp >= timestamp) {
		SUPERVERBOSE("Ignoring node announcement, it's outdated.");
		tal_free(tmpctx);
		return;
	}

	status_trace("Received node_announcement for node %s",
		     type_to_string(tmpctx, struct pubkey, &node_id));

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
	tal_free(node->alias);
	node->alias = tal_dup_arr(node, u8, alias, 32, 0);

	u8 *tag = tal_arr(tmpctx, u8, 0);
	towire_pubkey(&tag, &node_id);
	replace_broadcast(rstate->broadcasts,
			  &node->announcement_idx,
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
	u64 fee;
	struct route_hop *hops;
	int i;
	struct node_connection *first_conn;

	first_conn = find_route(ctx, rstate, source, destination, msatoshi,
				riskfactor / BLOCKS_PER_YEAR / 10000,
				&fee, &route);

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

/* Get the struct node_connection matching the short_channel_id,
 * which must be an out connection of the given node. */
static struct node_connection *
get_out_node_connection_of(struct routing_state *rstate,
			   const struct node *node,
			   const struct short_channel_id *short_channel_id)
{
	int i;

	for (i = 0; i < tal_count(node->out); ++i) {
		if (short_channel_id_eq(&node->out[i]->short_channel_id, short_channel_id))
			return node->out[i];
	}

	return NULL;
}

/**
 * routing_failure_on_nc - Handle routing failure on a specific
 * node_connection.
 */
static void routing_failure_on_nc(struct routing_state *rstate,
				  enum onion_type failcode,
				  struct node_connection *nc,
				  time_t now)
{
	/* BOLT #4:
	 *
	 * - if the PERM bit is NOT set:
	 *   - SHOULD restore the channels as it receives new `channel_update`s.
	 */
	if (!(failcode & PERM))
		/* Prevent it for 20 seconds. */
		nc->unroutable_until = now + 20;
	else
		delete_connection(rstate, nc);
}

void routing_failure(struct routing_state *rstate,
		     const struct pubkey *erring_node_pubkey,
		     const struct short_channel_id *scid,
		     enum onion_type failcode,
		     const u8 *channel_update)
{
	const tal_t *tmpctx = tal_tmpctx(rstate);
	struct node *node;
	struct node_connection *nc;
	int i;
	enum wire_type t;
	time_t now = time_now().ts.tv_sec;

	status_trace("Received routing failure 0x%04x (%s), "
		     "erring node %s, "
		     "channel %s",
		     (int) failcode, onion_type_name(failcode),
		     type_to_string(tmpctx, struct pubkey, erring_node_pubkey),
		     type_to_string(tmpctx, struct short_channel_id, scid));

	node = get_node(rstate, erring_node_pubkey);
	if (!node) {
		status_trace("UNUSUAL routing_failure: "
			     "Erring node %s not in map",
			     type_to_string(tmpctx, struct pubkey,
					    erring_node_pubkey));
		/* No node, so no channel, so any channel_update
		 * can also be ignored. */
		goto out;
	}

	/* BOLT #4:
	 *
	 * - if the NODE bit is set:
	 *   - SHOULD remove all channels connected with the erring node from
	 *   consideration.
	 *
	 */
	if (failcode & NODE) {
		for (i = 0; i < tal_count(node->in); ++i)
			routing_failure_on_nc(rstate, failcode, node->in[i], now);
		for (i = 0; i < tal_count(node->out); ++i)
			routing_failure_on_nc(rstate, failcode, node->out[i], now);
	} else {
		nc = get_out_node_connection_of(rstate, node, scid);
		if (nc)
			routing_failure_on_nc(rstate, failcode, nc, now);
		else
			status_trace("UNUSUAL routing_failure: "
				     "Channel %s not an out channel "
				     "of node %s",
				     type_to_string(tmpctx,
						    struct short_channel_id,
						    scid),
				     type_to_string(tmpctx, struct pubkey,
						    erring_node_pubkey));
	}

	/* Update the channel if UPDATE failcode. Do
	 * this after deactivating, so that if the
	 * channel_update is newer it will be
	 * reactivated. */
	if (failcode & UPDATE) {
		if (tal_len(channel_update) == 0) {
			status_trace("UNUSUAL routing_failure: "
				     "UPDATE bit set, no channel_update. "
				     "failcode: 0x%04x",
				     (int) failcode);
			goto out;
		}
		t = fromwire_peektype(channel_update);
		if (t != WIRE_CHANNEL_UPDATE) {
			status_trace("UNUSUAL routing_failure: "
				     "not a channel_update. "
				     "type: %d",
				     (int) t);
			goto out;
		}
		handle_channel_update(rstate, channel_update);
	} else {
		if (tal_len(channel_update) != 0)
			status_trace("UNUSUAL routing_failure: "
				     "UPDATE bit clear, channel_update given. "
				     "failcode: 0x%04x",
				     (int) failcode);
	}

out:
	tal_free(tmpctx);
}
