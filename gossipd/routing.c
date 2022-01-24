#include "config.h"
#include <bitcoin/chainparams.h>
#include <bitcoin/script.h>
#include <ccan/array_size/array_size.h>
#include <ccan/tal/str/str.h>
#include <common/memleak.h>
#include <common/pseudorand.h>
#include <common/status.h>
#include <common/timeout.h>
#include <common/type_to_string.h>
#include <common/wire_error.h>
#include <gossipd/gossip_generation.h>
#include <gossipd/gossip_store_wiregen.h>
#include <gossipd/gossipd.h>
#include <gossipd/gossipd_wiregen.h>
#include <gossipd/routing.h>

#ifndef SUPERVERBOSE
#define SUPERVERBOSE(...)
#endif

/* 365.25 * 24 * 60 / 10 */
#define BLOCKS_PER_YEAR 52596

struct pending_node_announce {
	struct routing_state *rstate;
	struct node_id nodeid;
	size_t refcount;
	u8 *node_announcement;
	u32 timestamp;
	u32 index;
	/* Automagically turns to NULL if peer freed */
	struct peer *peer_softref;
};

/* We consider a reasonable gossip rate to be 1 per day, with burst of
 * 4 per day.  So we use a granularity of one hour. */
#define TOKENS_PER_MSG 24
#define TOKEN_MAX (24 * 4)

static u8 update_tokens(const struct routing_state *rstate,
			u8 tokens, u32 prev_timestamp, u32 new_timestamp)
{
	u64 num_tokens = tokens;

	assert(new_timestamp >= prev_timestamp);

	num_tokens += ((new_timestamp - prev_timestamp)
		       / GOSSIP_TOKEN_TIME(rstate->dev_fast_gossip));
	if (num_tokens > TOKEN_MAX)
		num_tokens = TOKEN_MAX;
	return num_tokens;
}

static bool ratelimit(const struct routing_state *rstate,
		      u8 *tokens, u32 prev_timestamp, u32 new_timestamp)
{
	*tokens = update_tokens(rstate, *tokens, prev_timestamp, new_timestamp);

	/* Now, if we can afford it, pass this message. */
	if (*tokens >= TOKENS_PER_MSG) {
		*tokens -= TOKENS_PER_MSG;
		return true;
	}
	return false;
}

static const struct node_id *
pending_node_announce_keyof(const struct pending_node_announce *a)
{
	return &a->nodeid;
}

static bool pending_node_announce_eq(const struct pending_node_announce *pna,
				     const struct node_id *pc)
{
	return node_id_eq(&pna->nodeid, pc);
}

HTABLE_DEFINE_TYPE(struct pending_node_announce, pending_node_announce_keyof,
		   node_map_hash_key, pending_node_announce_eq,
		   pending_node_map);

/* We keep around announcements for channels until we have an
 * update for them (which gives us their timestamp) */
struct unupdated_channel {
	/* The channel_announcement message */
	const u8 *channel_announce;
	/* The short_channel_id */
	struct short_channel_id scid;
	/* The ids of the nodes */
	struct node_id id[2];
	/* When we added, so we can discard old ones */
	struct timeabs added;
	/* If we loaded from the store, this is where. */
	u32 index;
	/* Channel capacity */
	struct amount_sat sat;
	/* Automagically turns to NULL of peer freed */
	struct peer *peer_softref;
};

static struct unupdated_channel *
get_unupdated_channel(const struct routing_state *rstate,
		      const struct short_channel_id *scid)
{
	return uintmap_get(&rstate->unupdated_chanmap, scid->u64);
}

static void destroy_unupdated_channel(struct unupdated_channel *uc,
				      struct routing_state *rstate)
{
	uintmap_del(&rstate->unupdated_chanmap, uc->scid.u64);
}

static struct node_map *new_node_map(const tal_t *ctx)
{
	struct node_map *map = tal(ctx, struct node_map);
	node_map_init(map);
	tal_add_destructor(map, node_map_clear);
	return map;
}

/* We use a simple array (with NULL entries) until we have too many. */
static bool node_uses_chan_map(const struct node *node)
{
	/* This is a layering violation: last entry in htable is the table ptr,
	 * which is never NULL */
	return node->chans.arr[NUM_IMMEDIATE_CHANS] != NULL;
}

/* When simple array fills, use a htable. */
static void convert_node_to_chan_map(struct node *node)
{
	struct chan *chans[NUM_IMMEDIATE_CHANS];

	memcpy(chans, node->chans.arr, sizeof(chans));
	chan_map_init_sized(&node->chans.map, NUM_IMMEDIATE_CHANS + 1);
	assert(node_uses_chan_map(node));
	for (size_t i = 0; i < ARRAY_SIZE(chans); i++)
		chan_map_add(&node->chans.map, chans[i]);
}

static void add_chan(struct node *node, struct chan *chan)
{
	if (!node_uses_chan_map(node)) {
		for (size_t i = 0; i < NUM_IMMEDIATE_CHANS; i++) {
			if (node->chans.arr[i] == NULL) {
				node->chans.arr[i] = chan;
				return;
			}
		}
		convert_node_to_chan_map(node);
	}

	chan_map_add(&node->chans.map, chan);
}

static struct chan *next_chan_arr(const struct node *node,
				  struct chan_map_iter *i)
{
	while (i->i.off < NUM_IMMEDIATE_CHANS) {
		if (node->chans.arr[i->i.off])
			return node->chans.arr[i->i.off];
		i->i.off++;
	}
	return NULL;
}

struct chan *first_chan(const struct node *node, struct chan_map_iter *i)
{
	if (!node_uses_chan_map(node)) {
		i->i.off = 0;
		return next_chan_arr(node, i);
	}

	return chan_map_first(&node->chans.map, i);
}

struct chan *next_chan(const struct node *node, struct chan_map_iter *i)
{
	if (!node_uses_chan_map(node)) {
		i->i.off++;
		return next_chan_arr(node, i);
	}

	return chan_map_next(&node->chans.map, i);
}

static void destroy_routing_state(struct routing_state *rstate)
{
	/* Since we omitted destructors on these, clean up manually */
	u64 idx;
	for (struct chan *chan = uintmap_first(&rstate->chanmap, &idx);
	     chan;
	     chan = uintmap_after(&rstate->chanmap, &idx))
		free_chan(rstate, chan);

	/* Free up our htables */
	pending_cannouncement_map_clear(&rstate->pending_cannouncements);
}

/* We don't check this when loading from the gossip_store: that would break
 * our canned tests, and usually old gossip is better than no gossip */
static bool timestamp_reasonable(struct routing_state *rstate, u32 timestamp)
{
	u64 now = gossip_time_now(rstate).ts.tv_sec;

	/* More than one day ahead? */
	if (timestamp > now + 24*60*60)
		return false;
	/* More than 2 weeks behind? */
	if (timestamp < now - GOSSIP_PRUNE_INTERVAL(rstate->dev_fast_gossip_prune))
		return false;
	return true;
}

#if DEVELOPER
static void memleak_help_routing_tables(struct htable *memtable,
					struct routing_state *rstate)
{
	struct node *n;
	struct node_map_iter nit;

	memleak_remove_htable(memtable, &rstate->nodes->raw);
	memleak_remove_htable(memtable, &rstate->pending_node_map->raw);
	memleak_remove_htable(memtable, &rstate->pending_cannouncements.raw);
	memleak_remove_uintmap(memtable, &rstate->unupdated_chanmap);

	for (n = node_map_first(rstate->nodes, &nit);
	     n;
	     n = node_map_next(rstate->nodes, &nit)) {
		if (node_uses_chan_map(n))
			memleak_remove_htable(memtable, &n->chans.map.raw);
	}
}
#endif /* DEVELOPER */

/* Once an hour, or at 10000 entries, we expire old ones */
static void txout_failure_age(struct routing_state *rstate)
{
	uintmap_clear(&rstate->txout_failures_old);
	rstate->txout_failures_old = rstate->txout_failures;
	uintmap_init(&rstate->txout_failures);
	rstate->num_txout_failures = 0;

	rstate->txout_failure_timer = new_reltimer(rstate->timers,
						   rstate, time_from_sec(3600),
						   txout_failure_age, rstate);
}

void add_to_txout_failures(struct routing_state *rstate,
			   const struct short_channel_id *scid)
{
	if (uintmap_add(&rstate->txout_failures, scid->u64, true)
	    && ++rstate->num_txout_failures == 10000) {
		tal_free(rstate->txout_failure_timer);
		txout_failure_age(rstate);
	}
}

static bool in_txout_failures(struct routing_state *rstate,
			      const struct short_channel_id *scid)
{
	if (uintmap_get(&rstate->txout_failures, scid->u64))
		return true;

	/* If we were going to expire it, we no longer are. */
	if (uintmap_get(&rstate->txout_failures_old, scid->u64)) {
		add_to_txout_failures(rstate, scid);
		return true;
	}
	return false;
}

struct routing_state *new_routing_state(const tal_t *ctx,
					const struct node_id *local_id,
					struct list_head *peers,
					struct timers *timers,
					const u32 *dev_gossip_time TAKES,
					bool dev_fast_gossip,
					bool dev_fast_gossip_prune)
{
	struct routing_state *rstate = tal(ctx, struct routing_state);
	rstate->nodes = new_node_map(rstate);
	rstate->timers = timers;
	rstate->local_id = *local_id;
	rstate->gs = gossip_store_new(rstate, peers);
	rstate->local_channel_announced = false;
	rstate->last_timestamp = 0;

	pending_cannouncement_map_init(&rstate->pending_cannouncements);

	uintmap_init(&rstate->chanmap);
	uintmap_init(&rstate->unupdated_chanmap);
	rstate->num_txout_failures = 0;
	uintmap_init(&rstate->txout_failures);
	uintmap_init(&rstate->txout_failures_old);
	txout_failure_age(rstate);
	rstate->pending_node_map = tal(ctx, struct pending_node_map);
	pending_node_map_init(rstate->pending_node_map);

#if DEVELOPER
	if (dev_gossip_time) {
		rstate->gossip_time = tal(rstate, struct timeabs);
		rstate->gossip_time->ts.tv_sec = *dev_gossip_time;
		rstate->gossip_time->ts.tv_nsec = 0;
	} else
		rstate->gossip_time = NULL;
	rstate->dev_fast_gossip = dev_fast_gossip;
	rstate->dev_fast_gossip_prune = dev_fast_gossip_prune;
#endif
	tal_add_destructor(rstate, destroy_routing_state);
	memleak_add_helper(rstate, memleak_help_routing_tables);

	if (taken(dev_gossip_time))
		tal_free(dev_gossip_time);

	return rstate;
}


const struct node_id *node_map_keyof_node(const struct node *n)
{
	return &n->id;
}

size_t node_map_hash_key(const struct node_id *pc)
{
	return siphash24(siphash_seed(), pc->k, sizeof(pc->k));
}

bool node_map_node_eq(const struct node *n, const struct node_id *pc)
{
	return node_id_eq(&n->id, pc);
}


static void destroy_node(struct node *node, struct routing_state *rstate)
{
	struct chan_map_iter i;
	struct chan *c;
	node_map_del(rstate->nodes, node);

	/* These remove themselves from chans[]. */
	while ((c = first_chan(node, &i)) != NULL)
		free_chan(rstate, c);

	/* Free htable if we need. */
	if (node_uses_chan_map(node))
		chan_map_clear(&node->chans.map);
}

struct node *get_node(struct routing_state *rstate,
		      const struct node_id *id)
{
	return node_map_get(rstate->nodes, id);
}

static struct node *new_node(struct routing_state *rstate,
			     const struct node_id *id)
{
	struct node *n;

	assert(!get_node(rstate, id));

	n = tal(rstate, struct node);
	n->id = *id;
	memset(n->chans.arr, 0, sizeof(n->chans.arr));
	broadcastable_init(&n->bcast);
	n->tokens = TOKEN_MAX;
	node_map_add(rstate->nodes, n);
	tal_add_destructor2(n, destroy_node, rstate);

	return n;
}

/* We've received a channel_announce for a channel attached to this node:
 * otherwise it's in the map only because it's a peer, or us. */
static bool node_has_public_channels(struct node *node)
{
	struct chan_map_iter i;
	struct chan *c;

	for (c = first_chan(node, &i); c; c = next_chan(node, &i)) {
		if (is_chan_public(c))
			return true;
	}
	return false;
}

/* We can *send* a channel_announce for a channel attached to this node:
 * we only send once we have a channel_update. */
static bool node_has_broadcastable_channels(struct node *node)
{
	struct chan_map_iter i;
	struct chan *c;

	for (c = first_chan(node, &i); c; c = next_chan(node, &i)) {
		if (!is_chan_public(c))
			continue;
		if (is_halfchan_defined(&c->half[0])
		    || is_halfchan_defined(&c->half[1]))
			return true;
	}
	return false;
}

static bool node_announce_predates_channels(const struct node *node)
{
	struct chan_map_iter i;
	struct chan *c;

	for (c = first_chan(node, &i); c; c = next_chan(node, &i)) {
		if (!is_chan_public(c))
			continue;

		if (c->bcast.index < node->bcast.index)
			return false;
	}
	return true;
}

static void remove_chan_from_node(struct routing_state *rstate,
				  struct node *node, const struct chan *chan)
{
	size_t num_chans;

	if (!node_uses_chan_map(node)) {
		num_chans = 0;
		for (size_t i = 0; i < NUM_IMMEDIATE_CHANS; i++) {
			if (node->chans.arr[i] == chan)
				node->chans.arr[i] = NULL;
			else if (node->chans.arr[i] != NULL)
				num_chans++;
		}
	} else {
		if (!chan_map_del(&node->chans.map, chan))
			abort();
		num_chans = chan_map_count(&node->chans.map);
	}

	/* Last channel?  Simply delete node (and associated announce) */
	if (num_chans == 0) {
		gossip_store_delete(rstate->gs,
				    &node->bcast,
				    WIRE_NODE_ANNOUNCEMENT);
		tal_free(node);
		return;
	}

	if (!node->bcast.index)
		return;

	/* Removed only public channel?  Remove node announcement. */
	if (!node_has_broadcastable_channels(node)) {
		gossip_store_delete(rstate->gs,
				    &node->bcast,
				    WIRE_NODE_ANNOUNCEMENT);
	} else if (node_announce_predates_channels(node)) {
		const u8 *announce;

		announce = gossip_store_get(tmpctx, rstate->gs,
					    node->bcast.index);

		/* node announcement predates all channel announcements?
		 * Move to end (we could, in theory, move to just past next
		 * channel_announce, but we don't care that much about spurious
		 * retransmissions in this corner case */
		gossip_store_delete(rstate->gs,
				    &node->bcast,
				    WIRE_NODE_ANNOUNCEMENT);
		node->bcast.index = gossip_store_add(rstate->gs,
						     announce,
						     node->bcast.timestamp,
						     false,
						     NULL);
	}
}

#if DEVELOPER
/* We make sure that free_chan is called on this chan! */
static void destroy_chan_check(struct chan *chan)
{
	assert(chan->sat.satoshis == (unsigned long)chan); /* Raw: dev-hack */
}
#endif

/* We used to make this a tal_add_destructor2, but that costs 40 bytes per
 * chan, and we only ever explicitly free it anyway. */
void free_chan(struct routing_state *rstate, struct chan *chan)
{
	remove_chan_from_node(rstate, chan->nodes[0], chan);
	remove_chan_from_node(rstate, chan->nodes[1], chan);

	uintmap_del(&rstate->chanmap, chan->scid.u64);

#if DEVELOPER
	chan->sat.satoshis = (unsigned long)chan; /* Raw: dev-hack */
#endif
	tal_free(chan);
}

static void init_half_chan(struct routing_state *rstate,
				 struct chan *chan,
				 int channel_idx)
{
	struct half_chan *c = &chan->half[channel_idx];

	broadcastable_init(&c->bcast);
	c->tokens = TOKEN_MAX;
}

static void bad_gossip_order(const u8 *msg,
			     const struct peer *peer,
			     const char *details)
{
	status_peer_debug(peer ? &peer->id : NULL,
			  "Bad gossip order: %s before announcement %s",
			  peer_wire_name(fromwire_peektype(msg)),
			  details);
}

struct chan *new_chan(struct routing_state *rstate,
		      const struct short_channel_id *scid,
		      const struct node_id *id1,
		      const struct node_id *id2,
		      struct amount_sat satoshis)
{
	struct chan *chan = tal(rstate, struct chan);
	int n1idx = node_id_idx(id1, id2);
	struct node *n1, *n2;

#if DEVELOPER
	tal_add_destructor(chan, destroy_chan_check);
#endif
	/* We should never add a channel twice */
	assert(!uintmap_get(&rstate->chanmap, scid->u64));

	/* Create nodes on demand */
	n1 = get_node(rstate, id1);
	if (!n1)
		n1 = new_node(rstate, id1);
	n2 = get_node(rstate, id2);
	if (!n2)
		n2 = new_node(rstate, id2);

	chan->scid = *scid;
	chan->nodes[n1idx] = n1;
	chan->nodes[!n1idx] = n2;
	broadcastable_init(&chan->bcast);
	/* This is how we indicate it's not public yet. */
	chan->bcast.timestamp = 0;
	chan->sat = satoshis;

	add_chan(n2, chan);
	add_chan(n1, chan);

	/* Populate with (inactive) connections */
	init_half_chan(rstate, chan, n1idx);
	init_half_chan(rstate, chan, !n1idx);

	uintmap_add(&rstate->chanmap, scid->u64, chan);

	return chan;
}

/* Checks that key is valid, and signed this hash */
static bool check_signed_hash_nodeid(const struct sha256_double *hash,
				     const secp256k1_ecdsa_signature *signature,
				     const struct node_id *id)
{
	struct pubkey key;

	return pubkey_from_node_id(&key, id)
		&& check_signed_hash(hash, signature, &key);
}

/* Verify the signature of a channel_update message */
static u8 *check_channel_update(const tal_t *ctx,
				const struct node_id *node_id,
				const secp256k1_ecdsa_signature *node_sig,
				const u8 *update)
{
	/* 2 byte msg type + 64 byte signatures */
	int offset = 66;
	struct sha256_double hash;
	sha256_double(&hash, update + offset, tal_count(update) - offset);

	if (!check_signed_hash_nodeid(&hash, node_sig, node_id))
		return towire_warningfmt(ctx, NULL,
					 "Bad signature for %s hash %s"
					 " on channel_update %s",
					 type_to_string(tmpctx,
							secp256k1_ecdsa_signature,
							node_sig),
					 type_to_string(tmpctx,
							struct sha256_double,
							&hash),
					 tal_hex(tmpctx, update));
	return NULL;
}

static u8 *check_channel_announcement(const tal_t *ctx,
	const struct node_id *node1_id, const struct node_id *node2_id,
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
		      tal_count(announcement) - offset);

	if (!check_signed_hash_nodeid(&hash, node1_sig, node1_id)) {
		return towire_warningfmt(ctx, NULL,
					 "Bad node_signature_1 %s hash %s"
					 " on channel_announcement %s",
					 type_to_string(tmpctx,
							secp256k1_ecdsa_signature,
							node1_sig),
					 type_to_string(tmpctx,
							struct sha256_double,
							&hash),
					 tal_hex(tmpctx, announcement));
	}
	if (!check_signed_hash_nodeid(&hash, node2_sig, node2_id)) {
		return towire_warningfmt(ctx, NULL,
					 "Bad node_signature_2 %s hash %s"
					 " on channel_announcement %s",
					 type_to_string(tmpctx,
							secp256k1_ecdsa_signature,
							node2_sig),
					 type_to_string(tmpctx,
							struct sha256_double,
							&hash),
					 tal_hex(tmpctx, announcement));
	}
	if (!check_signed_hash(&hash, bitcoin1_sig, bitcoin1_key)) {
		return towire_warningfmt(ctx, NULL,
					 "Bad bitcoin_signature_1 %s hash %s"
					 " on channel_announcement %s",
					 type_to_string(tmpctx,
							secp256k1_ecdsa_signature,
							bitcoin1_sig),
					 type_to_string(tmpctx,
							struct sha256_double,
							&hash),
					 tal_hex(tmpctx, announcement));
	}
	if (!check_signed_hash(&hash, bitcoin2_sig, bitcoin2_key)) {
		return towire_warningfmt(ctx, NULL,
					 "Bad bitcoin_signature_2 %s hash %s"
					 " on channel_announcement %s",
					 type_to_string(tmpctx,
							secp256k1_ecdsa_signature,
							bitcoin2_sig),
					 type_to_string(tmpctx,
							struct sha256_double,
							&hash),
					 tal_hex(tmpctx, announcement));
	}
	return NULL;
}

/* We allow node announcements for this node if it doesn't otherwise exist, so
 * we can process them once it does exist (a channel_announce is being
 * validated right now).
 *
 * If we attach one, remove it on destruction of @ctx.
 */
static void del_pending_node_announcement(const tal_t *ctx UNUSED,
					  struct pending_node_announce *pna)
{
	if (--pna->refcount == 0) {
		pending_node_map_del(pna->rstate->pending_node_map, pna);
		tal_free(pna);
	}
}

static void catch_node_announcement(const tal_t *ctx,
				    struct routing_state *rstate,
				    struct node_id *nodeid)
{
	struct pending_node_announce *pna;
	struct node *node;

	/* No need if we already know about the node.  We might, however, only
	 * know about it because it's a peer (maybe with private or
	 * not-yet-announced channels), so check for that too. */
	node = get_node(rstate, nodeid);
	if (node && node_has_public_channels(node))
		return;

	/* We can have multiple channels announced at same time for nodes;
	 * but we can only have one of these in the map. */
	pna = pending_node_map_get(rstate->pending_node_map, nodeid);
	if (!pna) {
		pna = tal(rstate, struct pending_node_announce);
		pna->rstate = rstate;
		pna->nodeid = *nodeid;
		pna->node_announcement = NULL;
		pna->timestamp = 0;
		pna->index = 0;
		pna->refcount = 0;
		pna->peer_softref = NULL;
		pending_node_map_add(rstate->pending_node_map, pna);
	}
	pna->refcount++;
	tal_add_destructor2(ctx, del_pending_node_announcement, pna);
}

static void process_pending_node_announcement(struct routing_state *rstate,
					      struct node_id *nodeid)
{
	struct pending_node_announce *pna = pending_node_map_get(rstate->pending_node_map, nodeid);
	if (!pna)
		return;

	if (pna->node_announcement) {
		SUPERVERBOSE(
		    "Processing deferred node_announcement for node %s",
		    type_to_string(pna, struct node_id, nodeid));

		/* Can fail it timestamp is now too old */
		if (!routing_add_node_announcement(rstate,
						   pna->node_announcement,
						   pna->index,
						   pna->peer_softref, NULL))
			status_unusual("pending node_announcement %s too old?",
				       tal_hex(tmpctx, pna->node_announcement));
		/* Never send this again. */
		pna->node_announcement = tal_free(pna->node_announcement);
	}

	/* We don't need to catch any more node_announcements, since we've
	 * accepted the public channel now.  But other pending announcements
	 * may still hold a reference they use in
	 * del_pending_node_announcement, so simply delete it from the map. */
	pending_node_map_del(rstate->pending_node_map, notleak(pna));
}

static struct pending_cannouncement *
find_pending_cannouncement(struct routing_state *rstate,
			   const struct short_channel_id *scid)
{
	struct pending_cannouncement *pann;

	pann = pending_cannouncement_map_get(&rstate->pending_cannouncements, scid);

	return pann;
}

static void destroy_pending_cannouncement(struct pending_cannouncement *pending,
					  struct routing_state *rstate)
{
	pending_cannouncement_map_del(&rstate->pending_cannouncements, pending);
}

static void add_channel_announce_to_broadcast(struct routing_state *rstate,
					      struct chan *chan,
					      const u8 *channel_announce,
					      u32 timestamp,
					      u32 index)
{
	u8 *addendum = towire_gossip_store_channel_amount(tmpctx, chan->sat);
	bool is_local = local_direction(rstate, chan, NULL);

	chan->bcast.timestamp = timestamp;
	/* 0, unless we're loading from store */
	if (index)
		chan->bcast.index = index;
	else
		chan->bcast.index = gossip_store_add(rstate->gs,
						     channel_announce,
						     chan->bcast.timestamp,
						     is_local,
						     addendum);
	rstate->local_channel_announced |= is_local;
}

bool routing_add_channel_announcement(struct routing_state *rstate,
				      const u8 *msg TAKES,
				      struct amount_sat sat,
				      u32 index,
				      struct peer *peer)
{
	struct chan *chan;
	secp256k1_ecdsa_signature node_signature_1, node_signature_2;
	secp256k1_ecdsa_signature bitcoin_signature_1, bitcoin_signature_2;
	u8 *features;
	struct bitcoin_blkid chain_hash;
	struct short_channel_id scid;
	struct node_id node_id_1;
	struct node_id node_id_2;
	struct pubkey bitcoin_key_1;
	struct pubkey bitcoin_key_2;
	struct unupdated_channel *uc;
	const u8 *private_updates[2] = { NULL, NULL };

	/* Make sure we own msg, even if we don't save it. */
	if (taken(msg))
		tal_steal(tmpctx, msg);

	if (!fromwire_channel_announcement(
		    tmpctx, msg, &node_signature_1, &node_signature_2,
		    &bitcoin_signature_1, &bitcoin_signature_2, &features, &chain_hash,
		    &scid, &node_id_1, &node_id_2, &bitcoin_key_1, &bitcoin_key_2))
		return false;

	/* The channel may already exist if it was non-public from
	 * local_add_channel(); normally we don't accept new
	 * channel_announcements.  See handle_channel_announcement. */
	chan = get_channel(rstate, &scid);

	/* private updates will exist in the store before the announce: we
	 * can't index those for broadcast since they would predate it, so we
	 * add fresh ones. */
	if (chan) {
		/* If this was in the gossip_store, gossip_store is bad! */
		if (index) {
			status_broken("gossip_store channel_announce"
				      " %u replaces %u!",
				      index, chan->bcast.index);
			return false;
		}

		/* Reload any private updates */
		if (chan->half[0].bcast.index)
			private_updates[0]
				= gossip_store_get_private_update(NULL,
						   rstate->gs,
						   chan->half[0].bcast.index);
		if (chan->half[1].bcast.index)
			private_updates[1]
				= gossip_store_get_private_update(NULL,
						   rstate->gs,
						   chan->half[1].bcast.index);

		remove_channel_from_store(rstate, chan);
		free_chan(rstate, chan);
	}

	uc = tal(rstate, struct unupdated_channel);
	uc->channel_announce = tal_dup_talarr(uc, u8, msg);
	uc->added = gossip_time_now(rstate);
	uc->index = index;
	uc->sat = sat;
	uc->scid = scid;
	uc->id[0] = node_id_1;
	uc->id[1] = node_id_2;
	set_softref(uc, &uc->peer_softref, peer);
	uintmap_add(&rstate->unupdated_chanmap, scid.u64, uc);
	tal_add_destructor2(uc, destroy_unupdated_channel, rstate);

	/* If a node_announcement comes along, save it for once we're updated */
	catch_node_announcement(uc, rstate, &node_id_1);
	catch_node_announcement(uc, rstate, &node_id_2);

	/* If we had private updates, they'll immediately create the channel. */
	if (private_updates[0])
		routing_add_channel_update(rstate, take(private_updates[0]), 0,
					   peer, false);
	if (private_updates[1])
		routing_add_channel_update(rstate, take(private_updates[1]), 0,
					   peer, false);

	return true;
}

u8 *handle_channel_announcement(struct routing_state *rstate,
				const u8 *announce TAKES,
				u32 current_blockheight,
				const struct short_channel_id **scid,
				struct peer *peer)
{
	struct pending_cannouncement *pending;
	struct bitcoin_blkid chain_hash;
	u8 *features, *err;
	secp256k1_ecdsa_signature node_signature_1, node_signature_2;
	secp256k1_ecdsa_signature bitcoin_signature_1, bitcoin_signature_2;
	struct chan *chan;

	pending = tal(rstate, struct pending_cannouncement);
	set_softref(pending, &pending->peer_softref, peer);
	pending->updates[0] = NULL;
	pending->updates[1] = NULL;
	pending->update_peer_softref[0] = pending->update_peer_softref[1] = NULL;
	pending->announce = tal_dup_talarr(pending, u8, announce);
	pending->update_timestamps[0] = pending->update_timestamps[1] = 0;

	if (!fromwire_channel_announcement(pending, pending->announce,
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
		err = towire_warningfmt(rstate, NULL,
					"Malformed channel_announcement %s",
					tal_hex(pending, pending->announce));
		goto malformed;
	}

	/* We don't use features */
	tal_free(features);

	/* If we know the blockheight, and it's in the future, reject
	 * out-of-hand.  Remember, it should be 6 deep before they tell us
	 * anyway. */
	if (current_blockheight != 0
	    && short_channel_id_blocknum(&pending->short_channel_id) > current_blockheight) {
		status_peer_debug(peer ? &peer->id : NULL,
				  "Ignoring future channel_announcment for %s"
				  " (current block %u)",
				  type_to_string(tmpctx, struct short_channel_id,
						 &pending->short_channel_id),
				  current_blockheight);
		goto ignored;
	}

	/* If a prior txout lookup failed there is little point it trying
	 * again. Just drop the announcement and walk away whistling. */
	if (in_txout_failures(rstate, &pending->short_channel_id)) {
		SUPERVERBOSE(
		    "Ignoring channel_announcement of %s due to a prior txout "
		    "query failure. The channel was likely closed on-chain.",
		    type_to_string(tmpctx, struct short_channel_id,
				   &pending->short_channel_id));
		goto ignored;
	}

	/* Check if we know the channel already (no matter in what
	 * state, we stop here if yes). */
	chan = get_channel(rstate, &pending->short_channel_id);
	if (chan != NULL && is_chan_public(chan)) {
		SUPERVERBOSE("%s: %s already has public channel",
			     __func__,
			     type_to_string(tmpctx, struct short_channel_id,
					    &pending->short_channel_id));
		goto ignored;
	}
	if (get_unupdated_channel(rstate, &pending->short_channel_id)) {
		SUPERVERBOSE("%s: %s already has unupdated channel",
			     __func__,
			     type_to_string(tmpctx, struct short_channel_id,
					    &pending->short_channel_id));
		goto ignored;
	}

	/* We don't replace previous ones, since we might validate that and
	 * think this one is OK! */
	if (find_pending_cannouncement(rstate, &pending->short_channel_id)) {
		SUPERVERBOSE("%s: %s already has pending cannouncement",
			     __func__,
			     type_to_string(tmpctx, struct short_channel_id,
					    &pending->short_channel_id));
		goto ignored;
	}

	/* FIXME: Handle duplicates as per BOLT #7 */

	/* BOLT #7:
	 * The receiving node:
	 *...
	 *  - if the specified `chain_hash` is unknown to the receiver:
	 *    - MUST ignore the message.
	 */
	if (!bitcoin_blkid_eq(&chain_hash, &chainparams->genesis_blockhash)) {
		status_peer_debug(peer ? &peer->id : NULL,
		    "Received channel_announcement %s for unknown chain %s",
		    type_to_string(pending, struct short_channel_id,
				   &pending->short_channel_id),
		    type_to_string(pending, struct bitcoin_blkid, &chain_hash));
		goto ignored;
	}

	/* Note that if node_id_1 or node_id_2 are malformed, it's caught here */
	err = check_channel_announcement(rstate,
					 &pending->node_id_1,
					 &pending->node_id_2,
					 &pending->bitcoin_key_1,
					 &pending->bitcoin_key_2,
					 &node_signature_1,
					 &node_signature_2,
					 &bitcoin_signature_1,
					 &bitcoin_signature_2,
					 pending->announce);
	if (err) {
		/* BOLT #7:
		 *
		 * - if `bitcoin_signature_1`, `bitcoin_signature_2`,
		 *   `node_signature_1` OR `node_signature_2` are invalid OR NOT
		 *    correct:
		 *    - SHOULD fail the connection.
		 */
		goto malformed;
	}

	/* Don't add an infinite number of pending announcements.  If we're
	 * catching up with the bitcoin chain, though, they can definitely
	 * pile up. */
	if (pending_cannouncement_map_count(&rstate->pending_cannouncements)
	    > 100000) {
		static bool warned = false;
		if (!warned) {
			status_peer_unusual(peer ? &peer->id : NULL,
					    "Flooded by channel_announcements:"
					    " ignoring some");
			warned = true;
		}
		goto ignored;
	}

	status_peer_debug(peer ? &peer->id : NULL,
			  "Received channel_announcement for channel %s",
			  type_to_string(tmpctx, struct short_channel_id,
					 &pending->short_channel_id));

	/* Add both endpoints to the pending_node_map so we can stash
	 * node_announcements while we wait for the txout check */
	catch_node_announcement(pending, rstate, &pending->node_id_1);
	catch_node_announcement(pending, rstate, &pending->node_id_2);

	pending_cannouncement_map_add(&rstate->pending_cannouncements, pending);
	tal_add_destructor2(pending, destroy_pending_cannouncement, rstate);

	/* Success */
	// MSC: Cppcheck 1.86 gets this false positive
	// cppcheck-suppress autoVariables
	*scid = &pending->short_channel_id;
	return NULL;

malformed:
	tal_free(pending);
	*scid = NULL;
	return err;

ignored:
	tal_free(pending);
	*scid = NULL;
	return NULL;
}

static void process_pending_channel_update(struct daemon *daemon,
					   struct routing_state *rstate,
					   const struct short_channel_id *scid,
					   const u8 *cupdate,
					   struct peer *peer)
{
	u8 *err;

	if (!cupdate)
		return;

	err = handle_channel_update(rstate, cupdate, peer, NULL, false);
	if (err) {
		/* FIXME: We could send this error back to peer if != NULL */
		status_peer_debug(peer ? &peer->id : NULL,
				  "Pending channel_update for %s: %s",
				  type_to_string(tmpctx, struct short_channel_id,
						 scid),
				  sanitize_error(tmpctx, err, NULL));
		tal_free(err);
	}
}

bool handle_pending_cannouncement(struct daemon *daemon,
				  struct routing_state *rstate,
				  const struct short_channel_id *scid,
				  struct amount_sat sat,
				  const u8 *outscript)
{
	const u8 *s;
	struct pending_cannouncement *pending;
	const struct node_id *src;

	pending = find_pending_cannouncement(rstate, scid);
	if (!pending)
		return false;

	src = pending->peer_softref ? &pending->peer_softref->id : NULL;

	/* BOLT #7:
	 *
	 * The receiving node:
	 *...
	 *   - if the `short_channel_id`'s output... is spent:
	 *    - MUST ignore the message.
	 */
	if (tal_count(outscript) == 0) {
		status_peer_debug(src,
				  "channel_announcement: no unspent txout %s",
				  type_to_string(pending,
						 struct short_channel_id,
						 scid));
		tal_free(pending);
		add_to_txout_failures(rstate, scid);
		return false;
	}

	/* BOLT #7:
	 *
	 * The receiving node:
	 *...
	 *   - if the `short_channel_id`'s output does NOT correspond to a P2WSH
	 *     (using `bitcoin_key_1` and `bitcoin_key_2`, as specified in
	 *    [BOLT #3](03-transactions.md#funding-transaction-output)) ...
	 *    - MUST ignore the message.
	 */
	s = scriptpubkey_p2wsh(pending,
			       bitcoin_redeem_2of2(pending,
						   &pending->bitcoin_key_1,
						   &pending->bitcoin_key_2));

	if (!scripteq(s, outscript)) {
		status_peer_debug(src,
				  "channel_announcement: txout %s expected %s, got %s",
				  type_to_string(
					  pending, struct short_channel_id,
					  scid),
				  tal_hex(tmpctx, s),
				  tal_hex(tmpctx, outscript));
		tal_free(pending);
		return false;
	}

	/* Remove pending now, so below functions don't see it. */
	pending_cannouncement_map_del(&rstate->pending_cannouncements, pending);
	tal_del_destructor2(pending, destroy_pending_cannouncement, rstate);

	/* Can fail if channel_announcement too old */
	if (!routing_add_channel_announcement(rstate, pending->announce, sat, 0,
					      pending->peer_softref))
		status_peer_unusual(src,
				    "Could not add channel_announcement %s: too old?",
				    tal_hex(tmpctx, pending->announce));
	else {
		/* Did we have an update waiting?  If so, apply now. */
		process_pending_channel_update(daemon, rstate, scid, pending->updates[0],
					       pending->update_peer_softref[0]);
		process_pending_channel_update(daemon, rstate, scid, pending->updates[1],
					       pending->update_peer_softref[1]);
	}

	tal_free(pending);
	return true;
}

static void update_pending(struct pending_cannouncement *pending,
			   u32 timestamp, const u8 *update,
			   const u8 direction,
			   struct peer *peer)
{
	SUPERVERBOSE("Deferring update for pending channel %s/%d",
		     type_to_string(tmpctx, struct short_channel_id,
				    &pending->short_channel_id), direction);

	if (pending->update_timestamps[direction] < timestamp) {
		if (pending->updates[direction]) {
			status_peer_debug(peer ? &peer->id : NULL,
					  "Replacing existing update");
			tal_free(pending->updates[direction]);
		}
		pending->updates[direction]
			= tal_dup_talarr(pending, u8, update);
		pending->update_timestamps[direction] = timestamp;
		clear_softref(pending, &pending->update_peer_softref[direction]);
		set_softref(pending, &pending->update_peer_softref[direction],
			    peer);
	}
}

bool routing_add_channel_update(struct routing_state *rstate,
				const u8 *update TAKES,
				u32 index,
				struct peer *peer,
				bool ignore_timestamp)
{
	secp256k1_ecdsa_signature signature;
	struct short_channel_id short_channel_id;
	u32 timestamp;
	u8 message_flags, channel_flags;
	u16 expiry;
	struct amount_msat htlc_minimum, htlc_maximum;
	u32 fee_base_msat;
	u32 fee_proportional_millionths;
	struct bitcoin_blkid chain_hash;
	struct chan *chan;
	struct half_chan *hc;
	struct unupdated_channel *uc;
	u8 direction;
	struct amount_sat sat;

	/* Make sure we own msg, even if we don't save it. */
	if (taken(update))
		tal_steal(tmpctx, update);

	if (!fromwire_channel_update(update, &signature, &chain_hash,
				     &short_channel_id, &timestamp,
				     &message_flags, &channel_flags,
				     &expiry, &htlc_minimum, &fee_base_msat,
				     &fee_proportional_millionths))
		return false;
	/* If it's flagged as containing the optional field, reparse for
	 * the optional field */
	if ((message_flags & ROUTING_OPT_HTLC_MAX_MSAT) &&
			!fromwire_channel_update_option_channel_htlc_max(
				update, &signature, &chain_hash,
				&short_channel_id, &timestamp,
				&message_flags, &channel_flags,
				&expiry, &htlc_minimum, &fee_base_msat,
				&fee_proportional_millionths,
				&htlc_maximum))
		return false;

	direction = channel_flags & 0x1;
	chan = get_channel(rstate, &short_channel_id);

	if (chan) {
		uc = NULL;
		sat = chan->sat;
	} else {
		/* Maybe announcement was waiting for this update? */
		uc = get_unupdated_channel(rstate, &short_channel_id);
		if (!uc) {
			return false;
		}
		sat = uc->sat;
	}

	if (message_flags & ROUTING_OPT_HTLC_MAX_MSAT) {
		/* Reject update if the `htlc_maximum_msat` is greater
		 * than the total available channel satoshis */
		if (amount_msat_greater_sat(htlc_maximum, sat))
			return false;
	} else {
		/* If not indicated, set htlc_max_msat to channel capacity */
		if (!amount_sat_to_msat(&htlc_maximum, sat)) {
			status_peer_broken(peer ? &peer->id : NULL,
					   "Channel capacity %s overflows!",
					   type_to_string(tmpctx, struct amount_sat,
							  &sat));
			return false;
		}
	}

	/* Check timestamp is sane (unless from store). */
	if (!index && !timestamp_reasonable(rstate, timestamp)) {
		SUPERVERBOSE("Ignoring update timestamp %u for %s/%u",
			     timestamp,
			     type_to_string(tmpctx, struct short_channel_id,
					    &short_channel_id),
			     direction);
		return false;
	}

	/* OK, we're going to accept this, so create chan if doesn't exist */
	if (uc) {
		assert(!chan);
		chan = new_chan(rstate, &short_channel_id,
				&uc->id[0], &uc->id[1], sat);
	}

	/* Discard older updates */
	hc = &chan->half[direction];

	if (is_halfchan_defined(hc) && !ignore_timestamp) {
		/* If we're loading from store, duplicate entries are a bug. */
		if (index != 0) {
			status_broken("gossip_store channel_update %u replaces %u!",
				      index, hc->bcast.index);
			return false;
		}

		if (timestamp <= hc->bcast.timestamp) {
			SUPERVERBOSE("Ignoring outdated update.");
			/* Ignoring != failing */
			return true;
		}

		/* Allow redundant updates once every 7 days */
		if (timestamp < hc->bcast.timestamp + GOSSIP_PRUNE_INTERVAL(rstate->dev_fast_gossip_prune) / 2
		    && !cupdate_different(rstate->gs, hc, update)) {
			SUPERVERBOSE("Ignoring redundant update for %s/%u"
				     " (last %u, now %u)",
				     type_to_string(tmpctx,
						    struct short_channel_id,
						    &short_channel_id),
				     direction, hc->bcast.timestamp, timestamp);
			/* Ignoring != failing */
			return true;
		}

		/* Make sure it's not spamming us. */
		if (!ratelimit(rstate,
			       &hc->tokens, hc->bcast.timestamp, timestamp)) {
			status_peer_debug(peer ? &peer->id : NULL,
					  "Ignoring spammy update for %s/%u"
					  " (last %u, now %u)",
					  type_to_string(tmpctx,
							 struct short_channel_id,
							 &short_channel_id),
					  direction,
					  hc->bcast.timestamp, timestamp);
			/* Ignoring != failing */
			return true;
		}
	}

	chan->half[direction].bcast.timestamp = timestamp;

	/* Safe even if was never added, but if it's a private channel it
	 * would be a WIRE_GOSSIP_STORE_PRIVATE_UPDATE. */
	gossip_store_delete(rstate->gs, &hc->bcast,
			    is_chan_public(chan)
			    ? WIRE_CHANNEL_UPDATE
			    : WIRE_GOSSIP_STORE_PRIVATE_UPDATE);

	/* BOLT #7:
	 *   - MUST consider the `timestamp` of the `channel_announcement` to be
	 *     the `timestamp` of a corresponding `channel_update`.
	 *   - MUST consider whether to send the `channel_announcement` after
	 *     receiving the first corresponding `channel_update`.
	 */
	if (uc) {
		add_channel_announce_to_broadcast(rstate, chan,
						  uc->channel_announce,
						  timestamp,
						  uc->index);
	} else if (!is_chan_public(chan)) {
		/* For private channels, we get updates without an announce: don't
		 * broadcast them!  But save local ones to store anyway. */
		assert(local_direction(rstate, chan, NULL));
		/* Don't save if we're loading from store */
		if (!index) {
			hc->bcast.index
				= gossip_store_add_private_update(rstate->gs,
								  update);
		} else
			hc->bcast.index = index;
		return true;
	}

	/* If we're loading from store, this means we don't re-add to store. */
	if (index)
		hc->bcast.index = index;
	else {
		hc->bcast.index
			= gossip_store_add(rstate->gs, update,
					   hc->bcast.timestamp,
					   local_direction(rstate, chan, NULL),
					   NULL);
		if (hc->bcast.timestamp > rstate->last_timestamp
		    && hc->bcast.timestamp < time_now().ts.tv_sec)
			rstate->last_timestamp = hc->bcast.timestamp;

		peer_supplied_good_gossip(peer, 1);
	}

	if (uc) {
		/* If we were waiting for these nodes to appear (or gain a
		   public channel), process node_announcements now */
		process_pending_node_announcement(rstate, &chan->nodes[0]->id);
		process_pending_node_announcement(rstate, &chan->nodes[1]->id);
		tal_free(uc);
	}

	status_peer_debug(peer ? &peer->id : NULL,
			  "Received %schannel_update for channel %s/%d now %s",
			  ignore_timestamp ? "(forced) " : "",
			  type_to_string(tmpctx, struct short_channel_id,
					 &short_channel_id),
			  channel_flags & 0x01,
			  channel_flags & ROUTING_FLAGS_DISABLED ? "DISABLED" : "ACTIVE");

	return true;
}

bool would_ratelimit_cupdate(struct routing_state *rstate,
			     const struct half_chan *hc,
			     u32 timestamp)
{
	return update_tokens(rstate, hc->tokens, hc->bcast.timestamp, timestamp)
		>= TOKENS_PER_MSG;
}

static const struct node_id *get_channel_owner(struct routing_state *rstate,
					       const struct short_channel_id *scid,
					       int direction)
{
	struct chan *chan = get_channel(rstate, scid);
	struct unupdated_channel *uc;

	if (chan)
		return &chan->nodes[direction]->id;

	/* Might be unupdated channel */
	uc = get_unupdated_channel(rstate, scid);
	if (uc)
		return &uc->id[direction];
	return NULL;
}

void remove_channel_from_store(struct routing_state *rstate,
			       struct chan *chan)
{
	int update_type, announcment_type;

	if (is_chan_public(chan)) {
		update_type = WIRE_CHANNEL_UPDATE;
		announcment_type = WIRE_CHANNEL_ANNOUNCEMENT;
	} else {
		update_type = WIRE_GOSSIP_STORE_PRIVATE_UPDATE;
		announcment_type = WIRE_GOSSIP_STORE_PRIVATE_CHANNEL;
	}
	gossip_store_mark_channel_deleted(rstate->gs, &chan->scid);

	/* If these aren't in the store, these are noops. */
	gossip_store_delete(rstate->gs,
			    &chan->bcast, announcment_type);
	gossip_store_delete(rstate->gs,
			    &chan->half[0].bcast, update_type);
	gossip_store_delete(rstate->gs,
			    &chan->half[1].bcast, update_type);
}

u8 *handle_channel_update(struct routing_state *rstate, const u8 *update TAKES,
			  struct peer *peer,
			  struct short_channel_id *unknown_scid,
			  bool force)
{
	u8 *serialized;
	const struct node_id *owner;
	secp256k1_ecdsa_signature signature;
	struct short_channel_id short_channel_id;
	u32 timestamp;
	u8 message_flags, channel_flags;
	u16 expiry;
	struct amount_msat htlc_minimum;
	u32 fee_base_msat;
	u32 fee_proportional_millionths;
	struct bitcoin_blkid chain_hash;
	u8 direction;
	struct pending_cannouncement *pending;
	u8 *err;

	serialized = tal_dup_talarr(tmpctx, u8, update);
	if (!fromwire_channel_update(serialized, &signature,
				     &chain_hash, &short_channel_id,
				     &timestamp, &message_flags,
				     &channel_flags, &expiry,
				     &htlc_minimum, &fee_base_msat,
				     &fee_proportional_millionths)) {
		err = towire_warningfmt(rstate, NULL,
					"Malformed channel_update %s",
					tal_hex(tmpctx, serialized));
		return err;
	}
	direction = channel_flags & 0x1;

	/* BOLT #7:
	 *
	 * The receiving node:
	 *...
	 *  - if the specified `chain_hash` value is unknown (meaning it isn't
	 *    active on the specified chain):
	 *    - MUST ignore the channel update.
	 */
	if (!bitcoin_blkid_eq(&chain_hash, &chainparams->genesis_blockhash)) {
		status_peer_debug(peer ? &peer->id : NULL,
				  "Received channel_update for unknown chain %s",
				  type_to_string(tmpctx, struct bitcoin_blkid,
						 &chain_hash));
		return NULL;
	}

	/* If we dropped the matching announcement for this channel due to the
	 * txout query failing, don't report failure, it's just too noisy on
	 * mainnet */
	if (in_txout_failures(rstate, &short_channel_id))
		return NULL;

	/* If we have an unvalidated channel, just queue on that */
	pending = find_pending_cannouncement(rstate, &short_channel_id);
	if (pending) {
		status_peer_debug(peer ? &peer->id : NULL,
				  "Updated pending announce with update %s/%u",
				  type_to_string(tmpctx,
						 struct short_channel_id,
						 &short_channel_id),
				  direction);
		update_pending(pending, timestamp, serialized, direction, peer);
		return NULL;
	}

	owner = get_channel_owner(rstate, &short_channel_id, direction);
	if (!owner) {
		if (unknown_scid)
			*unknown_scid = short_channel_id;
		bad_gossip_order(serialized,
				 peer,
				 tal_fmt(tmpctx, "%s/%u",
					 type_to_string(tmpctx,
							struct short_channel_id,
							&short_channel_id),
					 direction));
		return NULL;
	}

	err = check_channel_update(rstate, owner, &signature, serialized);
	if (err) {
		/* BOLT #7:
		 *
		 * - if `signature` is not a valid signature, using `node_id`
		 *  of the double-SHA256 of the entire message following the
		 *  `signature` field (including unknown fields following
		 *  `fee_proportional_millionths`):
		 *    - MUST NOT process the message further.
		 *    - SHOULD fail the connection.
		 */
		return err;
	}

	routing_add_channel_update(rstate, take(serialized), 0, peer, force);
	return NULL;
}

bool routing_add_node_announcement(struct routing_state *rstate,
				   const u8 *msg TAKES,
				   u32 index,
				   struct peer *peer,
				   bool *was_unknown)
{
	struct node *node;
	secp256k1_ecdsa_signature signature;
	u32 timestamp;
	struct node_id node_id;
	u8 rgb_color[3];
	u8 alias[32];
	u8 *features, *addresses;
	struct tlv_node_ann_tlvs *na_tlv;

	if (was_unknown)
		*was_unknown = false;

	/* Make sure we own msg, even if we don't save it. */
	if (taken(msg))
		tal_steal(tmpctx, msg);

	/* Note: validity of node_id is already checked. */
	na_tlv = tlv_node_ann_tlvs_new(tmpctx);
	if (!fromwire_node_announcement(tmpctx, msg,
					&signature, &features, &timestamp,
					&node_id, rgb_color, alias,
					&addresses,
					na_tlv)) {
		return false;
	}

	node = get_node(rstate, &node_id);

	if (node == NULL || !node_has_broadcastable_channels(node)) {
		struct pending_node_announce *pna;
		/* BOLT #7:
		 *
		 * - if `node_id` is NOT previously known from a
		 *   `channel_announcement` message, OR if `timestamp` is NOT
		 *   greater than the last-received `node_announcement` from
		 *   this `node_id`:
		 *    - SHOULD ignore the message.
		 */
		/* Check if we are currently verifying the txout for a
		 * matching channel */
		pna = pending_node_map_get(rstate->pending_node_map,
					   &node_id);
		if (!pna) {
			if (was_unknown)
				*was_unknown = true;
			bad_gossip_order(msg, peer,
					 type_to_string(tmpctx, struct node_id,
							&node_id));
			return false;
		} else if (timestamp <= pna->timestamp)
			/* Ignore old ones: they're OK (unless from store). */
			return index == 0;

		SUPERVERBOSE("Deferring node_announcement for node %s",
			     type_to_string(tmpctx, struct node_id, &node_id));
		pna->timestamp = timestamp;
		pna->index = index;
		tal_free(pna->node_announcement);
		clear_softref(pna, &pna->peer_softref);
		pna->node_announcement = tal_dup_talarr(pna, u8, msg);
		set_softref(pna, &pna->peer_softref, peer);
		return true;
	}

	if (node->bcast.index) {
		bool only_tlv_diff;

		if (index != 0) {
			status_broken("gossip_store node_announcement %u replaces %u!",
				      index, node->bcast.index);
			return false;
		}

		if (node->bcast.timestamp >= timestamp) {
			SUPERVERBOSE("Ignoring node announcement, it's outdated.");
			/* OK unless we're loading from store */
			return index == 0;
		}

		/* Allow redundant updates once every 7 days */
		if (timestamp < node->bcast.timestamp + GOSSIP_PRUNE_INTERVAL(rstate->dev_fast_gossip_prune) / 2
		    && !nannounce_different(rstate->gs, node, msg,
					    &only_tlv_diff)) {
			SUPERVERBOSE(
			    "Ignoring redundant nannounce for %s"
			    " (last %u, now %u)",
			    type_to_string(tmpctx, struct node_id, &node_id),
			    node->bcast.timestamp, timestamp);
			/* Ignoring != failing */
			return true;
		}

		/* Make sure it's not spamming us. */
		if (!ratelimit(rstate,
			       &node->tokens, node->bcast.timestamp, timestamp)) {
			status_peer_debug(peer ? &peer->id : NULL,
					  "Ignoring spammy nannounce for %s"
					  " (last %u, now %u)",
					  type_to_string(tmpctx,
							 struct node_id,
							 &node_id),
					  node->bcast.timestamp, timestamp);
			/* Ignoring != failing */
			return true;
		}
	}

	/* Harmless if it was never added */
	gossip_store_delete(rstate->gs,
			    &node->bcast,
			    WIRE_NODE_ANNOUNCEMENT);

	node->bcast.timestamp = timestamp;
	if (node->bcast.timestamp > rstate->last_timestamp
	    && node->bcast.timestamp < time_now().ts.tv_sec)
		rstate->last_timestamp = node->bcast.timestamp;

	if (index)
		node->bcast.index = index;
	else {
		node->bcast.index
			= gossip_store_add(rstate->gs, msg,
					   node->bcast.timestamp,
					   node_id_eq(&node_id,
						      &rstate->local_id),
					   NULL);
		peer_supplied_good_gossip(peer, 1);
	}

	/* Only log this if *not* loading from store. */
	if (!index)
		status_peer_debug(peer ? &peer->id : NULL,
				  "Received node_announcement for node %s",
				  type_to_string(tmpctx, struct node_id,
						 &node_id));

	return true;
}

u8 *handle_node_announcement(struct routing_state *rstate, const u8 *node_ann,
			     struct peer *peer, bool *was_unknown)
{
	u8 *serialized;
	struct sha256_double hash;
	secp256k1_ecdsa_signature signature;
	u32 timestamp;
	struct node_id node_id;
	u8 rgb_color[3];
	u8 alias[32];
	u8 *features, *addresses;
	struct wireaddr *wireaddrs;
	size_t len = tal_count(node_ann);
	struct tlv_node_ann_tlvs *na_tlv;

	if (was_unknown)
		*was_unknown = false;

	serialized = tal_dup_arr(tmpctx, u8, node_ann, len, 0);
	na_tlv = tlv_node_ann_tlvs_new(tmpctx);
	if (!fromwire_node_announcement(tmpctx, serialized,
					&signature, &features, &timestamp,
					&node_id, rgb_color, alias,
					&addresses,
					na_tlv)) {
		/* BOLT #7:
		 *
		 *   - if `node_id` is NOT a valid compressed public key:
		 *    - SHOULD fail the connection.
		 *    - MUST NOT process the message further.
		 */
		u8 *err = towire_warningfmt(rstate, NULL,
					    "Malformed node_announcement %s",
					    tal_hex(tmpctx, node_ann));
		return err;
	}

	sha256_double(&hash, serialized + 66, tal_count(serialized) - 66);
	/* If node_id is invalid, it fails here */
	if (!check_signed_hash_nodeid(&hash, &signature, &node_id)) {
		/* BOLT #7:
		 *
		 * - if `signature` is not a valid signature, using
                 *   `node_id` of the double-SHA256 of the entire
                 *   message following the `signature` field
                 *   (including unknown fields following
                 *   `fee_proportional_millionths`):
		 *    - MUST NOT process the message further.
		 *    - SHOULD fail the connection.
		 */
		u8 *err = towire_warningfmt(rstate, NULL,
					    "Bad signature for %s hash %s"
					    " on node_announcement %s",
					    type_to_string(tmpctx,
							   secp256k1_ecdsa_signature,
							   &signature),
					    type_to_string(tmpctx,
							   struct sha256_double,
							   &hash),
					    tal_hex(tmpctx, node_ann));
		return err;
	}

	wireaddrs = fromwire_wireaddr_array(tmpctx, addresses);
	if (!wireaddrs) {
		/* BOLT #7:
		 *
		 * - if `addrlen` is insufficient to hold the address
		 *  descriptors of the known types:
		 *    - SHOULD fail the connection.
		 */
		u8 *err = towire_warningfmt(rstate, NULL,
					    "Malformed wireaddrs %s in %s.",
					    tal_hex(tmpctx, wireaddrs),
					    tal_hex(tmpctx, node_ann));
		return err;
	}

	/* May still fail, if we don't know the node. */
	routing_add_node_announcement(rstate, serialized, 0, peer, was_unknown);
	return NULL;
}

void route_prune(struct routing_state *rstate)
{
	u64 now = gossip_time_now(rstate).ts.tv_sec;
	/* Anything below this highwater mark ought to be pruned */
	const s64 highwater = now - GOSSIP_PRUNE_INTERVAL(rstate->dev_fast_gossip_prune);
	struct chan **pruned = tal_arr(tmpctx, struct chan *, 0);
	u64 idx;

	/* Now iterate through all channels and see if it is still alive */
	for (struct chan *chan = uintmap_first(&rstate->chanmap, &idx);
	     chan;
	     chan = uintmap_after(&rstate->chanmap, &idx)) {
		/* Local-only?  Don't prune. */
		if (!is_chan_public(chan))
			continue;

		/* BOLT #7:
		 *   - if a channel's oldest `channel_update`s `timestamp` is
		 *     older than two weeks (1209600 seconds):
		 *    - MAY prune the channel.
		 */
		/* This is a fancy way of saying "both ends must refresh!" */
		if (!is_halfchan_defined(&chan->half[0])
		    || chan->half[0].bcast.timestamp < highwater
		    || !is_halfchan_defined(&chan->half[1])
		    || chan->half[1].bcast.timestamp < highwater) {
			status_debug(
			    "Pruning channel %s from network view (ages %"PRIu64" and %"PRIu64"s)",
			    type_to_string(tmpctx, struct short_channel_id,
					   &chan->scid),
			    is_halfchan_defined(&chan->half[0])
			    ? now - chan->half[0].bcast.timestamp : 0,
			    is_halfchan_defined(&chan->half[1])
			    ? now - chan->half[1].bcast.timestamp : 0);

			/* This may perturb iteration so do outside loop. */
			tal_arr_expand(&pruned, chan);
		}
	}

	/* Look for channels we had an announcement for, but no update. */
	for (struct unupdated_channel *uc
		     = uintmap_first(&rstate->unupdated_chanmap, &idx);
	     uc;
	     uc = uintmap_after(&rstate->unupdated_chanmap, &idx)) {
		if (uc->added.ts.tv_sec < highwater) {
			tal_free(uc);
		}
	}

	/* Now free all the chans and maybe even nodes. */
	for (size_t i = 0; i < tal_count(pruned); i++) {
		remove_channel_from_store(rstate, pruned[i]);
		free_chan(rstate, pruned[i]);
	}
}

bool routing_add_private_channel(struct routing_state *rstate,
				 const struct node_id *id,
				 struct amount_sat capacity,
				 const u8 *chan_ann, u64 index)
{
	struct short_channel_id scid;
	struct node_id node_id[2];
	struct pubkey ignorekey;
	struct chan *chan;
	u8 *features;
	secp256k1_ecdsa_signature ignoresig;
	struct bitcoin_blkid chain_hash;

	if (!fromwire_channel_announcement(tmpctx, chan_ann,
					   &ignoresig,
					   &ignoresig,
					   &ignoresig,
					   &ignoresig,
					   &features,
					   &chain_hash,
					   &scid,
					   &node_id[0],
					   &node_id[1],
					   &ignorekey,
					   &ignorekey))
		return false;

	/* Happens on channeld restart. */
	if (get_channel(rstate, &scid))
		return true;

	/* Make sure this id (if any) was allowed to create this */
	if (id) {
		struct node_id expected[2];
		int cmp = node_id_cmp(&rstate->local_id, id);

		if (cmp < 0) {
			expected[0] = rstate->local_id;
			expected[1] = *id;
		} else if (cmp > 0) {
			expected[0] = *id;
			expected[1] = rstate->local_id;
		} else {
			/* lightningd sets id, so this is fatal */
			status_failed(STATUS_FAIL_MASTER_IO,
				      "private_channel peer was us?");
		}

		if (!node_id_eq(&node_id[0], &expected[0])
		    || !node_id_eq(&node_id[1], &expected[1])) {
			status_peer_broken(id, "private channel %s<->%s invalid",
					   type_to_string(tmpctx, struct node_id,
							  &node_id[0]),
					   type_to_string(tmpctx, struct node_id,
							  &node_id[1]));
			return false;
		}
	}

	/* Create new (unannounced) channel */
	chan = new_chan(rstate, &scid, &node_id[0], &node_id[1], capacity);
	if (!index) {
		u8 *msg = towire_gossip_store_private_channel(tmpctx,
							      capacity,
							      chan_ann);
		index = gossip_store_add(rstate->gs, msg, 0, false, NULL);
	}
	chan->bcast.index = index;
	return true;
}

struct timeabs gossip_time_now(const struct routing_state *rstate)
{
#if DEVELOPER
	if (rstate->gossip_time)
		return *rstate->gossip_time;
#endif
	return time_now();
}

const char *unfinalized_entries(const tal_t *ctx, struct routing_state *rstate)
{
	struct unupdated_channel *uc;
	u64 index;
	struct pending_node_announce *pna;
	struct pending_node_map_iter it;

	uc = uintmap_first(&rstate->unupdated_chanmap, &index);
	if (uc)
		return tal_fmt(ctx, "Unupdated channel_announcement at %u",
			       uc->index);

	pna = pending_node_map_first(rstate->pending_node_map, &it);
	if (pna)
		return tal_fmt(ctx, "Waiting node_announcement at %u",
			       pna->index);

	return NULL;
}

/* Gossip store was corrupt, forget anything we loaded. */
void remove_all_gossip(struct routing_state *rstate)
{
	struct node *n;
	struct node_map_iter nit;
	struct chan *c;
	struct unupdated_channel *uc;
	u64 index;
	struct pending_cannouncement *pca;
	struct pending_cannouncement_map_iter pit;
	struct pending_node_map_iter pnait;

	/* We don't want them to try to delete from store, so do this
	 * manually. */
	while ((n = node_map_first(rstate->nodes, &nit)) != NULL) {
		tal_del_destructor2(n, destroy_node, rstate);
		if (node_uses_chan_map(n))
			chan_map_clear(&n->chans.map);
		node_map_del(rstate->nodes, n);
		tal_free(n);
	}

	/* Now free all the channels. */
	while ((c = uintmap_first(&rstate->chanmap, &index)) != NULL) {
		uintmap_del(&rstate->chanmap, index);
#if DEVELOPER
		c->sat = amount_sat((unsigned long)c);
#endif
		tal_free(c);
	}

	while ((uc = uintmap_first(&rstate->unupdated_chanmap, &index)) != NULL)
		tal_free(uc);

	while ((pca = pending_cannouncement_map_first(&rstate->pending_cannouncements, &pit)) != NULL)
		tal_free(pca);

	/* Freeing unupdated chanmaps should empty this */
	assert(pending_node_map_first(rstate->pending_node_map, &pnait) == NULL);
}
