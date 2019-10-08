/* This contains the code which actively seeks out gossip from peers */
#include <bitcoin/short_channel_id.h>
#include <ccan/list/list.h>
#include <ccan/mem/mem.h>
#include <ccan/tal/tal.h>
#include <common/decode_array.h>
#include <common/memleak.h>
#include <common/pseudorand.h>
#include <common/status.h>
#include <common/timeout.h>
#include <common/type_to_string.h>
#include <gossipd/gossipd.h>
#include <gossipd/queries.h>
#include <gossipd/routing.h>
#include <gossipd/seeker.h>
#include <wire/gen_peer_wire.h>

#define GOSSIP_SEEKER_INTERVAL(seeker) \
	DEV_FAST_GOSSIP((seeker)->daemon->rstate->dev_fast_gossip, 5, 60)

enum seeker_state {
	/* First initialized, no peers. */
	STARTING_UP_NEED_PEER,

	/* Still streaming gossip from single peer. */
	STARTING_UP_FIRSTPEER,

	/* Probing scids: need peer to check startup really finished. */
	PROBING_SCIDS_NEED_PEER,

	/* Probing: checking our startup really is finished. */
	PROBING_SCIDS,

	/* Probing: need peer to check that we have node_announcements. */
	PROBING_NANNOUNCES_NEED_PEER,

	/* Probing: check that we have node_announcements. */
	PROBING_NANNOUNCES,

	/* Normal running. */
	NORMAL,

	/* Asking a peer for unknown scids. */
	ASKING_FOR_UNKNOWN_SCIDS,
};

/* Passthrough helper for HTABLE_DEFINE_TYPE */
static const struct short_channel_id *scid_pass(const struct short_channel_id *s)
{
	return s;
}

HTABLE_DEFINE_TYPE(struct short_channel_id,
		   scid_pass, hash_scid, short_channel_id_eq, scid_map);

/* Gossip we're seeking at the moment. */
struct seeker {
	struct daemon *daemon;

	enum seeker_state state;

	/* Timer which checks on progress every minute */
	struct oneshot *check_timer;

	/* Channels we've heard about, but don't know. */
	struct scid_map unknown_scids;

	/* Range of scid blocks we've probed. */
	size_t scid_probe_start, scid_probe_end;

	/* Timestamp of gossip store (or 0). */
	u32 last_gossip_timestamp;

	/* During startup, we ask a single peer for gossip. */
	struct peer *random_peer_softref;

	/* This checks progress of our random peer */
	size_t prev_gossip_count;

	/* Array of scids for node announcements. */
	struct short_channel_id *nannounce_scids;
	u8 *nannounce_query_flags;
	size_t nannounce_offset;
};

/* Mutual recursion */
static void seeker_check(struct seeker *seeker);

/* If we think we might be missing something, call with true.  If we
 * think we're caught up, call with false. */
static void probe_random_scids(struct seeker *seeker,
			       bool suspect_something_wrong);

static void begin_check_timer(struct seeker *seeker)
{
	const u32 polltime = GOSSIP_SEEKER_INTERVAL(seeker);

	seeker->check_timer = new_reltimer(&seeker->daemon->timers,
					   seeker,
					   time_from_sec(polltime),
					   seeker_check, seeker);
}

#if DEVELOPER
static void memleak_help_seeker(struct htable *memtable,
				struct seeker *seeker)
{
	memleak_remove_htable(memtable, &seeker->unknown_scids.raw);
}
#endif /* DEVELOPER */

#define set_state(seeker, state) \
	set_state_((seeker), (state), stringify(state))

static void set_state_(struct seeker *seeker, enum seeker_state state,
		       const char *statename)
{
	status_debug("seeker: state = %s", statename);
	seeker->state = state;
}

struct seeker *new_seeker(struct daemon *daemon, u32 timestamp)
{
	struct seeker *seeker = tal(daemon, struct seeker);

	seeker->daemon = daemon;
	scid_map_init(&seeker->unknown_scids);
	seeker->last_gossip_timestamp = timestamp;
	set_state(seeker, STARTING_UP_NEED_PEER);
	begin_check_timer(seeker);
	memleak_add_helper(seeker, memleak_help_seeker);
	return seeker;
}

/* Set this peer as our random peer; return false if NULL. */
static bool selected_peer(struct seeker *seeker, struct peer *peer)
{
	if (!peer)
		return false;

	set_softref(seeker, &seeker->random_peer_softref, peer);
	status_debug("seeker: chose peer %s",
		     type_to_string(tmpctx, struct node_id, &peer->id));

	/* Give it some grace in case we immediately hit timer */
	seeker->prev_gossip_count
		= peer->gossip_counter - GOSSIP_SEEKER_INTERVAL(seeker);
	return true;
}

static bool peer_made_progress(struct seeker *seeker)
{
	const struct peer *peer = seeker->random_peer_softref;

	/* Has it made progress (at least one valid update per second)?  If
	 * not, we assume it's finished, and if it hasn't, we'll end up
	 * querying backwards in next steps. */
	if (peer->gossip_counter
	    >= seeker->prev_gossip_count + GOSSIP_SEEKER_INTERVAL(seeker)) {
		seeker->prev_gossip_count = peer->gossip_counter;
		return true;
	}

	return false;
}

static void normal_gossip_start(struct seeker *seeker, struct peer *peer)
{
	u32 start;
	u8 *msg;

	/* FIXME: gets the last minute of gossip, works around our current
	 * lack of discovery if we're missing gossip. */
	if (peer->gossip_enabled)
		start = time_now().ts.tv_sec - 60;
	else
		start = UINT32_MAX;

	status_debug("seeker: starting %s from %s",
		     peer->gossip_enabled ? "gossip" : "disabled gossip",
		     type_to_string(tmpctx, struct node_id, &peer->id));

	/* This is allowed even if they don't understand it (odd) */
	msg = towire_gossip_timestamp_filter(NULL,
					     &seeker->daemon->chain_hash,
					     start,
					     UINT32_MAX);
	queue_peer_msg(peer, take(msg));
}

/* Turn unknown_scids map into a flat array. */
static struct short_channel_id *unknown_scids_arr(const tal_t *ctx,
						  const struct seeker *seeker)
{
	const struct scid_map *map = &seeker->unknown_scids;
	struct short_channel_id *scids, *s;
	size_t i, max;
	struct scid_map_iter it;

	/* Marshal into an array: we can fit 8000 comfortably. */
	if (scid_map_count(map) < 8000)
		max = scid_map_count(map);
	else
		max = 8000;

	scids = tal_arr(ctx, struct short_channel_id, max);
	i = 0;
	for (s = scid_map_first(map, &it); i < max; s = scid_map_next(map, &it))
		scids[i++] = *s;
	assert(i == tal_count(scids));
	return scids;
}

/* We have selected this peer to stream us startup gossip */
static void peer_gossip_startup(struct seeker *seeker, struct peer *peer)
{
	const u32 polltime = GOSSIP_SEEKER_INTERVAL(seeker);
	u8 *msg;
	u32 start;

	if (seeker->last_gossip_timestamp < polltime)
		start = 0;
	else
		start = seeker->last_gossip_timestamp - polltime;

	selected_peer(seeker, peer);

	status_debug("seeker: startup gossip from t=%u from %s",
		     start, type_to_string(tmpctx, struct node_id, &peer->id));
	msg = towire_gossip_timestamp_filter(NULL,
					     &peer->daemon->chain_hash,
					     start, UINT32_MAX);
	queue_peer_msg(peer, take(msg));
}

static bool peer_has_gossip_queries(const struct peer *peer)
{
	return peer->gossip_queries_feature;
}

static bool peer_can_take_range_query(const struct peer *peer)
{
	return peer->gossip_queries_feature
		&& !peer->query_channel_blocks;
}

static bool peer_can_take_scid_query(const struct peer *peer)
{
	return peer->gossip_queries_feature
		&& !peer->scid_query_outstanding;
}

static void scid_query_done(struct peer *peer, bool complete)
{
	struct seeker *seeker = peer->daemon->seeker;

	/* Peer completed!  OK, start random scid probe in case we're
	 * still missing gossip. */
	probe_random_scids(seeker, false);
}

static void seek_any_unknown_scids(struct seeker *seeker)
{
	struct peer *peer;
	struct short_channel_id *scids;

	/* Nothing we need to know about? */
	if (scid_map_count(&seeker->unknown_scids) == 0)
		return;

	/* No peers can answer?  Try again later. */
	peer = random_peer(seeker->daemon, peer_can_take_scid_query);
	if (!peer)
		return;

	set_state(seeker, ASKING_FOR_UNKNOWN_SCIDS);
	selected_peer(seeker, peer);

	scids = unknown_scids_arr(tmpctx, seeker);
	if (!query_short_channel_ids(seeker->daemon, peer, scids, NULL,
				     scid_query_done))
		status_failed(STATUS_FAIL_INTERNAL_ERROR,
			      "seeker: quering %zu scids is too many?",
			      tal_count(scids));
}

static void check_unknown_scid_query(struct seeker *seeker)
{
	struct peer *peer = seeker->random_peer_softref;

	/* Did peer die? */
	if (!peer) {
		probe_random_scids(seeker, true);
		return;
	}

	if (!peer_made_progress(seeker)) {
		status_unusual("Bad gossip: peer %s has only moved gossip %zu->%zu for scid probe, hanging up on it",
			       type_to_string(tmpctx, struct node_id, &peer->id),
			       seeker->prev_gossip_count, peer->gossip_counter);
		tal_free(peer);

		probe_random_scids(seeker, true);
	}
}

/* Returns true and sets first_blocknum and number_of_blocks if
 * there's more to find. */
static bool next_block_range(struct seeker *seeker,
			     u32 prev_num_blocks,
			     u32 *first_blocknum, u32 *number_of_blocks)
{
	const u32 current_height = seeker->daemon->current_blockheight;

	/* We always try to get twice as many as last time. */
	*number_of_blocks = prev_num_blocks * 2;

	if (seeker->scid_probe_start > 0) {
		/* Enlarge probe to cover prior blocks, but twice as many. */
		if (*number_of_blocks > seeker->scid_probe_start) {
			*number_of_blocks = seeker->scid_probe_start;
			*first_blocknum = 0;
		} else {
			*first_blocknum
				= seeker->scid_probe_start - *number_of_blocks;
		}
		seeker->scid_probe_start = *first_blocknum;
		return true;
	}

	/* We allow 6 new blocks since we started; they should be empty anyway */
	if (seeker->scid_probe_end + 6 < current_height) {
		if (seeker->scid_probe_end + *number_of_blocks > current_height)
			*number_of_blocks
				= current_height - seeker->scid_probe_end;
		*first_blocknum = seeker->scid_probe_end + 1;
		seeker->scid_probe_end = *first_blocknum + *number_of_blocks - 1;
		return true;
	}

	/* No more to find. */
	return false;
}

static bool get_unannounced_nodes(const tal_t *ctx,
				  struct routing_state *rstate,
				  size_t off,
				  size_t max,
				  struct short_channel_id **scids,
				  u8 **query_flags)
{
	struct node_map_iter it;
	size_t i = 0, num = 0;
	struct node *n;

	/* Pick an example short_channel_id at random to query.  As a
	 * side-effect this gets the node */
	*scids = tal_arr(ctx, struct short_channel_id, max);
	*query_flags = tal_arr(ctx, u8, max);

	for (n = node_map_first(rstate->nodes, &it);
	     n && num < max;
	     n = node_map_next(rstate->nodes, &it)) {
		if (n->bcast.index)
			continue;

		if (i >= off) {
			struct chan_map_iter cit;
			struct chan *c = first_chan(n, &cit);

			(*scids)[num] = c->scid;
			if (c->nodes[0] == n)
				(*query_flags)[num] = SCID_QF_NODE1;
			else
				(*query_flags)[num] = SCID_QF_NODE2;
			num++;
		}
		i++;
	}

	if (num == 0) {
		*scids = tal_free(*scids);
		*query_flags = tal_free(*query_flags);
		return false;
	}
	if (num < max) {
		tal_resize(scids, num);
		tal_resize(query_flags, i - off);
	}
	return true;
}

/* Mutual recursion */
static void peer_gossip_probe_nannounces(struct seeker *seeker);

static void nodeannounce_query_done(struct peer *peer, bool complete)
{
	struct seeker *seeker = peer->daemon->seeker;
	struct routing_state *rstate = seeker->daemon->rstate;
	size_t new_nannounce = 0, num_scids;

	assert(seeker->random_peer_softref == peer);
	clear_softref(seeker, &seeker->random_peer_softref);

	num_scids = tal_count(seeker->nannounce_scids);
	for (size_t i = 0; i < num_scids; i++) {
		struct chan *c = get_channel(rstate,
					     &seeker->nannounce_scids[i]);
		/* Could have closed since we asked. */
		if (!c)
			continue;
		if ((seeker->nannounce_query_flags[i] & SCID_QF_NODE1)
		    && c->nodes[0]->bcast.index)
			new_nannounce++;
		if ((seeker->nannounce_query_flags[i] & SCID_QF_NODE2)
		    && c->nodes[1]->bcast.index)
			new_nannounce++;
	}

	status_debug("seeker: found %zu new node_announcements in %zu scids",
		     new_nannounce, num_scids);

	seeker->nannounce_scids = tal_free(seeker->nannounce_scids);
	seeker->nannounce_query_flags = tal_free(seeker->nannounce_query_flags);
	seeker->nannounce_offset += num_scids;

	if (!new_nannounce) {
		set_state(seeker, NORMAL);
		return;
	}

	/* Double every time.  We may skip a few, of course, since map
	 * is changing. */
	num_scids *= 2;
	/* Don't try to create a query larger than 64k */
	if (num_scids > 7000)
		num_scids = 7000;

	if (!get_unannounced_nodes(seeker, seeker->daemon->rstate,
				   seeker->nannounce_offset, num_scids,
				   &seeker->nannounce_scids,
				   &seeker->nannounce_query_flags)) {
		/* Nothing unknown at all?  Great, we're done */
		set_state(seeker, NORMAL);
		return;
	}

	set_state(seeker, PROBING_NANNOUNCES_NEED_PEER);
	peer_gossip_probe_nannounces(seeker);
}

/* Pick a peer, ask it for a few node announcements, to check. */
static void peer_gossip_probe_nannounces(struct seeker *seeker)
{
	struct peer *peer;

	peer = random_peer(seeker->daemon, peer_can_take_scid_query);
	if (!peer)
		return;
	selected_peer(seeker, peer);

	set_state(seeker, PROBING_NANNOUNCES);
	if (!query_short_channel_ids(seeker->daemon, peer,
				     seeker->nannounce_scids,
				     seeker->nannounce_query_flags,
				     nodeannounce_query_done))
		status_failed(STATUS_FAIL_INTERNAL_ERROR,
			      "seeker: quering %zu scids is too many?",
			      tal_count(seeker->nannounce_scids));
}

static void process_scid_probe(struct peer *peer,
			       u32 first_blocknum, u32 number_of_blocks,
			       const struct short_channel_id *scids,
			       bool complete)
{
	struct seeker *seeker = peer->daemon->seeker;
	bool new_unknown_scids = false;

	if (seeker->random_peer_softref != peer)
		status_debug("softref = %p, peer = %p",
			     seeker->random_peer_softref, peer);
	assert(seeker->random_peer_softref == peer);
	clear_softref(seeker, &seeker->random_peer_softref);

	for (size_t i = 0; i < tal_count(scids); i++) {
		struct chan *c = get_channel(seeker->daemon->rstate, &scids[i]);
		if (c)
			continue;

		new_unknown_scids |= add_unknown_scid(seeker, &scids[i]);
	}

	/* No new unknown scids, or no more to ask?  We give some wiggle
	 * room in case blocks came in since we started. */
	if (new_unknown_scids
	    && next_block_range(seeker, number_of_blocks,
				&first_blocknum, &number_of_blocks)) {
		/* This must return a peer, since we have the current peer! */
		peer = random_peer(seeker->daemon, peer_can_take_range_query);
		assert(peer);
		selected_peer(seeker, peer);

		query_channel_range(seeker->daemon, peer,
				    first_blocknum, number_of_blocks,
				    QUERY_ADD_TIMESTAMPS,
				    process_scid_probe);
		return;
	}

	/* Channel probe finished, try asking for 32 unannounced nodes. */
	set_state(seeker, PROBING_NANNOUNCES_NEED_PEER);
	seeker->nannounce_offset = 0;

	if (!get_unannounced_nodes(seeker, seeker->daemon->rstate,
				   seeker->nannounce_offset, 32,
				   &seeker->nannounce_scids,
				   &seeker->nannounce_query_flags)) {
		/* No unknown nodes.  Great! */
		set_state(seeker, NORMAL);
		return;
	}

	peer_gossip_probe_nannounces(seeker);
}

/* Pick a peer, ask it for a few scids, to check. */
static void peer_gossip_probe_scids(struct seeker *seeker)
{
	struct peer *peer;

	peer = random_peer(seeker->daemon, peer_can_take_range_query);
	if (!peer)
		return;
	selected_peer(seeker, peer);

	/* This calls process_scid_probe when we get the reply. */
	query_channel_range(seeker->daemon, peer,
			    seeker->scid_probe_start,
			    seeker->scid_probe_end - seeker->scid_probe_start + 1,
			    QUERY_ADD_TIMESTAMPS,
			    process_scid_probe);
	set_state(seeker, PROBING_SCIDS);
}

static void probe_random_scids(struct seeker *seeker,
			       bool suspect_something_wrong)
{
	/* We usually get a channel per block, so this covers a fair
	   bit of ground */
	size_t num_blocks = suspect_something_wrong ? 1008 : 64;

	if (seeker->daemon->current_blockheight < num_blocks) {
		seeker->scid_probe_start = 0;
		seeker->scid_probe_end = seeker->daemon->current_blockheight;
	} else {
		seeker->scid_probe_start
			= pseudorand(seeker->daemon->current_blockheight
				     + num_blocks);
		seeker->scid_probe_end
			= seeker->scid_probe_start + num_blocks - 1;
	}

	set_state(seeker, PROBING_SCIDS_NEED_PEER);
	seeker->nannounce_scids = NULL;
	seeker->nannounce_offset = 0;
	peer_gossip_probe_scids(seeker);
}

static void check_firstpeer(struct seeker *seeker)
{
	struct chan *c;
	u64 index;
	struct peer *peer = seeker->random_peer_softref, *p;

	/* It might have died, pick another. */
	if (!peer) {
		status_debug("seeker: startup peer died, re-choosing");
		peer = random_peer(seeker->daemon, peer_has_gossip_queries);
		/* No peer?  Wait for a new one to join. */
		if (!peer) {
			status_debug("seeker: no peers, waiting");
			set_state(seeker, STARTING_UP_NEED_PEER);
			return;
		}

		peer_gossip_startup(seeker, peer);
		return;
	}

	/* If no progress, we assume it's finished, and if it hasn't,
	 * we'll end up querying backwards in next steps. */
	if (peer_made_progress(seeker))
		return;

	/* Other peers can gossip now. */
	status_debug("seeker: startup peer finished");
	clear_softref(seeker, &seeker->random_peer_softref);
	list_for_each(&seeker->daemon->peers, p, list) {
		if (p == peer)
			continue;

		normal_gossip_start(seeker, p);
	}

	/* We always look up 6 prior to last we have */
	c = uintmap_last(&seeker->daemon->rstate->chanmap, &index);
	if (c && short_channel_id_blocknum(&c->scid) > 6) {
		seeker->scid_probe_start = short_channel_id_blocknum(&c->scid) - 6;
	} else {
		seeker->scid_probe_start = 0;
	}
	seeker->scid_probe_end = seeker->daemon->current_blockheight;
	set_state(seeker, PROBING_SCIDS_NEED_PEER);
	peer_gossip_probe_scids(seeker);
}

static void check_scid_probing(struct seeker *seeker)
{
	/* FIXME: Time them out of they don't respond to gossip */
	struct peer *peer = seeker->random_peer_softref;

	/* It might have died, pick another. */
	if (!peer) {
		status_debug("seeker: scid probing peer died, re-choosing");
		set_state(seeker, PROBING_SCIDS_NEED_PEER);
		peer_gossip_probe_scids(seeker);
		return;
	}
}

static void check_nannounce_probing(struct seeker *seeker)
{
	struct peer *peer = seeker->random_peer_softref;

	/* It might have died, pick another. */
	if (!peer) {
		status_debug("seeker: nannounce probing peer died, re-choosing");
		set_state(seeker, PROBING_NANNOUNCES_NEED_PEER);
		peer_gossip_probe_nannounces(seeker);
		return;
	}

	/* Is peer making progress with responses? */
	if (peer_made_progress(seeker))
		return;

	status_unusual("Peer %s has only moved gossip %zu->%zu for nannounce probe, hanging up on it",
		       type_to_string(tmpctx, struct node_id, &peer->id),
		       seeker->prev_gossip_count, peer->gossip_counter);
	tal_free(peer);

	set_state(seeker, PROBING_NANNOUNCES_NEED_PEER);
	peer_gossip_probe_nannounces(seeker);
}


/* Periodic timer to see how our gossip is going. */
static void seeker_check(struct seeker *seeker)
{
	switch (seeker->state) {
	case STARTING_UP_NEED_PEER:
		break;
	case STARTING_UP_FIRSTPEER:
		check_firstpeer(seeker);
		break;
	case PROBING_SCIDS_NEED_PEER:
		peer_gossip_probe_scids(seeker);
		break;
	case PROBING_SCIDS:
		check_scid_probing(seeker);
		break;
	case ASKING_FOR_UNKNOWN_SCIDS:
		check_unknown_scid_query(seeker);
		break;
	case PROBING_NANNOUNCES_NEED_PEER:
		peer_gossip_probe_nannounces(seeker);
		break;
	case PROBING_NANNOUNCES:
		check_nannounce_probing(seeker);
		break;
	case NORMAL:
		seek_any_unknown_scids(seeker);
		break;
	}

	begin_check_timer(seeker);
}

/* We get this when we have a new peer. */
void seeker_setup_peer_gossip(struct seeker *seeker, struct peer *peer)
{
	/* Can't do anything useful with these peers. */
	if (!peer->gossip_queries_feature)
		return;

	switch (seeker->state) {
	case STARTING_UP_NEED_PEER:
		peer_gossip_startup(seeker, peer);
		set_state(seeker, STARTING_UP_FIRSTPEER);
		return;
	case STARTING_UP_FIRSTPEER:
		/* Waiting for seeker_check to release us */
		return;

	/* In these states, we set up peers to stream gossip normally */
	case PROBING_SCIDS_NEED_PEER:
		peer_gossip_probe_scids(seeker);
		normal_gossip_start(seeker, peer);
		return;
	case PROBING_NANNOUNCES_NEED_PEER:
		peer_gossip_probe_nannounces(seeker);
		normal_gossip_start(seeker, peer);
		return;
	case PROBING_SCIDS:
	case PROBING_NANNOUNCES:
	case NORMAL:
	case ASKING_FOR_UNKNOWN_SCIDS:
		normal_gossip_start(seeker, peer);
		return;
	}
	abort();
}

bool remove_unknown_scid(struct seeker *seeker,
			 const struct short_channel_id *scid,
			 bool found /*FIXME: use this info!*/)
{
	struct short_channel_id *unknown;

	unknown = scid_map_get(&seeker->unknown_scids, scid);
	if (unknown) {
		scid_map_del(&seeker->unknown_scids, unknown);
		tal_free(unknown);
		return true;
	}
	return false;
}

bool add_unknown_scid(struct seeker *seeker,
		      const struct short_channel_id *scid)
{
	/* Check we're not already getting this one. */
	if (scid_map_get(&seeker->unknown_scids, scid))
		return false;

	scid_map_add(&seeker->unknown_scids,
		     tal_dup(seeker, struct short_channel_id, scid));
	return true;
}

/* This peer told us about an update to an unknown channel.  Ask it for a
 * channel_announcement. */
void query_unknown_channel(struct daemon *daemon,
			   struct peer *peer,
			   const struct short_channel_id *id)
{
	/* Too many, or duplicate? */
	if (!add_unknown_scid(daemon->seeker, id))
		return;
}
