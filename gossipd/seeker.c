/* This contains the code which actively seeks out gossip from peers */
#include <bitcoin/chainparams.h>
#include <bitcoin/short_channel_id.h>
#include <ccan/array_size/array_size.h>
#include <ccan/asort/asort.h>
#include <ccan/list/list.h>
#include <ccan/mem/mem.h>
#include <ccan/tal/str/str.h>
#include <ccan/tal/tal.h>
#include <common/decode_array.h>
#include <common/pseudorand.h>
#include <common/random_select.h>
#include <common/status.h>
#include <common/timeout.h>
#include <common/type_to_string.h>
#include <gossipd/gossipd.h>
#include <gossipd/queries.h>
#include <gossipd/routing.h>
#include <gossipd/seeker.h>
#include <wire/peer_wire.h>

#define GOSSIP_SEEKER_INTERVAL(seeker) \
	DEV_FAST_GOSSIP((seeker)->daemon->rstate->dev_fast_gossip, 5, 60)

enum seeker_state {
	/* Still streaming gossip from single peer. */
	STARTING_UP,

	/* Probing: checking our startup really is finished. */
	PROBING_SCIDS,

	/* Probing: check that we have node_announcements. */
	PROBING_NANNOUNCES,

	/* Normal running. */
	NORMAL,

	/* Asking a peer for unknown scids. */
	ASKING_FOR_UNKNOWN_SCIDS,

	/* Asking a peer for stale scids. */
	ASKING_FOR_STALE_SCIDS,
};

#if DEVELOPER
bool dev_suppress_gossip;
#endif

/* Gossip we're seeking at the moment. */
struct seeker {
	struct daemon *daemon;

	enum seeker_state state;

	/* Timer which checks on progress every minute */
	struct oneshot *check_timer;

	/* Channels we've heard about, but don't know (by scid). */
	UINTMAP(bool) unknown_scids;

	/* Channels we've heard about newer timestamps for (by scid).  u8 is
	 * query_flags. */
	UINTMAP(u8 *) stale_scids;

	/* Range of scid blocks we've probed. */
	size_t scid_probe_start, scid_probe_end;

	/* During startup, we ask a single peer for gossip. */
	struct peer *random_peer_softref;

	/* This checks progress of our random peer */
	size_t prev_gossip_count;

	/* Array of scids for node announcements. */
	struct short_channel_id *nannounce_scids;
	u8 *nannounce_query_flags;

	/* Are there any node_ids we didn't know?  Implies we're
	 * missing channels. */
	bool unknown_nodes;

	/* Peers we've asked to stream us gossip */
	struct peer *gossiper_softref[5];

	/* A peer that told us about unknown gossip. */
	struct peer *preferred_peer_softref;

};

/* Mutual recursion */
static void seeker_check(struct seeker *seeker);
static void probe_some_random_scids(struct seeker *seeker);

static void begin_check_timer(struct seeker *seeker)
{
	const u32 polltime = GOSSIP_SEEKER_INTERVAL(seeker);

	seeker->check_timer = new_reltimer(&seeker->daemon->timers,
					   seeker,
					   time_from_sec(polltime),
					   seeker_check, seeker);
}

/* Set this peer as our random peer; return false if NULL. */
static bool selected_peer(struct seeker *seeker, struct peer *peer)
{
	if (!peer)
		return false;

	set_softref(seeker, &seeker->random_peer_softref, peer);

	/* Give it some grace in case we immediately hit timer */
	seeker->prev_gossip_count
		= peer->gossip_counter - GOSSIP_SEEKER_INTERVAL(seeker);
	return true;
}

#define set_state(seeker, state, peer, ...)				\
	set_state_((seeker), (state), (peer), stringify(state), __VA_ARGS__)

static void set_state_(struct seeker *seeker, enum seeker_state state,
		       struct peer *peer,
		       const char *statename, const char *fmt, ...)
PRINTF_FMT(5,6);

static void set_state_(struct seeker *seeker, enum seeker_state state,
		       struct peer *peer,
		       const char *statename, const char *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	status_peer_debug(peer ? &peer->id : NULL,
			  "seeker: state = %s %s",
			  statename, tal_vfmt(tmpctx, fmt, ap));
	va_end(ap);
	seeker->state = state;
	selected_peer(seeker, peer);
}

struct seeker *new_seeker(struct daemon *daemon)
{
	struct seeker *seeker = tal(daemon, struct seeker);

	seeker->daemon = daemon;
	uintmap_init(&seeker->unknown_scids);
	uintmap_init(&seeker->stale_scids);
	seeker->random_peer_softref = NULL;
	for (size_t i = 0; i < ARRAY_SIZE(seeker->gossiper_softref); i++)
		seeker->gossiper_softref[i] = NULL;
	seeker->preferred_peer_softref = NULL;
	seeker->unknown_nodes = false;
	set_state(seeker, STARTING_UP, NULL, "New seeker");
	begin_check_timer(seeker);
	return seeker;
}

static void set_preferred_peer(struct seeker *seeker, struct peer *peer)
{
	if (seeker->preferred_peer_softref
	    && seeker->preferred_peer_softref != peer) {
		clear_softref(seeker, &seeker->preferred_peer_softref);
		set_softref(seeker, &seeker->preferred_peer_softref, peer);
	}
}

/* Get a random peer, but try our preferred peer first, if any.  This
 * biasses us to the peer that told us of unexpected gossip. */
static struct peer *random_seeker(struct seeker *seeker,
				  bool (*check_peer)(const struct peer *peer))
{
	struct peer *peer = seeker->preferred_peer_softref;

	/* 80% chance of immediately choosing a peer who reported the missing
	 * stuff: they presumably can tell us more about it.  We don't
	 * *always* choose it because it could be simply spamming us with
	 * invalid announcements to get chosen, and we don't handle that case
	 * well yet. */
	if (peer && check_peer(peer) && pseudorand(5) != 0) {
		clear_softref(seeker, &seeker->random_peer_softref);
		return peer;
	}

	return random_peer(seeker->daemon, check_peer);
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

static void disable_gossip_stream(struct seeker *seeker, struct peer *peer)
{
	u8 *msg;

	status_peer_debug(&peer->id, "seeker: disabling gossip");

	/* This is allowed even if they don't understand it (odd) */
	msg = towire_gossip_timestamp_filter(NULL,
					     &chainparams->genesis_blockhash,
					     UINT32_MAX,
					     UINT32_MAX);
	queue_peer_msg(peer, take(msg));
}

static void enable_gossip_stream(struct seeker *seeker, struct peer *peer)
{
	/* We seek some way back, to take into account propagation time */
	const u32 polltime = GOSSIP_SEEKER_INTERVAL(seeker) * 10;
	u32 start = seeker->daemon->rstate->last_timestamp;
	u8 *msg;

#if DEVELOPER
	if (dev_suppress_gossip)
		return;
#endif

	if (start > polltime)
		start -= polltime;
	else
		start = 0;

	status_peer_debug(&peer->id, "seeker: starting gossip");

	/* This is allowed even if they don't understand it (odd) */
	msg = towire_gossip_timestamp_filter(NULL,
					     &chainparams->genesis_blockhash,
					     start,
					     UINT32_MAX);
	queue_peer_msg(peer, take(msg));
}

static void normal_gossip_start(struct seeker *seeker, struct peer *peer)
{
	bool enable_stream = false;

	/* Make this one of our streaming gossipers if we aren't full */
	for (size_t i = 0; i < ARRAY_SIZE(seeker->gossiper_softref); i++) {
		if (seeker->gossiper_softref[i] == NULL) {
			set_softref(seeker, &seeker->gossiper_softref[i], peer);
			enable_stream = true;
			break;
		}
	}

	if (enable_stream)
		enable_gossip_stream(seeker, peer);
	else
		disable_gossip_stream(seeker, peer);
}

/* Turn unknown_scids map into a flat array, removes from map. */
static struct short_channel_id *unknown_scids_remove(const tal_t *ctx,
						     struct seeker *seeker)
{
	struct short_channel_id *scids;
	/* Marshal into an array: we can fit 8000 comfortably. */
	size_t i, max = 8000;
	u64 scid;

	scids = tal_arr(ctx, struct short_channel_id, max);
	i = 0;
	while (uintmap_first(&seeker->unknown_scids, &scid)) {
		scids[i].u64 = scid;
		(void)uintmap_del(&seeker->unknown_scids, scid);
		if (++i == max)
			break;
	}
	tal_resize(&scids, i);
	return scids;
}

/* We have selected this peer to stream us startup gossip */
static void peer_gossip_startup(struct seeker *seeker, struct peer *peer)
{
	status_peer_debug(&peer->id, "seeker: chosen as startup peer");
	selected_peer(seeker, peer);
	normal_gossip_start(seeker, peer);
}

static bool peer_has_gossip_queries(const struct peer *peer)
{
	return peer->gossip_queries_feature;
}

static bool peer_can_take_range_query(const struct peer *peer)
{
	return peer->gossip_queries_feature
		&& !peer->range_replies;
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
	probe_some_random_scids(seeker);
}

/* Returns true if there were scids to seek. */
static bool seek_any_unknown_scids(struct seeker *seeker)
{
	struct peer *peer;
	struct short_channel_id *scids;

	/* Nothing we need to know about? */
	if (uintmap_empty(&seeker->unknown_scids))
		return false;

	/* No peers can answer?  Try again later. */
	peer = random_seeker(seeker, peer_can_take_scid_query);
	if (!peer)
		return false;

	scids = unknown_scids_remove(tmpctx, seeker);
	set_state(seeker, ASKING_FOR_UNKNOWN_SCIDS, peer,
		  "Asking for %zu scids", tal_count(scids));
	if (!query_short_channel_ids(seeker->daemon, peer, scids, NULL,
				     scid_query_done))
		status_failed(STATUS_FAIL_INTERNAL_ERROR,
			      "seeker: quering %zu scids is too many?",
			      tal_count(scids));
	return true;
}

/* Turns stale_scid_map into two arrays, and removes from map */
static struct short_channel_id *stale_scids_remove(const tal_t *ctx,
						   struct seeker *seeker,
						   u8 **query_flags)
{
	struct short_channel_id *scids;
	const u8 *qf;
	/* We can fit 7000 comfortably (8 byte scid, 1 byte flag). */
	size_t i, max = 7000;
	u64 scid;

	scids = tal_arr(ctx, struct short_channel_id, max);
	*query_flags = tal_arr(ctx, u8, max);

	i = 0;
	while ((qf = uintmap_first(&seeker->stale_scids, &scid)) != NULL) {
		scids[i].u64 = scid;
		(*query_flags)[i] = *qf;
		uintmap_del(&seeker->stale_scids, scid);
		tal_free(qf);
		i++;
		if (i == max)
			break;
	}
	tal_resize(&scids, i);
	tal_resize(query_flags, i);
	return scids;
}

static bool seek_any_stale_scids(struct seeker *seeker)
{
	struct peer *peer;
	struct short_channel_id *scids;
	u8 *query_flags;

	/* Nothing we need to know about? */
	if (uintmap_empty(&seeker->stale_scids))
		return false;

	/* No peers can answer?  Try again later. */
	peer = random_seeker(seeker, peer_can_take_scid_query);
	if (!peer)
		return false;

	/* This is best-effort, so this consumes them as well. */
	scids = stale_scids_remove(tmpctx, seeker, &query_flags);
	set_state(seeker, ASKING_FOR_STALE_SCIDS, peer,
		  "Asking for %zu scids", tal_count(scids));

	if (!query_short_channel_ids(seeker->daemon, peer, scids, query_flags,
				     scid_query_done))
		status_failed(STATUS_FAIL_INTERNAL_ERROR,
			      "seeker: quering %zu scids is too many?",
			      tal_count(scids));
	return true;
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

static int cmp_scid(const struct short_channel_id *a,
		    const struct short_channel_id *b,
		    void *unused)
{
	if (a->u64 > b->u64)
		return 1;
	else if (a->u64 < b->u64)
		return -1;
	return 0;
}

/* We can't ask for channels by node_id, so probe at random */
static bool get_unannounced_nodes(const tal_t *ctx,
				  struct routing_state *rstate,
				  size_t max,
				  struct short_channel_id **scids,
				  u8 **query_flags)
{
	size_t num = 0;
	u64 offset;
	double total_weight = 0.0;

	/* Pick an example short_channel_id at random to query.  As a
	 * side-effect this gets the node. */
	*scids = tal_arr(ctx, struct short_channel_id, max);

	/* FIXME: This is inefficient!  Reuse next_block_range here! */
	for (struct chan *c = uintmap_first(&rstate->chanmap, &offset);
	     c;
	     c = uintmap_after(&rstate->chanmap, &offset)) {
		/* Local-only?  Don't ask. */
		if (!is_chan_public(c))
			continue;

		if (c->nodes[0]->bcast.index && c->nodes[1]->bcast.index)
			continue;

		if (num < max) {
			(*scids)[num++] = c->scid;
		} else {
			/* Maybe replace one: approx. reservoir sampling */
			if (random_select(1.0, &total_weight))
				(*scids)[pseudorand(max)] = c->scid;
		}
	}

	if (num == 0) {
		*scids = tal_free(*scids);
		return false;
	}

	if (num < max)
		tal_resize(scids, num);

	/* Sort them into order. */
	asort(*scids, num, cmp_scid, NULL);

	/* Now get flags. */
	*query_flags = tal_arr(ctx, u8, num);
	for (size_t i = 0; i < tal_count(*scids); i++) {
		struct chan *c = get_channel(rstate, &(*scids)[i]);

		(*query_flags)[i] = 0;
		if (!c->nodes[0]->bcast.index)
			(*query_flags)[i] |= SCID_QF_NODE1;
		if (!c->nodes[1]->bcast.index)
			(*query_flags)[i] |= SCID_QF_NODE2;
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

	/* We might have given up on them, then they replied. */
	if (seeker->random_peer_softref != peer) {
		status_peer_debug(&peer->id, "seeker: belated reply: ignoring");
		return;
	}

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

	status_peer_debug(&peer->id,
			  "seeker: found %zu new node_announcements in %zu scids",
			  new_nannounce, num_scids);

	seeker->nannounce_scids = tal_free(seeker->nannounce_scids);
	seeker->nannounce_query_flags = tal_free(seeker->nannounce_query_flags);

	if (!new_nannounce) {
		set_state(seeker, NORMAL, NULL,
			  "No new node_announcements in %zu scids", num_scids);
		return;
	}

	/* Since they told us about new announcements, keep asking them. */
	set_preferred_peer(seeker, peer);

	/* Double every time.  We may skip a few, of course, since map
	 * is changing. */
	num_scids *= 2;
	/* Don't try to create a query larger than 64k */
	if (num_scids > 7000)
		num_scids = 7000;

	if (!get_unannounced_nodes(seeker, seeker->daemon->rstate, num_scids,
				   &seeker->nannounce_scids,
				   &seeker->nannounce_query_flags)) {
		/* Nothing unknown at all?  Great, we're done */
		set_state(seeker, NORMAL, NULL, "No unannounced nodes");
		return;
	}

	peer_gossip_probe_nannounces(seeker);
}

/* Pick a peer, ask it for a few node announcements, to check. */
static void peer_gossip_probe_nannounces(struct seeker *seeker)
{
	struct peer *peer;

	peer = random_seeker(seeker, peer_can_take_scid_query);
	set_state(seeker, PROBING_NANNOUNCES, peer,
		  "Probing for %zu scids",
		  tal_count(seeker->nannounce_scids));
	if (!peer)
		return;

	if (!query_short_channel_ids(seeker->daemon, peer,
				     seeker->nannounce_scids,
				     seeker->nannounce_query_flags,
				     nodeannounce_query_done))
		status_failed(STATUS_FAIL_INTERNAL_ERROR,
			      "seeker: quering %zu scids is too many?",
			      tal_count(seeker->nannounce_scids));
}

/* They have update with this timestamp: do we want it? */
static bool want_update(struct seeker *seeker,
			u32 timestamp, const struct half_chan *hc)
{
	if (!is_halfchan_defined(hc))
		return timestamp != 0;

	if (timestamp <= hc->bcast.timestamp)
		return false;

	return !would_ratelimit_cupdate(seeker->daemon->rstate, hc, timestamp);
}

/* They gave us timestamps.  Do we want updated versions? */
static void check_timestamps(struct seeker *seeker,
			     struct chan *c,
			     const struct channel_update_timestamps *ts,
			     struct peer *peer)
{
	u8 *stale;
	u8 query_flag = 0;

	/* BOLT #7:
	 * * `timestamp_node_id_1` is the timestamp of the `channel_update`
	 *    for `node_id_1`, or 0 if there was no `channel_update` from that
	 *    node.
	 * * `timestamp_node_id_2` is the timestamp of the `channel_update`
	 *    for `node_id_2`, or 0 if there was no `channel_update` from that
	 *    node.
	 */
	if (want_update(seeker, ts->timestamp_node_id_1, &c->half[0]))
		query_flag |= SCID_QF_UPDATE1;
	if (want_update(seeker, ts->timestamp_node_id_2, &c->half[1]))
		query_flag |= SCID_QF_UPDATE2;

	if (!query_flag)
		return;

	/* Add in flags if we're already getting it. */
	stale = uintmap_get(&seeker->stale_scids, c->scid.u64);
	if (!stale) {
		stale = talz(seeker, u8);
		uintmap_add(&seeker->stale_scids, c->scid.u64, stale);
		set_preferred_peer(seeker, peer);
	}
	*stale |= query_flag;
}

static void process_scid_probe(struct peer *peer,
			       u32 first_blocknum, u32 number_of_blocks,
			       const struct range_query_reply *replies)
{
	struct seeker *seeker = peer->daemon->seeker;
	bool new_unknown_scids = false;

	/* We might have given up on them, then they replied. */
	if (seeker->random_peer_softref != peer)
		return;

	clear_softref(seeker, &seeker->random_peer_softref);

	for (size_t i = 0; i < tal_count(replies); i++) {
		struct chan *c = get_channel(seeker->daemon->rstate,
					     &replies[i].scid);
		if (c) {
			check_timestamps(seeker, c, &replies[i].ts, peer);
			continue;
		}

		new_unknown_scids |= add_unknown_scid(seeker, &replies[i].scid,
						      peer);
	}

	/* No new unknown scids, or no more to ask?  We give some wiggle
	 * room in case blocks came in since we started. */
	if (new_unknown_scids
	    && next_block_range(seeker, number_of_blocks,
				&first_blocknum, &number_of_blocks)) {
		/* This must return a peer, since we have the current peer! */
		peer = random_seeker(seeker, peer_can_take_range_query);
		assert(peer);
		selected_peer(seeker, peer);

		query_channel_range(seeker->daemon, peer,
				    first_blocknum, number_of_blocks,
				    QUERY_ADD_TIMESTAMPS,
				    process_scid_probe);
		return;
	}

	/* Channel probe finished, try asking for 128 unannounced nodes. */
	if (!get_unannounced_nodes(seeker, seeker->daemon->rstate, 128,
				   &seeker->nannounce_scids,
				   &seeker->nannounce_query_flags)) {
		/* No unknown nodes.  Great! */
		set_state(seeker, NORMAL, NULL, "No unannounced nodes");
		return;
	}

	peer_gossip_probe_nannounces(seeker);
}

/* Pick a peer, ask it for a few scids, to check. */
static void peer_gossip_probe_scids(struct seeker *seeker)
{
	struct peer *peer;

	peer = random_seeker(seeker, peer_can_take_range_query);
	set_state(seeker, PROBING_SCIDS, peer,
		  "Seeking scids %zu - %zu",
		  seeker->scid_probe_start, seeker->scid_probe_end);
	if (!peer)
		return;

	/* This calls process_scid_probe when we get the reply. */
	query_channel_range(seeker->daemon, peer,
			    seeker->scid_probe_start,
			    seeker->scid_probe_end - seeker->scid_probe_start + 1,
			    QUERY_ADD_TIMESTAMPS,
			    process_scid_probe);
}

static void probe_random_scids(struct seeker *seeker, size_t num_blocks)
{
	u32 avail_blocks;

	/* Ignore early blocks (unless we're before, which would be weird) */
	if (seeker->daemon->current_blockheight
	    < chainparams->when_lightning_became_cool)
		avail_blocks = seeker->daemon->current_blockheight;
	else
		avail_blocks = seeker->daemon->current_blockheight
			- chainparams->when_lightning_became_cool;

	if (avail_blocks < num_blocks) {
		seeker->scid_probe_start = 0;
		seeker->scid_probe_end = seeker->daemon->current_blockheight;
	} else {
		seeker->scid_probe_start
			= chainparams->when_lightning_became_cool
			+ pseudorand(avail_blocks - num_blocks);
		seeker->scid_probe_end
			= seeker->scid_probe_start + num_blocks - 1;
	}

	seeker->nannounce_scids = NULL;
	peer_gossip_probe_scids(seeker);
}

/* We usually get a channel per block, so these cover a fair bit of ground */
static void probe_some_random_scids(struct seeker *seeker)
{
	return probe_random_scids(seeker, 1024);
}

static void probe_many_random_scids(struct seeker *seeker)
{
	return probe_random_scids(seeker, 10000);
}

static void check_firstpeer(struct seeker *seeker)
{
	struct peer *peer = seeker->random_peer_softref, *p;

	/* It might have died, pick another. */
	if (!peer) {
		peer = random_seeker(seeker, peer_has_gossip_queries);
		/* No peer?  Wait for a new one to join. */
		if (!peer) {
			status_debug("seeker: no peers, waiting");
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
	status_peer_debug(&peer->id, "seeker: startup peer finished");
	clear_softref(seeker, &seeker->random_peer_softref);
	list_for_each(&seeker->daemon->peers, p, list) {
		if (p == peer)
			continue;

		normal_gossip_start(seeker, p);
	}

	/* Ask a random peer for all channels, in case we're missing */
	seeker->scid_probe_start = chainparams->when_lightning_became_cool;
	seeker->scid_probe_end = seeker->daemon->current_blockheight;
	if (seeker->scid_probe_start > seeker->scid_probe_end)
		seeker->scid_probe_start = 0;
	peer_gossip_probe_scids(seeker);
}

static void check_probe(struct seeker *seeker,
			void (*restart)(struct seeker *seeker))
{
	struct peer *peer = seeker->random_peer_softref;

	/* It might have died, pick another. */
	if (!peer) {
		restart(seeker);
		return;
	}

	/* Is peer making progress with responses? */
	if (peer_made_progress(seeker))
		return;

	status_peer_debug(&peer->id,
			  "has only moved gossip %zu->%zu for probe, giving up on it",
			  seeker->prev_gossip_count, peer->gossip_counter);
	clear_softref(seeker, &seeker->random_peer_softref);
	restart(seeker);
}

static bool peer_is_not_gossipper(const struct peer *peer)
{
	const struct seeker *seeker = peer->daemon->seeker;

	for (size_t i = 0; i < ARRAY_SIZE(seeker->gossiper_softref); i++) {
		if (seeker->gossiper_softref[i] == peer)
			return false;
	}
	return true;
}

/* FIXME: We should look at gossip performance and replace the underperforming
 * peers in preference. */
static void maybe_rotate_gossipers(struct seeker *seeker)
{
	struct peer *peer;
	size_t i;

	/* If all peers are gossiping, we're done */
	peer = random_seeker(seeker, peer_is_not_gossipper);
	if (!peer)
		return;

	/* If we have a slot free, or ~ 1 per hour */
	for (i = 0; i < ARRAY_SIZE(seeker->gossiper_softref); i++) {
		if (!seeker->gossiper_softref[i]) {
			status_peer_debug(&peer->id, "seeker: filling slot %zu",
					  i);
			goto set_gossiper;
		}
		if (pseudorand(ARRAY_SIZE(seeker->gossiper_softref) * 60) == 0) {
			status_peer_debug(&peer->id,
					  "seeker: replacing slot %zu",
					  i);
			goto clear_and_set_gossiper;
		}
	}
	return;

clear_and_set_gossiper:
	disable_gossip_stream(seeker, seeker->gossiper_softref[i]);
	clear_softref(seeker, &seeker->gossiper_softref[i]);
set_gossiper:
	set_softref(seeker, &seeker->gossiper_softref[i], peer);
	enable_gossip_stream(seeker, peer);
}

static bool seek_any_unknown_nodes(struct seeker *seeker)
{
	if (!seeker->unknown_nodes)
		return false;

	seeker->unknown_nodes = false;
	probe_many_random_scids(seeker);
	return true;
}

/* Periodic timer to see how our gossip is going. */
static void seeker_check(struct seeker *seeker)
{
#if DEVELOPER
	if (dev_suppress_gossip)
		goto out;
#endif

	/* We don't do anything until we're synced. */
	if (seeker->daemon->current_blockheight == 0)
		goto out;

	switch (seeker->state) {
	case STARTING_UP:
		check_firstpeer(seeker);
		break;
	case PROBING_SCIDS:
		check_probe(seeker, peer_gossip_probe_scids);
		break;
	case ASKING_FOR_UNKNOWN_SCIDS:
		check_probe(seeker, probe_many_random_scids);
		break;
	case ASKING_FOR_STALE_SCIDS:
		check_probe(seeker, probe_some_random_scids);
		break;
	case PROBING_NANNOUNCES:
		check_probe(seeker, peer_gossip_probe_nannounces);
		break;
	case NORMAL:
		maybe_rotate_gossipers(seeker);
		if (!seek_any_unknown_scids(seeker)
		    && !seek_any_stale_scids(seeker))
			seek_any_unknown_nodes(seeker);
		break;
	}

out:
	begin_check_timer(seeker);
}

/* We get this when we have a new peer. */
void seeker_setup_peer_gossip(struct seeker *seeker, struct peer *peer)
{
	/* Can't do anything useful with these peers. */
	if (!peer->gossip_queries_feature)
		return;

#if DEVELOPER
	if (dev_suppress_gossip)
		return;
#endif
	/* Don't start gossiping until we're synced. */
	if (seeker->daemon->current_blockheight == 0)
		return;

	switch (seeker->state) {
	case STARTING_UP:
		if (seeker->random_peer_softref == NULL)
			peer_gossip_startup(seeker, peer);
		/* Waiting for seeker_check to release us */
		return;

	/* In these states, we set up peers to stream gossip normally */
	case PROBING_SCIDS:
	case PROBING_NANNOUNCES:
	case NORMAL:
	case ASKING_FOR_UNKNOWN_SCIDS:
	case ASKING_FOR_STALE_SCIDS:
		normal_gossip_start(seeker, peer);
		return;
	}
	abort();
}

bool remove_unknown_scid(struct seeker *seeker,
			 const struct short_channel_id *scid,
			 bool found /*FIXME: use this info!*/)
{
	return uintmap_del(&seeker->unknown_scids, scid->u64);
}

bool add_unknown_scid(struct seeker *seeker,
		      const struct short_channel_id *scid,
		      struct peer *peer)
{
	/* Check we're not already getting this one. */
	if (!uintmap_add(&seeker->unknown_scids, scid->u64, true))
		return false;

	set_preferred_peer(seeker, peer);
	return true;
}

/* This peer told us about an update to an unknown channel.  Ask it for a
 * channel_announcement. */
void query_unknown_channel(struct daemon *daemon,
			   struct peer *peer,
			   const struct short_channel_id *id)
{
	/* Too many, or duplicate? */
	if (!add_unknown_scid(daemon->seeker, id, peer))
		return;
}

/* This peer told us about an unknown node.  Start probing it. */
void query_unknown_node(struct seeker *seeker, struct peer *peer)
{
	seeker->unknown_nodes = true;
	set_preferred_peer(seeker, peer);
}
