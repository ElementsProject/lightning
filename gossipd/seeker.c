/* This contains the code which actively seeks out gossip from peers */
#include <bitcoin/short_channel_id.h>
#include <ccan/list/list.h>
#include <ccan/tal/tal.h>
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

	/* Normal running. */
	NORMAL,
};

/* Gossip we're seeking at the moment. */
struct seeker {
	struct daemon *daemon;

	enum seeker_state state;

	/* Timer which checks on progress every minute */
	struct oneshot *check_timer;

	/* Channels we've heard about, but don't know. */
	struct short_channel_id *unknown_scids;

	/* Timestamp of gossip store (or 0). */
	u32 last_gossip_timestamp;

	/* During startup, we ask a single peer for gossip. */
	struct peer *random_peer_softref;

	/* This checks progress of our random peer during startup */
	size_t prev_gossip_count;
};

/* Mutual recursion */
static void seeker_check(struct seeker *seeker);

static void begin_check_timer(struct seeker *seeker)
{
	const u32 polltime = GOSSIP_SEEKER_INTERVAL(seeker);

	seeker->check_timer = new_reltimer(&seeker->daemon->timers,
					   seeker,
					   time_from_sec(polltime),
					   seeker_check, seeker);
}

struct seeker *new_seeker(struct daemon *daemon, u32 timestamp)
{
	struct seeker *seeker = tal(daemon, struct seeker);

	seeker->daemon = daemon;
	seeker->unknown_scids = tal_arr(seeker, struct short_channel_id, 0);
	seeker->last_gossip_timestamp = timestamp;
	seeker->state = STARTING_UP_NEED_PEER;
	begin_check_timer(seeker);
	return seeker;
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

static void check_firstpeer(struct seeker *seeker)
{
	struct peer *peer = seeker->random_peer_softref, *p;

	/* It might have died, pick another. */
	if (!peer) {
		status_debug("seeker: startup peer died, re-choosing");
		peer = random_peer(seeker->daemon, peer_has_gossip_queries);
		/* No peer?  Wait for a new one to join. */
		if (!peer) {
			status_debug("seeker: no peers, waiting");
			seeker->state = STARTING_UP_NEED_PEER;
			return;
		}

		peer_gossip_startup(seeker, peer);
		return;
	}

	/* If no progress, we assume it's finished, and if it hasn't,
	 * we'll end up querying backwards in next steps. */
	if (peer_made_progress(seeker))
		return;

	/* Begin normal gossip regime */
	status_debug("seeker: startup peer finished");
	clear_softref(seeker, &seeker->random_peer_softref);
	seeker->state = NORMAL;
	list_for_each(&seeker->daemon->peers, p, list) {
		if (p == peer)
			continue;

		normal_gossip_start(seeker, p);
	}
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
	case NORMAL:
		/* FIXME: Check! */
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
		seeker->state = STARTING_UP_FIRSTPEER;
		return;
	case STARTING_UP_FIRSTPEER:
		/* Waiting for seeker_check to release us */
		return;
	case NORMAL:
		normal_gossip_start(seeker, peer);
		return;
	}
	abort();
}

/* We've found gossip is missing. */
void gossip_missing(struct daemon *daemon, struct seeker *seeker)
{
	/* FIXME */
}

bool remove_unknown_scid(struct seeker *seeker,
			 const struct short_channel_id *scid)
{
	for (size_t i = 0; i < tal_count(seeker->unknown_scids); i++) {
		if (short_channel_id_eq(&seeker->unknown_scids[i], scid)) {
			tal_arr_remove(&seeker->unknown_scids, i);
			return true;
		}
	}
	return false;
}

bool add_unknown_scid(struct seeker *seeker,
		      const struct short_channel_id *scid)
{
	/* Don't go overboard if we're already asking for a lot. */
	if (tal_count(seeker->unknown_scids) > 1000)
		return false;

	/* Check we're not already getting this one. */
	for (size_t i = 0; i < tal_count(seeker->unknown_scids); i++)
		if (short_channel_id_eq(&seeker->unknown_scids[i], scid))
			return false;

	tal_arr_expand(&seeker->unknown_scids, *scid);
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

	/* This is best effort: if peer is busy, we'll try next time. */
	query_short_channel_ids(daemon, peer, daemon->seeker->unknown_scids,
				NULL);
}
