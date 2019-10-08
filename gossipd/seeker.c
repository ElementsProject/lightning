/* This contains the code which actively seeks out gossip from peers */
#include <bitcoin/short_channel_id.h>
#include <ccan/list/list.h>
#include <ccan/tal/tal.h>
#include <common/status.h>
#include <common/timeout.h>
#include <common/type_to_string.h>
#include <gossipd/gossipd.h>
#include <gossipd/queries.h>
#include <gossipd/seeker.h>

/* Gossip we're seeking at the moment. */
struct seeker {
	/* Do we think we're missing gossip?  Contains timer to re-check */
	struct oneshot *gossip_missing;

	/* Channels we've heard about, but don't know. */
	struct short_channel_id *unknown_scids;
};

struct seeker *new_seeker(struct daemon *daemon)
{
	struct seeker *seeker = tal(daemon, struct seeker);
	seeker->gossip_missing = NULL;
	seeker->unknown_scids = tal_arr(seeker, struct short_channel_id, 0);

	return seeker;
}


/*~ This is a timer, which goes off 10 minutes after the last time we noticed
 * that gossip was missing. */
static void gossip_not_missing(struct daemon *daemon)
{
	struct seeker *seeker = daemon->seeker;

	/* Corner case: no peers, try again! */
	if (list_empty(&daemon->peers))
		gossip_missing(daemon, daemon->seeker);
	else {
		struct peer *peer;

		seeker->gossip_missing = tal_free(seeker->gossip_missing);
		status_info("We seem to be caught up on gossip messages");
		/* Free any lagging/stale unknown scids. */
		seeker->unknown_scids = tal_free(seeker->unknown_scids);

		/* Reset peers we marked as HIGH */
		list_for_each(&daemon->peers, peer, list) {
			if (peer->gossip_level != GOSSIP_HIGH)
				continue;
			if (!peer->gossip_queries_feature)
				continue;
			peer->gossip_level = peer_gossip_level(daemon, true);
			setup_gossip_range(peer);
		}
	}
}

static bool peer_is_not_gossip_high(const struct peer *peer)
{
	return peer->gossip_level != GOSSIP_HIGH;
}

/* We've found gossip is missing. */
void gossip_missing(struct daemon *daemon, struct seeker *seeker)
{
	if (!seeker->gossip_missing) {
		status_info("We seem to be missing gossip messages");
		/* FIXME: we could use query_channel_range. */
		/* Make some peers gossip harder. */
		for (size_t i = 0; i < 3; i++) {
			struct peer *peer = random_peer(daemon,
							peer_is_not_gossip_high);

			if (!peer)
				break;

			status_info("%s: gossip harder!",
				    type_to_string(tmpctx, struct node_id,
						   &peer->id));
			peer->gossip_level = GOSSIP_HIGH;
			setup_gossip_range(peer);
		}
	}

	tal_free(seeker->gossip_missing);
	/* Check again in 10 minutes. */
	seeker->gossip_missing = new_reltimer(&daemon->timers, daemon,
					       time_from_sec(600),
					       gossip_not_missing, daemon);
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

bool seeker_gossip(const struct seeker *seeker)
{
	return seeker->gossip_missing != NULL;
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
