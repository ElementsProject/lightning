#include <common/bolt11.h>
#include <common/utils.h>
#include <gossipd/gossipd_wiregen.h>
#include <lightningd/log.h>
#include <lightningd/peer_control.h>
#include <lightningd/routehint.h>

static void append_routes(struct route_info **dst, const struct route_info *src)
{
	size_t n = tal_count(*dst);

	tal_resize(dst, n + tal_count(src));
	memcpy(*dst + n, src, tal_count(src) * sizeof(*src));
}

static void append_bools(bool **dst, const bool *src)
{
	size_t n = tal_count(*dst);

	tal_resize(dst, n + tal_count(src));
	memcpy(*dst + n, src, tal_count(src) * sizeof(*src));
}

static bool scid_in_arr(const struct short_channel_id *scidarr,
			const struct short_channel_id *scid)
{
	for (size_t i = 0; i < tal_count(scidarr); i++)
		if (short_channel_id_eq(&scidarr[i], scid))
			return true;

	return false;
}

struct routehint_candidate *
routehint_candidates(const tal_t *ctx,
		     struct lightningd *ld,
		     const u8 *incoming_channels_reply,
		     bool expose_all_private,
		     const struct short_channel_id *hints,
		     bool *none_public,
		     bool *deadends,
		     struct amount_msat *amount_offline)
{
	struct routehint_candidate *candidates;
	struct route_info *inchans, *private;
	bool *inchan_deadends, *private_deadends;

	if (!fromwire_gossipd_get_incoming_channels_reply(tmpctx,
							  incoming_channels_reply,
							  &inchans,
							  &inchan_deadends,
							  &private,
							  &private_deadends))
		fatal("Gossip gave bad GOSSIPD_GET_INCOMING_CHANNELS_REPLY %s",
		      tal_hex(tmpctx, incoming_channels_reply));

	*none_public = (tal_count(inchans) == 0) && (tal_count(private) > 0);
	*deadends = false;

	/* fromwire explicitly makes empty arrays into NULL */
	if (!inchans) {
		inchans = tal_arr(tmpctx, struct route_info, 0);
		inchan_deadends = tal_arr(tmpctx, bool, 0);
	}

	if (expose_all_private) {
		append_routes(&inchans, private);
		append_bools(&inchan_deadends, private_deadends);
	} else if (hints) {
		/* Start by considering all channels as candidates */
		append_routes(&inchans, private);
		append_bools(&inchan_deadends, private_deadends);

		/* Consider only hints they gave */
		for (size_t i = 0; i < tal_count(inchans); i++) {
			if (!scid_in_arr(hints,
					 &inchans[i].short_channel_id)) {
				tal_arr_remove(&inchans, i);
				tal_arr_remove(&inchan_deadends, i);
				i--;
			} else
				/* If they specify directly, we don't
				 * care if it's a deadend */
				inchan_deadends[i] = false;
		}
	} else {
		assert(!hints);
		/* By default, only consider private channels if there are
		 * no public channels *at all* */
		if (tal_count(inchans) == 0) {
			append_routes(&inchans, private);
			append_bools(&inchan_deadends, private_deadends);
		}
	}

	candidates = tal_arr(ctx, struct routehint_candidate, 0);
	*amount_offline = AMOUNT_MSAT(0);

	for (size_t i = 0; i < tal_count(inchans); i++) {
		struct peer *peer;
		struct routehint_candidate candidate;

		/* Do we know about this peer? */
		peer = peer_by_id(ld, &inchans[i].pubkey);
		if (!peer)
			continue;

		/* Does it have a channel in state CHANNELD_NORMAL */
		candidate.c = peer_normal_channel(peer);
		if (!candidate.c)
			continue;

		/* Is it a dead-end? */
		if (inchan_deadends[i]) {
			*deadends = true;
			continue;
		}

		candidate.capacity = channel_amount_receivable(candidate.c);

		/* Is it offline? */
		if (candidate.c->owner == NULL) {
			if (!amount_msat_add(amount_offline,
					     *amount_offline,
					     candidate.capacity))
				fatal("Overflow summing offline capacity!");
			continue;
		}
		candidate.r = &inchans[i];
		tal_arr_expand(&candidates, candidate);
	}

	return candidates;
}
