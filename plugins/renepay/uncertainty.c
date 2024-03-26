#include "config.h"
#include <plugins/renepay/uncertainty.h>

void uncertainty_route_success(struct uncertainty *uncertainty,
			       const struct route *route)
{
	if (!route->hops)
		return;

	for (size_t i = 0; i < tal_count(route->hops); i++) {
		const struct route_hop *hop = &route->hops[i];
		struct short_channel_id_dir scidd = {hop->scid, hop->direction};

		// FIXME: check errors here, report back
		chan_extra_sent_success(uncertainty->chan_extra_map, &scidd,
					route->hops[i].amount);
	}
}
void uncertainty_remove_htlcs(struct uncertainty *uncertainty,
			      const struct route *route)
{
	// FIXME: how could we get the route details of a sendpay that we did
	// not send?
	if (!route->hops)
		return;

	const size_t pathlen = tal_count(route->hops);
	for (size_t i = 0; i < pathlen; i++) {
		const struct route_hop *hop = &route->hops[i];
		struct short_channel_id_dir scidd = {hop->scid, hop->direction};

		// FIXME: check error
		chan_extra_remove_htlc(uncertainty->chan_extra_map, &scidd,
				       hop->amount);
	}
}

void uncertainty_commit_htlcs(struct uncertainty *uncertainty,
			      const struct route *route)
{
	// FIXME: how could we get the route details of a sendpay that we did
	// not send?
	if (!route->hops)
		return;

	const size_t pathlen = tal_count(route->hops);
	for (size_t i = 0; i < pathlen; i++) {
		const struct route_hop *hop = &route->hops[i];
		struct short_channel_id_dir scidd = {hop->scid, hop->direction};

		// FIXME: check error
		chan_extra_commit_htlc(uncertainty->chan_extra_map, &scidd,
				       hop->amount);
	}
}

void uncertainty_channel_can_send(struct uncertainty *uncertainty,
				  struct route *route, u32 erridx)
{
	if (!route->hops)
		return;

	const size_t pathlen = tal_count(route->hops);
	for (size_t i = 0; i < erridx && i < pathlen; i++) {
		const struct route_hop *hop = &route->hops[i];
		struct short_channel_id_dir scidd = {hop->scid, hop->direction};

		// FIXME: check error
		chan_extra_can_send(uncertainty->chan_extra_map, &scidd);
	}
}
void uncertainty_channel_cannot_send(struct uncertainty *uncertainty,
				     struct short_channel_id scid,
				     int direction)
{
	struct short_channel_id_dir scidd = {scid, direction};
	// FIXME: check error
	chan_extra_cannot_send(uncertainty->chan_extra_map, &scidd);
}

void uncertainty_update(struct uncertainty *uncertainty,
			struct gossmap *gossmap)
{
	// FIXME: after running for some time we might find some channels in
	// chan_extra_map that are not needed and do not exist in the gossmap
	// for being private or closed.

	/* For each channel in the gossmap, create a extra data in
	 * chan_extra_map */
	for (struct gossmap_chan *chan = gossmap_first_chan(gossmap); chan;
	     chan = gossmap_next_chan(gossmap, chan)) {
		struct short_channel_id scid = gossmap_chan_scid(gossmap, chan);
		struct chan_extra *ce =
		    chan_extra_map_get(uncertainty->chan_extra_map,
				       gossmap_chan_scid(gossmap, chan));
		if (!ce) {
			struct amount_sat cap;
			struct amount_msat cap_msat;

			// FIXME: check errors
			if (!gossmap_chan_get_capacity(gossmap, chan, &cap) ||
			    !amount_sat_to_msat(&cap_msat, cap) ||
			    !new_chan_extra(uncertainty->chan_extra_map, scid,
					    cap_msat))
				return;
		}
	}
}

struct uncertainty *uncertainty_new(const tal_t *ctx)
{
	struct uncertainty *uncertainty = tal(ctx, struct uncertainty);
	if (uncertainty == NULL)
		goto function_fail;

	uncertainty->chan_extra_map = tal(uncertainty, struct chan_extra_map);
	if (uncertainty->chan_extra_map == NULL)
		goto function_fail;

	chan_extra_map_init(uncertainty->chan_extra_map);

	return uncertainty;

function_fail:
	return tal_free(uncertainty);
}

struct chan_extra_map *
uncertainty_get_chan_extra_map(struct uncertainty *uncertainty)
{
	// TODO: do we really need this function?
	return uncertainty->chan_extra_map;
}

/* Add channel to the Uncertainty Network if it doesn't already exist. */
const struct chan_extra *
uncertainty_add_channel(struct uncertainty *uncertainty,
			const struct short_channel_id scid,
			struct amount_msat capacity)
{
	const struct chan_extra *ce =
	    chan_extra_map_get(uncertainty->chan_extra_map, scid);
	if (ce)
		return ce;

	return new_chan_extra(uncertainty->chan_extra_map, scid, capacity);
}

bool uncertainty_set_liquidity(struct uncertainty *uncertainty,
			       const struct short_channel_id_dir *scidd,
			       struct amount_msat amount)
{
	// FIXME check error
	enum renepay_errorcode err = chan_extra_set_liquidity(
	    uncertainty->chan_extra_map, scidd, amount);

	return err == RENEPAY_NOERROR;
}

struct chan_extra *uncertainty_find_channel(struct uncertainty *uncertainty,
					    const struct short_channel_id scid)
{
	return chan_extra_map_get(uncertainty->chan_extra_map, scid);
}
