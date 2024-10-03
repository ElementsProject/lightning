#include "config.h"
#include <plugins/renepay/renepayconfig.h>
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
				  struct short_channel_id scid, int direction)
{
	struct short_channel_id_dir scidd = {scid, direction};
	// FIXME: check error
	chan_extra_can_send(uncertainty->chan_extra_map, &scidd);
}
void uncertainty_channel_cannot_send(struct uncertainty *uncertainty,
				     struct short_channel_id scid,
				     int direction)
{
	struct short_channel_id_dir scidd = {scid, direction};
	// FIXME: check error
	chan_extra_cannot_send(uncertainty->chan_extra_map, &scidd);
}

int uncertainty_update(struct uncertainty *uncertainty, struct gossmap *gossmap)
{
	/* Each channel in chan_extra_map should be either in gossmap or in
	 * local_gossmods. */
	assert(uncertainty);
	struct chan_extra_map *chan_extra_map = uncertainty->chan_extra_map;
	assert(chan_extra_map);
	struct chan_extra **del_list = tal_arr(NULL, struct chan_extra*, 0);
	struct chan_extra_map_iter it;
	for (struct chan_extra *ch = chan_extra_map_first(chan_extra_map, &it);
	     ch; ch = chan_extra_map_next(chan_extra_map, &it)) {

		/* If we cannot find that channel in the gossmap, add it to the
		 * delete list. */
		if (!gossmap_find_chan(gossmap, &ch->scid))
			tal_arr_expand(&del_list, ch);
	}
	for(size_t i=0;i<tal_count(del_list);i++) {
		chan_extra_map_del(chan_extra_map, del_list[i]);
		del_list[i] = tal_free(del_list[i]);
	}
	del_list = tal_free(del_list);


	/* For each channel in the gossmap, create a extra data in
	 * chan_extra_map */
	int skipped_count = 0;
	for (struct gossmap_chan *chan = gossmap_first_chan(gossmap); chan;
	     chan = gossmap_next_chan(gossmap, chan)) {
		struct short_channel_id scid = gossmap_chan_scid(gossmap, chan);
		struct chan_extra *ce =
		    chan_extra_map_get(chan_extra_map, scid);
		if (!ce) {
			struct amount_msat cap_msat;

			cap_msat = gossmap_chan_get_capacity(gossmap, chan);
			if (!new_chan_extra(chan_extra_map, scid,
					    cap_msat)) {
				/* If the new chan_extra cannot be created we
				 * skip this channel. */
				skipped_count++;
				continue;
			}
		}
	}
	assert(chan_extra_map_count(chan_extra_map) + skipped_count ==
	       gossmap_num_chans(gossmap));
	return skipped_count;
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
			       struct amount_msat min,
			       struct amount_msat max)
{
	// FIXME check error
	enum renepay_errorcode err = chan_extra_set_liquidity(
	    uncertainty->chan_extra_map, scidd, min, max);

	return err == RENEPAY_NOERROR;
}

struct chan_extra *uncertainty_find_channel(struct uncertainty *uncertainty,
					    const struct short_channel_id scid)
{
	return chan_extra_map_get(uncertainty->chan_extra_map, scid);
}

enum renepay_errorcode uncertainty_relax(struct uncertainty *uncertainty,
					 double seconds)
{
	assert(seconds >= 0);
	const double fraction = MIN(seconds / TIMER_FORGET_SEC, 1.0);
	struct chan_extra_map *chan_extra_map =
	    uncertainty_get_chan_extra_map(uncertainty);
	struct chan_extra_map_iter it;
	for (struct chan_extra *ce = chan_extra_map_first(chan_extra_map, &it);
	     ce; ce = chan_extra_map_next(chan_extra_map, &it)) {
		enum renepay_errorcode err =
		    chan_extra_relax_fraction(ce, fraction);

		if (err)
			return err;
	}
	return RENEPAY_NOERROR;
}
