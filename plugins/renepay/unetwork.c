#include "config.h"
#include <plugins/renepay/unetwork.h>

void unetwork_route_success(struct unetwork *unetwork,
			    const struct route *route)
{
	// TODO
}
void unetwork_remove_htlcs(struct unetwork *unetwork,
			   const struct route *route)
{
	// TODO
}

struct unetwork *unetwork_new(const tal_t *ctx)
{
	struct unetwork *unetwork = tal(ctx, struct unetwork);
	if(unetwork==NULL)
		goto function_fail;

	unetwork -> chan_extra_map = tal(unetwork,struct chan_extra_map);
	if(unetwork->chan_extra_map==NULL)
		goto function_fail;

	chan_extra_map_init(unetwork->chan_extra_map);

	return unetwork;

	function_fail:
	return tal_free(unetwork);
}

void unetwork_update(struct unetwork *unetwork, struct gossmap *gossmap)
{
	// TODO
}

struct chan_extra_map *unetwork_get_chan_extra_map(struct unetwork *unetwork)
{
	// TODO: do we really need this function?
	return unetwork->chan_extra_map;
}

/* Add channel to the Uncertainty Network if it doesn't already exist. */
const struct chan_extra *
unetwork_add_channel(struct unetwork *unetwork,
		     const struct short_channel_id scid,
		     struct amount_msat capacity)
{
	const struct chan_extra *ce =
	    chan_extra_map_get(unetwork->chan_extra_map, scid);
	if (ce)
		return ce;

	return new_chan_extra(unetwork->chan_extra_map, scid, capacity);
}

bool unetwork_set_liquidity(struct unetwork *unetwork,
			    const struct short_channel_id_dir *scidd,
			    struct amount_msat amount)
{
	return chan_extra_set_liquidity(unetwork->chan_extra_map, scidd, amount);
}
