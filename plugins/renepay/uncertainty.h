#ifndef LIGHTNING_PLUGINS_RENEPAY_UNCERTAINTY_H
#define LIGHTNING_PLUGINS_RENEPAY_UNCERTAINTY_H
#include "config.h"
#include <ccan/tal/tal.h>
#include <common/gossmap.h>
#include <plugins/renepay/chan_extra.h>
#include <plugins/renepay/route.h>

/* FIXME a hard coded constant to indicate a limit on any channel
 capacity. Channels for which the capacity is unknown (because they are not
 announced) use this value. It makes sense, because if we don't even know the
 channel capacity the liquidity could be anything but it will never be greater
 than the global number of msats.
 It remains to be checked if this value does not lead to overflow somewhere in
 the code. */
#define MAX_CAPACITY (AMOUNT_MSAT(21000000 * MSAT_PER_BTC))

struct uncertainty {
	struct chan_extra_map *chan_extra_map;
};

/* FIXME: add bool return value and WARN_UNUSED_RESULT */
void uncertainty_route_success(struct uncertainty *uncertainty,
			       const struct route *route);
void uncertainty_remove_htlcs(struct uncertainty *uncertainty,
			      const struct route *route);

void uncertainty_commit_htlcs(struct uncertainty *uncertainty,
			      const struct route *route);

void uncertainty_channel_can_send(struct uncertainty *uncertainty,
				  const struct route *route, u32 erridx);

void uncertainty_channel_cannot_send(struct uncertainty *uncertainty,
				     struct short_channel_id scid,
				     int direction);

void uncertainty_update(struct uncertainty *uncertainty,
			struct gossmap *gossmap);

struct uncertainty *uncertainty_new(const tal_t *ctx);

struct chan_extra_map *
uncertainty_get_chan_extra_map(struct uncertainty *uncertainty);

const struct chan_extra *
uncertainty_add_channel(struct uncertainty *uncertainty,
			const struct short_channel_id scid,
			struct amount_msat capacity);

bool uncertainty_set_liquidity(struct uncertainty *uncertainty,
			       const struct short_channel_id_dir *scidd,
			       struct amount_msat amount);

struct chan_extra *uncertainty_find_channel(struct uncertainty *uncertainty,
					    const struct short_channel_id scid);

#endif /* LIGHTNING_PLUGINS_RENEPAY_UNCERTAINTY_H */
