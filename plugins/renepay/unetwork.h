#ifndef LIGHTNING_PLUGINS_RENEPAY_UNETWORK_H
#define LIGHTNING_PLUGINS_RENEPAY_UNETWORK_H
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

struct unetwork {
	struct chan_extra_map *chan_extra_map;
};

void unetwork_route_success(struct unetwork *unetwork,
			    const struct route *route);
void unetwork_remove_htlcs(struct unetwork *unetwork,
			   const struct route *route);

void unetwork_commit_htlcs(struct unetwork *unetwork,
			   const struct route *route);

void unetwork_update(struct unetwork *unetwork, struct gossmap *gossmap);

struct unetwork *unetwork_new(const tal_t *ctx);

struct chan_extra_map *unetwork_get_chan_extra_map(struct unetwork *unetwork);

const struct chan_extra *
unetwork_add_channel(struct unetwork *unetwork,
		     const struct short_channel_id scid,
		     struct amount_msat capacity);

bool unetwork_set_liquidity(struct unetwork *unetwork,
			    const struct short_channel_id_dir *scidd,
			    struct amount_msat amount);

const struct chan_extra *
unetwork_find_channel(struct unetwork *unetwork,
		      const struct short_channel_id scid);

#endif /* LIGHTNING_PLUGINS_RENEPAY_UNETWORK_H */
