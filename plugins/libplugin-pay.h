#ifndef LIGHTNING_PLUGINS_LIBPLUGIN_PAY_H
#define LIGHTNING_PLUGINS_LIBPLUGIN_PAY_H
#include "config.h"

#include <plugins/libplugin.h>

enum route_hop_style {
	ROUTE_HOP_LEGACY = 1,
	ROUTE_HOP_TLV = 2,
};

struct route_hop {
	struct short_channel_id channel_id;
	int direction;
	struct node_id nodeid;
	struct amount_msat amount;
	u32 delay;
	struct pubkey *blinding;
	enum route_hop_style style;
};

/* A parsed version of the possible outcomes that a sendpay / payment may
 * result in. */
struct payment_result {
};

/* Relevant information about a local channel so we can  exclude them early. */
struct channel_status {
};

struct payment {

	/* Real destination we want to route to */
	struct node_id *destination;

	/* Payment hash extracted from the invoice if any. */
	struct sha256 *payment_hash;

	u32 partid;

	/* Destination we should ask `getroute` for. This might differ from
	 * the above destination if we use rendez-vous routing of blinded
	 * paths to amend the route later in a mixin. */
	struct node_id  *getroute_destination;

	/* Target amount to be delivered at the destination */
	struct amount_msat amount;

	/* tal_arr of route_hops we decoded from the `getroute` call. Exposed
	 * here so it can be amended by mixins. */
	struct route_hop *route;

	struct channel_status *peer_channels;

	/* The blockheight at which the payment attempt was
	 * started.  */
	u32 start_block;

	struct timeabs start_time, end_time;
	struct timeabs deadline;

	struct amount_msat extra_budget;

	struct short_channel_id *exclusions;

};

#endif /* LIGHTNING_PLUGINS_LIBPLUGIN_PAY_H */
