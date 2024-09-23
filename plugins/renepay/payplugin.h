#ifndef LIGHTNING_PLUGINS_RENEPAY_PAYPLUGIN_H
#define LIGHTNING_PLUGINS_RENEPAY_PAYPLUGIN_H
#include "config.h"
#include <ccan/list/list.h>
#include <common/node_id.h>
#include <plugins/libplugin.h>
#include <plugins/renepay/payment.h>
#include <plugins/renepay/renepayconfig.h>

// TODO(eduardo): renepaystatus should be similar to paystatus

// TODO(eduardo): MCF should consider pending HTLCs occupy some capacity in the
// routing channels.

// TODO(eduardo): check a problem with param_millionths(), if I input an integer
// should or shouldn't be multiplied by 10^6?
// TODO(eduardo): add an option entry for maxfeepercent
// TODO(eduardo): write a man entry for renepay
// TODO(eduardo): check if paynotes are meaningful
// TODO(eduardo): remove assertions, introduce LOG_BROKEN messages

// TODO(eduardo): Test ideas
// - make a payment to a node that is hidden behind private channels, check that
// private channels are removed from the gossmap and chan_extra_map
// - one payment route hangs, and the rest keep waiting, eventually all MPP
// should timeout and we retry excluding the unresponsive path (are we able to
// identify it?)
// - a particular route fails because fees are wrong, we update the gossip
// information and redo the path.
// - a MPP in which several parts have a common intermediary node
// 	source -MANY- o -MANY- dest
// - a MPP in which several parts have a common intermediary channel
// 	source -MANY- o--o -MANY- dest
// - a payment with a direct channel to the destination
// - payment failures:
// 	- destination is not in the gossmap
// 	- destination is offline
// 	- with current knowledge there is no flow solution to destination

/* Our convenient global data, here in one place. */
struct pay_plugin {
	/* From libplugin */
	struct plugin *plugin;

	/* Public key of this node. */
	struct node_id my_id;

	/* Map of gossip. */
	struct gossmap *gossmap;

	/* Settings for maxdelay */
	unsigned int maxdelay_default;

	/* Offers support */
	bool exp_offers;

	/* All the struct payment */
	struct payment_map *payment_map;

	/* Pending sendpays. Each pending route has an associated HTLC data in
	 * the uncertainty network. Pending routes are matched against sendpay
	 * notifications. */
	struct route_map *pending_routes;

	bool debug_mcf;
	bool debug_payflow;

	/* Pending flows have HTLCs (in-flight) liquidity
	 * attached that is reflected in the uncertainty network.
	 * When sendpay_fail or sendpay_success notifications arrive
	 * that flow is destroyed and the liquidity is restored.
	 * A payment command could end before all
	 * flows are destroyed, therefore it is important to delegate the
	 * ownership of the flows to pay_plugin->ctx so that the
	 * flows are kept alive.
	 *
	 * TODO(eduardo): maybe we should add a check to ensure that pending
	 * flows are not accumulating ad-infinitum. */

	/* It allows us to measure elapsed time
	 * and forget channel information accordingly. */
	u64 last_time;
};

/* Set in init */
extern struct pay_plugin *pay_plugin;

#endif /* LIGHTNING_PLUGINS_RENEPAY_PAYPLUGIN_H */
