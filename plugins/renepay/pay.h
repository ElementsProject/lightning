#ifndef LIGHTNING_PLUGINS_RENEPAY_PAY_H
#define LIGHTNING_PLUGINS_RENEPAY_PAY_H
#include "config.h"
#include <ccan/list/list.h>
#include <common/node_id.h>
#include <plugins/libplugin.h>
#include <plugins/renepay/flow.h>
#include <plugins/renepay/payment.h>

// TODO(eduardo): renepaystatus should be similar to paystatus

// TODO(eduardo): MCF should consider pending HTLCs occupy some capacity in the
// routing channels.

// TODO(eduardo): check a problem with param_millionths(), if I input an integer
// should or shouldn't be multiplied by 10^6?
// TODO(eduardo): add an option entry for maxfeepercent
// TODO(eduardo): write a man entry for renepay
// TODO(eduardo): check if paynotes are meaningful
// TODO(eduardo): remove assertions, introduce LOG_BROKEN messages

#define MAX_NUM_ATTEMPTS 10

/* Time lapse used to wait for failed sendpays before try_paying. */
#define TIMER_COLLECT_FAILURES_MSEC 250

/* Knowledge is proportionally decreased with time up to TIMER_FORGET_SEC when
 * we forget everything. */
#define TIMER_FORGET_SEC 3600

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
	struct list_head payments;

	/* Per-channel metadata: some persists between payments */
	struct chan_extra_map *chan_extra_map;

	/* Pending senpays. */
	struct payflow_map * payflow_map;

	bool debug_mcf;
	bool debug_payflow;

	/* I'll allocate all global (controlled by pay_plugin) variables tied to
	 * this tal_t. */
	tal_t *ctx;
	// TODO(eduardo): pending flows have HTLCs (in-flight) liquidity
	// attached that is reflected in the uncertainty network. When
	// waitsendpay returns either fail or success that flow is destroyed and
	// the liquidity is restored. A payment command could end before all
	// flows are destroyed, therefore it is important to delegate the
	// ownership of the waitsendpay request to pay_plugin->ctx so that the
	// request is kept alive. One more thing: to double check that flows are
	// not accumulating ad-infinitum I would insert them into a data
	// structure here so that once in a while a timer kicks and verifies the
	// list of pending flows.
	// TODO(eduardo): notice that pending attempts performed with another
	// pay plugin are not considered by the uncertainty network in renepay,
	// it would be nice if listsendpay would give us the route of pending
	// sendpays.
	/* Timers. */
	struct plugin_timer *rexmit_timer;

	/* It allows us to measure elapsed time
	 * and forget channel information accordingly. */
	u64 last_time;
};

/* Set in init */
extern struct pay_plugin * const pay_plugin;

/* Accumulate or panic on overflow */
#define amount_msat_accumulate(dst, src) \
	amount_msat_accumulate_((dst), (src), stringify(dst), stringify(src))
#define amount_msat_reduce(dst, src) \
	amount_msat_reduce_((dst), (src), stringify(dst), stringify(src))

void amount_msat_accumulate_(struct amount_msat *dst,
			     struct amount_msat src,
			     const char *dstname,
			     const char *srcname);
void amount_msat_reduce_(struct amount_msat *dst,
			 struct amount_msat src,
			 const char *dstname,
			 const char *srcname);

#endif /* LIGHTNING_PLUGINS_RENEPAY_PAY_H */
