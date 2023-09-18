#ifndef LIGHTNING_PLUGINS_RENEPAY_UNCERTAINTY_NETWORK_H
#define LIGHTNING_PLUGINS_RENEPAY_UNCERTAINTY_NETWORK_H
#include "config.h"
#include <common/gossmap.h>
#include <plugins/renepay/flow.h>
#include <plugins/renepay/pay_flow.h>
#include <plugins/renepay/payment.h>

struct pay_flow;
struct route_info;

/* Checks the entire uncertainty network for invariant violations. */
bool uncertainty_network_check_invariants(struct chan_extra_map *chan_extra_map);

/* Add routehints provided by bolt11 */
void uncertainty_network_add_routehints(
		struct chan_extra_map *chan_extra_map,
		const struct route_info **routes,
		struct payment *p);

/* Mirror the gossmap in the public uncertainty network.
 * result: Every channel in gossmap must have associated data in chan_extra_map,
 * while every channel in chan_extra_map is also registered in gossmap.
 * */
void uncertainty_network_update(
		const struct gossmap *gossmap,
		struct chan_extra_map *chan_extra_map);

void uncertainty_network_flow_success(
		struct chan_extra_map *chan_extra_map,
		struct pay_flow *flow);

/* All parts up to erridx succeeded, so we know something about min
 * capacity! */
void uncertainty_network_channel_can_send(
		struct chan_extra_map * chan_extra_map,
		struct pay_flow *flow,
		u32 erridx);

/* listpeerchannels gives us the certainty on local channels' capacity.  Of course,
 * this is racy and transient, but better than nothing! */
bool uncertainty_network_update_from_listpeerchannels(
		struct chan_extra_map * chan_extra_map,
		struct node_id my_id,
		struct payment *payment,
		const char *buf,
		const jsmntok_t *toks);

/* Forget ALL channels information by a fraction of the capacity. */
void uncertainty_network_relax_fraction(
		struct chan_extra_map* chan_extra_map,
		double fraction);

#endif /* LIGHTNING_PLUGINS_RENEPAY_UNCERTAINTY_NETWORK_H */
