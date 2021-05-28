#ifndef LIGHTNING_COMMON_GOSSIP_CONSTANTS_H
#define LIGHTNING_COMMON_GOSSIP_CONSTANTS_H
#include "config.h"
#include <common/utils.h>

/* BOLT #4:
 *
 * - a 1300-byte `hop_payloads` consisting of multiple, variable length,
 *   `hop_payload` payloads or up to 20 fixed sized legacy `hop_data` payloads.
 */
#define ROUTING_MAX_HOPS 20

/* BOLT #7:
 *
 * The `channel_flags` bitfield...individual bits:
 *...
 * | 0             | `direction` | Direction this update refers to. |
 * | 1             | `disable`   | Disable the channel.             |
 */
#define ROUTING_FLAGS_DIRECTION (1 << 0)
#define ROUTING_FLAGS_DISABLED  (1 << 1)

/* BOLT #7:
 *
 * The `message_flags` bitfield is used to indicate the presence of optional
 * fields in the `channel_update` message:
 * | Bit Position  | Name                      | Field                |
 * | ------------- | ------------------------- | ----------------...- |
 * | 0             | `option_channel_htlc_max` | `htlc_maximum_msat`  |
 */
#define ROUTING_OPT_HTLC_MAX_MSAT (1 << 0)

/* BOLT #7:
 *
 * - MUST NOT send `announcement_signatures` messages until `funding_locked`
 *   has been sent and received AND the funding transaction has at least six
 *   confirmations.
 */
#define ANNOUNCE_MIN_DEPTH 6

/* Gossip timing constants.  These can be overridden in --enable-developer
 * configurations with --dev-fast-gossip, otherwise the argument is ignored */
#define DEV_FAST_GOSSIP(dev_fast_gossip_flag, fast, normal)	\
	IFDEV((dev_fast_gossip_flag) ? (fast) : (normal), (normal))

/* How close we can generate gossip msgs (5 minutes) */
#define GOSSIP_MIN_INTERVAL(dev_fast_gossip_flag) \
	DEV_FAST_GOSSIP(dev_fast_gossip_flag, 5, 300)

/* How long to wait at start for the plugin to callback with liquidity ad */
#define GOSSIP_NANN_STARTUP_DELAY(dev_fast_gossip_flag) \
	DEV_FAST_GOSSIP(dev_fast_gossip_flag, 8, 60)

/* BOLT #7:
 *
 * - SHOULD flush outgoing gossip messages once every 60 seconds,
 *   independently of the arrival times of the messages.
 */
#define GOSSIP_FLUSH_INTERVAL(dev_fast_gossip_flag) \
	DEV_FAST_GOSSIP(dev_fast_gossip_flag, 1, 60)

/* BOLT #7:
 *
 * A node:
 *   - if a channel's oldest `channel_update`s `timestamp` is older than two weeks
 *   (1209600 seconds):
 *     - MAY prune the channel.
 *     - MAY ignore the channel.
 */
#define GOSSIP_PRUNE_INTERVAL(dev_fast_gossip_prune_flag) \
	DEV_FAST_GOSSIP(dev_fast_gossip_prune_flag, 60, 1209600)

/* How long after seeing lockin until we announce the channel. */
#define GOSSIP_ANNOUNCE_DELAY(dev_fast_gossip_flag) \
	DEV_FAST_GOSSIP(dev_fast_gossip_flag, 1, 60)

/* How long before deadline should we send refresh update? 1 day normally */
#define GOSSIP_BEFORE_DEADLINE(dev_fast_gossip_prune_flag) \
	DEV_FAST_GOSSIP(dev_fast_gossip_prune_flag, 30, 24*60*60)

/* How many seconds per token?  Normally 1 hour. */
#define GOSSIP_TOKEN_TIME(dev_fast_gossip_flag) \
	DEV_FAST_GOSSIP(dev_fast_gossip_flag, 1, 3600)

/* This is where we keep our gossip */
#define GOSSIP_STORE_FILENAME "gossip_store"

#endif /* LIGHTNING_COMMON_GOSSIP_CONSTANTS_H */
