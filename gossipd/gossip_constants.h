#ifndef LIGHTNING_GOSSIPD_GOSSIP_CONSTANTS_H
#define LIGHTNING_GOSSIPD_GOSSIP_CONSTANTS_H

/* BOLT #4:
 *
 * - Length: the maximum route length is limited to 20 hops.
 *...
 * 1. type: `onion_packet`
 * 2. data:
 *    * [`1`:`version`]
 *    * [`33`:`public_key`]
 *    * [`20*65`:`hops_data`]
 */
#define ROUTING_MAX_HOPS 20

/* BOLT #7:
 *
 * The `flags` bitfield...individual bits:
 *...
 * | 0             | `direction` | Direction this update refers to. |
 * | 1             | `disable`   | Disable the channel.             |
 */
#define ROUTING_FLAGS_DIRECTION (1 << 0)
#define ROUTING_FLAGS_DISABLED  (1 << 1)

/* BOLT #7:
 *
 * - MUST NOT send `announcement_signatures` messages until `funding_locked`
 *   has been sent AND the funding transaction has at least six confirmations.
 */
#define ANNOUNCE_MIN_DEPTH 6

#endif /* LIGHTNING_GOSSIPD_GOSSIP_CONSTANTS_H */
