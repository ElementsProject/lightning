#ifndef LIGHTNING_WIRE_PEER_WIRE_H
#define LIGHTNING_WIRE_PEER_WIRE_H
#include "config.h"
#include <stdbool.h>

#if EXPERIMENTAL_FEATURES
#include <wire/peer_exp_wiregen.h>
#else
#include <wire/peer_wiregen.h>
#endif

/* BOLT #1:
 *
 * A receiving node:
 *   - upon receiving a message of _odd_, unknown type:
 *     - MUST ignore the received message.
 *   - upon receiving a message of _even_, unknown type:
 *     - MUST close the connection.
 *     - MAY fail the channels.
 */

/* Return true if it's an unknown ODD message.  cursor is a tal ptr. */
bool is_unknown_msg_discardable(const u8 *cursor);
/* Return true if it's a message for gossipd. */
bool is_msg_for_gossipd(const u8 *cursor);
/* Return true if it's a gossip update or announcement. */
bool is_msg_gossip_broadcast(const u8 *cursor);

/* Extract channel_id from various packets, return true if possible. */
bool extract_channel_id(const u8 *in_pkt, struct channel_id *channel_id);

/* BOLT #2:
 *
 * Only the least-significant bit of `channel_flags` is currently
 * defined: `announce_channel`.  This indicates whether the initiator
 * of the funding flow wishes to advertise this channel publicly to
 * the network, as detailed within [BOLT #7]
 */
#define CHANNEL_FLAGS_ANNOUNCE_CHANNEL 1
#endif /* LIGHTNING_WIRE_PEER_WIRE_H */
