#ifndef LIGHTNING_COMMON_READ_PEER_MSG_H
#define LIGHTNING_COMMON_READ_PEER_MSG_H
#include "config.h"
#include <ccan/short_types/short_types.h>
#include <ccan/tal/tal.h>

struct crypto_state;
struct channel_id;
struct per_peer_state;

/**
 * is_peer_error - if it's an error, describe if it applies to this channel.
 * @ctx: context to allocate return from.
 * @msg: the peer message.
 * @channel_id: the channel id of the current channel.
 * @desc: set to non-NULL if this describes a channel we care about.
 * @warning: set to true if this is a warning, not an error.
 *
 * If @desc is NULL, ignore this message.  Otherwise, that's usually passed
 * to peer_failed_received_errmsg().
 */
bool is_peer_error(const tal_t *ctx, const u8 *msg,
		   const struct channel_id *channel_id,
		   char **desc, bool *warning);

/**
 * is_wrong_channel - if it's a message about a different channel, return true
 * @msg: the peer message.
 * @channel_id: the channel id of the current channel.
 * @actual: set to the actual channel id if this returns false.
 *
 * Note that this only handles some message types, returning false for others.
 */
bool is_wrong_channel(const u8 *msg, const struct channel_id *expected,
		      struct channel_id *actual);


/**
 * handle_peer_error - simple handler for errors
 * @pps: per-peer state.
 * @channel_id: the channel id of the current channel.
 * @msg: the peer message (only taken if returns true).
 *
 * This returns true if it handled the packet.
 */
bool handle_peer_error(struct per_peer_state *pps,
		       const struct channel_id *channel_id,
		       const u8 *msg TAKES);

#endif /* LIGHTNING_COMMON_READ_PEER_MSG_H */
