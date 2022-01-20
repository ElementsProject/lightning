#ifndef LIGHTNING_COMMON_READ_PEER_MSG_H
#define LIGHTNING_COMMON_READ_PEER_MSG_H
#include "config.h"
#include <ccan/short_types/short_types.h>
#include <ccan/tal/tal.h>

struct crypto_state;
struct channel_id;
struct per_peer_state;

/**
 * peer_or_gossip_sync_read - read a peer message, or maybe a gossip msg.
 * @ctx: context to allocate return packet from.
 * @pps: the per-peer peer state and fds
 * @from_gossipd: true if the msg was from gossipd, otherwise false.
 *
 * Will call peer_failed_connection_lost() or
 * status_failed(STATUS_FAIL_GOSSIP_IO) or return a message.
 *
 * Usually, you should call handle_gossip_msg if *@from_gossipd is
 * true, otherwise if is_peer_error() handle the error, otherwise if
 * is_msg_for_gossipd() then send to gossipd, otherwise if is
 * is_wrong_channel() send that as a reply.  Otherwise it should be
 * a valid message.
 */
u8 *peer_or_gossip_sync_read(const tal_t *ctx,
			     struct per_peer_state *pps,
			     bool *from_gossipd);

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
 * handle_peer_gossip_or_error - simple handler for all the above cases.
 * @pps: per-peer state.
 * @channel_id: the channel id of the current channel.
 * @msg: the peer message (only taken if returns true).
 *
 * This returns true if it handled the packet: a gossip packet (forwarded
 * to gossipd), or an error packet (causes peer_failed_received_errmsg or
 * ignored), or a ping (may reply with pong).
 */
bool handle_peer_gossip_or_error(struct per_peer_state *pps,
				 const struct channel_id *channel_id,
				 const u8 *msg TAKES);

/**
 * handle_timestamp_filter - deal with timestamp filter requests.
 * @pps: per-peer state.
 * @msg: the peer message (only taken if returns true).
 */
bool handle_timestamp_filter(struct per_peer_state *pps, const u8 *msg TAKES);

/* We got this message from gossipd: forward/quit as it asks. */
void handle_gossip_msg(struct per_peer_state *pps, const u8 *msg TAKES);
#endif /* LIGHTNING_COMMON_READ_PEER_MSG_H */
