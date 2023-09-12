#ifndef LIGHTNING_COMMON_READ_PEER_MSG_H
#define LIGHTNING_COMMON_READ_PEER_MSG_H
#include "config.h"
#include <ccan/short_types/short_types.h>
#include <ccan/tal/tal.h>

struct crypto_state;
struct channel_id;
struct per_peer_state;

/**
 * is_peer_error - if it's an error, describe it.
 * @ctx: context to allocate return from.
 * @msg: the peer message.
 *
 * If this returns non-NULL, it's usually passed to
 * peer_failed_received_errmsg().
 */
const char *is_peer_error(const tal_t *ctx, const u8 *msg);

/**
 * is_peer_warning - if it's a warning, describe it.
 * @ctx: context to allocate return from.
 * @msg: the peer message.
 *
 * If this returns non-NULL, it's usually logged.
 */
const char *is_peer_warning(const tal_t *ctx, const u8 *msg);

/**
 * handle_peer_error_or_warning - simple handler for errors / warnings
 * @pps: per-peer state.
 * @channel_id: the channel id of the current channel.
 * @msg: the peer message (only taken if returns true).
 *
 * This returns true if it handled the packet (i.e. logs a warning).
 * Doesn't return if it's an error.
 */
bool handle_peer_error_or_warning(struct per_peer_state *pps,
				  const u8 *msg TAKES);

#endif /* LIGHTNING_COMMON_READ_PEER_MSG_H */
