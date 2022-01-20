#include "config.h"
#include <assert.h>
#include <bitcoin/chainparams.h>
#include <common/peer_failed.h>
#include <common/peer_io.h>
#include <common/per_peer_state.h>
#include <common/ping.h>
#include <common/read_peer_msg.h>
#include <common/status.h>
#include <common/wire_error.h>
#include <errno.h>
#include <wire/peer_wire.h>
#include <wire/wire_sync.h>

u8 *peer_or_gossip_sync_read(const tal_t *ctx,
			     struct per_peer_state *pps,
			     bool *from_gossipd)
{
	fd_set readfds;
	u8 *msg;

	FD_ZERO(&readfds);
	FD_SET(pps->peer_fd, &readfds);
	FD_SET(pps->gossip_fd, &readfds);

	if (select(pps->peer_fd > pps->gossip_fd
		   ? pps->peer_fd + 1 : pps->gossip_fd + 1,
		   &readfds, NULL, NULL, NULL) <= 0) {
		status_failed(STATUS_FAIL_GOSSIP_IO,
			      "select failed?: %s", strerror(errno));
	}

	if (FD_ISSET(pps->peer_fd, &readfds)) {
		msg = peer_read(ctx, pps);
		*from_gossipd = false;
		return msg;
	}

	msg = wire_sync_read(ctx, pps->gossip_fd);
	if (!msg)
		status_failed(STATUS_FAIL_GOSSIP_IO,
			      "Error reading gossip msg: %s",
			      strerror(errno));
	*from_gossipd = true;
	return msg;
}

bool is_peer_error(const tal_t *ctx, const u8 *msg,
		   const struct channel_id *channel_id,
		   char **desc, bool *warning)
{
	struct channel_id err_chanid;

	if (fromwire_peektype(msg) == WIRE_ERROR)
		*warning = false;
	else if (fromwire_peektype(msg) == WIRE_WARNING)
		*warning = true;
	else
		return false;

	*desc = sanitize_error(ctx, msg, &err_chanid);

	/* BOLT #1:
	 *
	 * The channel is referred to by `channel_id`, unless `channel_id` is
	 * 0 (i.e. all bytes are 0), in which case it refers to all channels.
	 * ...
	 * The receiving node:
	 *   - upon receiving `error`:
	 *    - MUST fail the channel referred to by the error message, if that
	 *      channel is with the sending node.
	 *  - if no existing channel is referred to by the message:
	 *    - MUST ignore the message.
	 */
	/* FIXME: The spec changed, so for *errors* all 0 is not special.
	 * But old gossipd would send these, so we turn them into warnings */
	if (channel_id_is_all(&err_chanid))
		*warning = true;
	else if (!channel_id_eq(&err_chanid, channel_id))
		*desc = tal_free(*desc);

	return true;
}

bool is_wrong_channel(const u8 *msg, const struct channel_id *expected,
		      struct channel_id *actual)
{
	if (!expected)
		return false;

	if (!extract_channel_id(msg, actual))
		return false;

	return !channel_id_eq(expected, actual);
}

void handle_gossip_msg(struct per_peer_state *pps, const u8 *msg TAKES)
{
	u8 *gossip;

	/* It's a raw gossip msg: this copies or takes() */
	gossip = tal_dup_talarr(tmpctx, u8, msg);

	/* Gossipd can send us gossip messages, OR warnings */
	if (fromwire_peektype(gossip) == WIRE_WARNING) {
		peer_write(pps, gossip);
		peer_failed_connection_lost();
	} else {
		peer_write(pps, gossip);
	}
}

bool handle_peer_gossip_or_error(struct per_peer_state *pps,
				 const struct channel_id *channel_id,
				 const u8 *msg TAKES)
{
	char *err;
	bool warning;
	u8 *pong;

#if DEVELOPER
	/* Any odd-typed unknown message is handled by the caller, so if we
	 * find one here it's an error. */
	assert(!is_unknown_msg_discardable(msg));
#else
	/* BOLT #1:
	 *
	 * A receiving node:
	 *   - upon receiving a message of _odd_, unknown type:
	 *     - MUST ignore the received message.
	 */
	if (is_unknown_msg_discardable(msg))
		goto handled;
#endif

	if (check_ping_make_pong(NULL, msg, &pong)) {
		if (pong)
			peer_write(pps, take(pong));
		return true;
	} else if (is_msg_for_gossipd(msg)) {
		wire_sync_write(pps->gossip_fd, msg);
		/* wire_sync_write takes, so don't take again. */
		return true;
	}

	if (is_peer_error(tmpctx, msg, channel_id, &err, &warning)) {
		/* Ignore unknown channel errors. */
		if (!err)
			goto handled;

		/* We hang up when a warning is received. */
		peer_failed_received_errmsg(pps, err, channel_id, warning);

		goto handled;
	}

	return false;

handled:
	if (taken(msg))
		tal_free(msg);
	return true;
}
