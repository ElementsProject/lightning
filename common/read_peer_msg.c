#include <common/crypto_sync.h>
#include <common/peer_failed.h>
#include <common/read_peer_msg.h>
#include <common/status.h>
#include <common/type_to_string.h>
#include <common/utils.h>
#include <common/wire_error.h>
#include <errno.h>
#include <gossipd/gen_gossip_wire.h>
#include <sys/select.h>
#include <wire/peer_wire.h>
#include <wire/wire_sync.h>

u8 *peer_or_gossip_sync_read(const tal_t *ctx,
			     int peer_fd, int gossip_fd,
			     struct crypto_state *cs,
			     bool *from_gossipd)
{
	fd_set readfds;
	u8 *msg;

	FD_ZERO(&readfds);
	FD_SET(peer_fd, &readfds);
	FD_SET(gossip_fd, &readfds);

	select(peer_fd > gossip_fd ? peer_fd + 1 : gossip_fd + 1,
	       &readfds, NULL, NULL, NULL);

	if (FD_ISSET(gossip_fd, &readfds)) {
		msg = wire_sync_read(ctx, gossip_fd);
		if (!msg)
			status_failed(STATUS_FAIL_GOSSIP_IO,
				      "Error reading gossip msg: %s",
				      strerror(errno));
		*from_gossipd = true;
		return msg;
	}

	msg = sync_crypto_read(ctx, cs, peer_fd);
	*from_gossipd = false;
	return msg;
}

bool is_peer_error(const tal_t *ctx, const u8 *msg,
		   const struct channel_id *channel_id,
		   char **desc, bool *all_channels)
{
	struct channel_id err_chanid;

	if (fromwire_peektype(msg) != WIRE_ERROR)
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
	*all_channels = channel_id_is_all(&err_chanid);
	if (!*all_channels && !channel_id_eq(&err_chanid, channel_id))
		*desc = tal_free(*desc);

	return true;
}

bool is_wrong_channel(const u8 *msg, const struct channel_id *expected,
		      struct channel_id *actual)
{
	if (!extract_channel_id(msg, actual))
		return false;

	return !channel_id_eq(expected, actual);
}

void handle_gossip_msg(int peer_fd, struct crypto_state *cs, const u8 *msg TAKES)
{
	u8 *gossip;

	if (!fromwire_gossip_send_gossip(tmpctx, msg, &gossip)) {
		status_broken("Got bad message from gossipd: %s",
			      tal_hex(msg, msg));
		peer_failed_connection_lost();
	}

	/* Gossipd can send us gossip messages, OR errors */
	if (is_msg_for_gossipd(gossip)) {
		sync_crypto_write(cs, peer_fd, gossip);
	} else if (fromwire_peektype(gossip) == WIRE_ERROR) {
		status_debug("Gossipd told us to send error");
		sync_crypto_write(cs, peer_fd, gossip);
		peer_failed_connection_lost();
	} else {
		status_broken("Gossipd gave us bad send_gossip message %s",
			      tal_hex(msg, msg));
		peer_failed_connection_lost();
	}
	if (taken(msg))
		tal_free(msg);
}

bool handle_peer_gossip_or_error(int peer_fd, int gossip_fd,
				 struct crypto_state *cs,
				 const struct channel_id *channel_id,
				 const u8 *msg TAKES)
{
	char *err;
	bool all_channels;
	struct channel_id actual;

	if (is_msg_for_gossipd(msg)) {
		wire_sync_write(gossip_fd, msg);
		/* wire_sync_write takes, so don't take again. */
		return true;
	}

	if (is_peer_error(tmpctx, msg, channel_id, &err, &all_channels)) {
		if (err)
			peer_failed_received_errmsg(peer_fd, gossip_fd,
						    cs, err,
						    all_channels
						    ? NULL : channel_id);

		/* Ignore unknown channel errors. */
		goto handled;
	}

	/* They're talking about a different channel? */
	if (is_wrong_channel(msg, channel_id, &actual)) {
		status_trace("Rejecting %s for unknown channel_id %s",
			     wire_type_name(fromwire_peektype(msg)),
			     type_to_string(tmpctx, struct channel_id, &actual));
		sync_crypto_write(cs, peer_fd,
				  take(towire_errorfmt(NULL, &actual,
						       "Multiple channels"
						       " unsupported")));
		goto handled;
	}

	return false;

handled:
	if (taken(msg))
		tal_free(msg);
	return true;
}
