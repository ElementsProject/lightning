#include <common/crypto_sync.h>
#include <common/peer_failed.h>
#include <common/ping.h>
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

static void handle_ping(const u8 *msg,
			int peer_fd,
			struct crypto_state *cs,
			const struct channel_id *channel,
			bool (*send_reply)(struct crypto_state *, int,
					   const u8 *, void *),
			void *arg)
{
	u8 *pong;

	if (!check_ping_make_pong(msg, msg, &pong)) {
		send_reply(cs, peer_fd,
			   take(towire_errorfmt(NULL, channel,
						"Bad ping %s",
						tal_hex(msg, msg))), arg);
		peer_failed_connection_lost();
	}

	status_debug("Got ping, sending %s", pong ?
		     wire_type_name(fromwire_peektype(pong))
		     : "nothing");

	if (pong && !send_reply(cs, peer_fd, pong, arg))
		peer_failed_connection_lost();
}

void handle_gossip_msg_(const u8 *msg TAKES, int peer_fd,
			struct crypto_state *cs,
			bool (*send_msg)(struct crypto_state *cs, int fd,
					 const u8 *TAKES, void *arg),
			void *arg)
{
	u8 *gossip;

	if (!fromwire_gossip_send_gossip(tmpctx, msg, &gossip)) {
		status_broken("Got bad message from gossipd: %s",
			      tal_hex(msg, msg));
		peer_failed_connection_lost();
	}

	/* Gossipd can send us gossip messages, OR errors */
	if (is_msg_for_gossipd(gossip)) {
		if (!send_msg(cs, peer_fd, gossip, arg))
			peer_failed_connection_lost();
	} else if (fromwire_peektype(gossip) == WIRE_ERROR) {
		status_debug("Gossipd told us to send error");
		send_msg(cs, peer_fd, gossip, arg);
		peer_failed_connection_lost();
	} else {
		status_broken("Gossipd gave us bad send_gossip message %s",
			      tal_hex(msg, msg));
		peer_failed_connection_lost();
	}
	if (taken(msg))
		tal_free(msg);
}

u8 *read_peer_msg_(const tal_t *ctx,
		   int peer_fd, int gossip_fd,
		   struct crypto_state *cs,
		   const struct channel_id *channel,
		   bool (*send_reply)(struct crypto_state *cs, int fd,
				      const u8 *TAKES,  void *arg),
		   void *arg)
{
	u8 *msg;
	struct channel_id chanid;
	fd_set readfds;

	FD_ZERO(&readfds);
	FD_SET(peer_fd, &readfds);
	FD_SET(gossip_fd, &readfds);

	select(peer_fd > gossip_fd ? peer_fd + 1 : gossip_fd + 1,
	       &readfds, NULL, NULL, NULL);

	if (FD_ISSET(gossip_fd, &readfds)) {
		/* gossipd uses this to kill us, so not a surprise if it
		   happens. */
		msg = wire_sync_read(NULL, gossip_fd);
		if (!msg) {
			status_debug("Error reading gossip msg");
			peer_failed_connection_lost();
		}

		handle_gossip_msg_(msg, peer_fd, cs, send_reply, arg);
		return NULL;
	}

	msg = sync_crypto_read(ctx, cs, peer_fd);
	if (!msg)
		peer_failed_connection_lost();

	if (is_msg_for_gossipd(msg)) {
		/* Forward to gossip daemon */
		wire_sync_write(gossip_fd, take(msg));
		return NULL;
	}

	if (fromwire_peektype(msg) == WIRE_PING) {
		handle_ping(msg, peer_fd, cs, channel, send_reply, arg);
		return tal_free(msg);
	}

	if (fromwire_peektype(msg) == WIRE_ERROR) {
		char *err = sanitize_error(msg, msg, &chanid);

		/* BOLT #1:
		 *
		 * The channel is referred to by `channel_id`, unless
		 * `channel_id` is 0 (i.e. all bytes are 0), in which
		 * case it refers to all channels.
		 * ...

		 * The receiving node:
		 *   - upon receiving `error`:
		 *    - MUST fail the channel referred to by the error
		 *       message, if that channel is with the sending node.
		 *  - if no existing channel is referred to by the
		 *    message:
		 *    - MUST ignore the message.
		 */
		if (channel_id_eq(&chanid, channel)
		    || channel_id_is_all(&chanid)) {
			peer_failed_received_errmsg(peer_fd, gossip_fd,
						    cs, err, &chanid);
		}

		return tal_free(msg);
	}

	/* They're talking about a different channel? */
	if (extract_channel_id(msg, &chanid)
	    && !channel_id_eq(&chanid, channel)) {
		status_trace("Rejecting %s for unknown channel_id %s",
			     wire_type_name(fromwire_peektype(msg)),
			     type_to_string(tmpctx, struct channel_id, &chanid));
		if (!send_reply(cs, peer_fd,
				take(towire_errorfmt(NULL, &chanid,
						     "Multiple channels"
						     " unsupported")),
				arg))
			peer_failed_connection_lost();
		return tal_free(msg);
	}

	return msg;
}

/* Helper: sync_crypto_write, with extra args it ignores */
bool sync_crypto_write_arg(struct crypto_state *cs, int fd, const u8 *msg,
			   void *unused UNUSED)
{
	return sync_crypto_write(cs, fd, msg);
}
