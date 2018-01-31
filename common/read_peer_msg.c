#include <ccan/structeq/structeq.h>
#include <common/crypto_sync.h>
#include <common/ping.h>
#include <common/read_peer_msg.h>
#include <common/status.h>
#include <common/type_to_string.h>
#include <common/utils.h>
#include <common/wire_error.h>
#include <errno.h>
#include <wire/peer_wire.h>
#include <wire/wire_sync.h>

static void handle_ping(const u8 *msg,
			int peer_fd,
			struct crypto_state *cs,
			const struct channel_id *channel,
			bool (*send_reply)(struct crypto_state *, int,
					   const u8 *, void *),
			void (*io_error)(const char *, void *),
			void *arg)
{
	u8 *pong;

	if (!check_ping_make_pong(msg, msg, &pong)) {
		send_reply(cs, peer_fd,
			   take(towire_errorfmt(msg, channel,
						"Bad ping %s",
						tal_hex(msg, msg))), arg);
		io_error("Bad ping received", arg);
	}

	status_trace("Got ping, sending %s", pong ?
		     wire_type_name(fromwire_peektype(pong))
		     : "nothing");

	if (pong && !send_reply(cs, peer_fd, pong, arg))
		io_error("Failed writing pong", arg);
}

u8 *read_peer_msg_(const tal_t *ctx,
		   int peer_fd, int gossip_fd,
		   struct crypto_state *cs,
		   const struct channel_id *channel,
		   bool (*send_reply)(struct crypto_state *, int, const u8 *,
				      void *),
		   void (*io_error)(const char *what_i_was_doing, void *arg),
		   void (*err_pkt)(const char *desc, bool this_channel_only,
				   void *arg),
		   void *arg)
{
	u8 *msg;
	struct channel_id chanid;

	msg = sync_crypto_read(ctx, cs, peer_fd);
	if (!msg)
		io_error("reading from peer", arg);

	status_trace("peer_in %s", wire_type_name(fromwire_peektype(msg)));

	if (is_gossip_msg(msg)) {
		/* Forward to gossip daemon */
		wire_sync_write(gossip_fd, take(msg));
		return NULL;
	}

	if (fromwire_peektype(msg) == WIRE_PING) {
		handle_ping(msg, peer_fd, cs, channel,
			    send_reply, io_error, arg);
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
		 *       message.
		 *  - if no existing channel is referred to by the
		 *    message:
		 *    - MUST ignore the message.
		 */
		if (channel_id_is_all(&chanid))
			err_pkt(err, false, arg);
		else if (structeq(&chanid, channel))
			err_pkt(err, true, arg);

		return tal_free(msg);
	}

	/* They're talking about a different channel? */
	if (extract_channel_id(msg, &chanid)
	    && !structeq(&chanid, channel)) {
		status_trace("Rejecting %s for unknown channel_id %s",
			     wire_type_name(fromwire_peektype(msg)),
			     type_to_string(msg, struct channel_id, &chanid));
		if (!send_reply(cs, peer_fd,
				take(towire_errorfmt(msg, &chanid,
						     "Multiple channels"
						     " unsupported")),
				arg))
			io_error("Sending error for other channel ", arg);
		return tal_free(msg);
	}

	return msg;
}

/* Helper: sync_crypto_write, with extra args it ignores */
bool sync_crypto_write_arg(struct crypto_state *cs, int fd, const u8 *msg,
			   void *unused)
{
	return sync_crypto_write(cs, fd, msg);
}

/* Helper: calls status_failed(STATUS_FAIL_PEER_IO) */
void status_fail_io(const char *what_i_was_doing, void *unused)
{
	status_failed(STATUS_FAIL_PEER_IO,
		      "%s:%s", what_i_was_doing, strerror(errno));
}

/* Helper: calls status_failed(STATUS_FAIL_PEER_BAD, <error>) */
void status_fail_errpkt(const char *desc, bool this_channel_only, void *unused)
{
	status_failed(STATUS_FAIL_PEER_BAD, "Peer sent ERROR: %s", desc);
}
