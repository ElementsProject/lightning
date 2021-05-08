#include "config.h"
#include <assert.h>
#include <bitcoin/chainparams.h>
#include <ccan/fdpass/fdpass.h>
#include <common/crypto_sync.h>
#include <common/gossip_rcvd_filter.h>
#include <common/gossip_store.h>
#include <common/peer_failed.h>
#include <common/per_peer_state.h>
#include <common/read_peer_msg.h>
#include <common/status.h>
#include <common/type_to_string.h>
#include <common/utils.h>
#include <common/wire_error.h>
#include <errno.h>
#include <gossipd/gossipd_peerd_wiregen.h>
#include <sys/select.h>
#include <unistd.h>
#include <wire/peer_wire.h>
#include <wire/wire_sync.h>

u8 *peer_or_gossip_sync_read(const tal_t *ctx,
			     struct per_peer_state *pps,
			     bool *from_gossipd)
{
	fd_set readfds;
	u8 *msg;

	for (;;) {
		struct timeval tv, *tptr;
		struct timerel trel;

		if (time_to_next_gossip(pps, &trel)) {
			tv = timerel_to_timeval(trel);
			tptr = &tv;
		} else
			tptr = NULL;

		FD_ZERO(&readfds);
		FD_SET(pps->peer_fd, &readfds);
		FD_SET(pps->gossip_fd, &readfds);

		if (select(pps->peer_fd > pps->gossip_fd
			   ? pps->peer_fd + 1 : pps->gossip_fd + 1,
			   &readfds, NULL, NULL, tptr) != 0)
			break;

		/* We timed out; look in gossip_store.  Failure resets timer. */
		msg = gossip_store_next(tmpctx, pps);
		if (msg) {
			*from_gossipd = true;
			return msg;
		}
	}

	if (FD_ISSET(pps->peer_fd, &readfds)) {
		msg = sync_crypto_read(ctx, pps);
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
		sync_crypto_write(pps, gossip);
		peer_failed_connection_lost();
	} else {
		sync_crypto_write(pps, gossip);
	}
}

/* takes iff returns true */
bool handle_timestamp_filter(struct per_peer_state *pps, const u8 *msg TAKES)
{
	struct bitcoin_blkid chain_hash;
	u32 first_timestamp, timestamp_range;

	if (!fromwire_gossip_timestamp_filter(msg, &chain_hash,
					      &first_timestamp,
					      &timestamp_range)) {
		return false;
	}

	if (!bitcoin_blkid_eq(&chainparams->genesis_blockhash, &chain_hash)) {
		sync_crypto_write(pps,
				  take(towire_warningfmt(NULL, NULL,
				       "gossip_timestamp_filter"
				       " for bad chain: %s",
				       tal_hex(tmpctx, take(msg)))));
		return true;
	}

	gossip_setup_timestamp_filter(pps, first_timestamp, timestamp_range);
	return true;
}

bool handle_peer_gossip_or_error(struct per_peer_state *pps,
				 const struct channel_id *channel_id,
				 bool soft_error,
				 const u8 *msg TAKES)
{
	char *err;
	bool warning;
	struct channel_id actual;

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

	if (handle_timestamp_filter(pps, msg))
		return true;
	else if (is_msg_for_gossipd(msg)) {
		gossip_rcvd_filter_add(pps->grf, msg);
		wire_sync_write(pps->gossip_fd, msg);
		/* wire_sync_write takes, so don't take again. */
		return true;
	}

	if (is_peer_error(tmpctx, msg, channel_id, &err, &warning)) {
		/* Ignore unknown channel errors. */
		if (!err)
			goto handled;

		/* We hang up when a warning is received. */
		peer_failed_received_errmsg(pps, err, channel_id,
					    soft_error || warning);

		goto handled;
	}

	/* They're talking about a different channel? */
	if (is_wrong_channel(msg, channel_id, &actual)) {
		status_debug("Rejecting %s for unknown channel_id %s",
			     peer_wire_name(fromwire_peektype(msg)),
			     type_to_string(tmpctx, struct channel_id, &actual));
		sync_crypto_write(pps,
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
