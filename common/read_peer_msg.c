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
	 *  - upon receiving `error`:
	 *     - if `channel_id` is all zero:
	 *       - MUST fail all channels with the sending node.
	 *     - otherwise:
	 *       - MUST fail the channel referred to by `channel_id`, if that channel is with the sending node.
	 *   - upon receiving `warning`:
	 *     - SHOULD log the message for later diagnosis.
	 *     - MAY disconnect.
	 *     - MAY reconnect after some delay to retry.
	 *     - MAY attempt `shutdown` if permitted at this point.
	 *   - if no existing channel is referred to by `channel_id`:
	 *     - MUST ignore the message.
	 */

	/* FIXME: We don't actually free all channels at once, they'll
	 * have to error each in turn. */
	if (!channel_id_is_all(&err_chanid)
	    && !channel_id_eq(&err_chanid, channel_id))
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

bool handle_peer_error(struct per_peer_state *pps,
		       const struct channel_id *channel_id,
		       const u8 *msg TAKES)
{
	char *err;
	bool warning;
	if (is_peer_error(tmpctx, msg, channel_id, &err, &warning)) {
		/* Ignore unknown channel errors. */
		if (!err) {
			if (taken(msg))
				tal_free(msg);
			return true;
		}

		/* We hang up when a warning is received. */
		peer_failed_received_errmsg(pps, err, channel_id, warning);
	}

	return false;
}
