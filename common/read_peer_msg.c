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

const char *is_peer_warning(const tal_t *ctx, const u8 *msg)
{
	if (fromwire_peektype(msg) != WIRE_WARNING)
		return NULL;
	/* connectd demuxes, so we only see it if channel_id is ours. */
	return sanitize_error(ctx, msg, NULL);
}

const char *is_peer_error(const tal_t *ctx, const u8 *msg)
{
	if (fromwire_peektype(msg) != WIRE_ERROR)
		return NULL;
	/* connectd demuxes, so we only see it if channel_id is ours. */
	return sanitize_error(ctx, msg, NULL);
}

bool handle_peer_error_or_warning(struct per_peer_state *pps,
				  const u8 *msg TAKES)
{
	const char *err;

	err = is_peer_error(tmpctx, msg);
	if (err)
		peer_failed_received_errmsg(pps, true, err);

	/* Simply log incoming warnings */
	err = is_peer_warning(tmpctx, msg);
	if (err) {
		if (taken(msg))
			tal_free(msg);
		status_info("Received %s", err);
		return true;
	}

	return false;
}
