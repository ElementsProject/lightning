#include "config.h"
#include <assert.h>
#include <ccan/breakpoint/breakpoint.h>
#include <ccan/tal/str/str.h>
#include <common/peer_billboard.h>
#include <common/peer_failed.h>
#include <common/peer_io.h>
#include <common/peer_status_wiregen.h>
#include <common/status.h>
#include <common/status_wiregen.h>
#include <common/wire_error.h>

/* Fatal error here, return peer control to lightningd */
void NORETURN
peer_fatal_continue(const u8 *msg TAKES, const struct per_peer_state *pps)
{
 	int reason = fromwire_peektype(msg);
 	breakpoint();
 	status_send(msg);

	status_send_fd(pps->peer_fd);
	exit(0x80 | (reason & 0xFF));
}

/* We only support one channel per peer anyway */
static void NORETURN
peer_failed(struct per_peer_state *pps,
	    bool disconnect,
	    bool warn,
	    const struct channel_id *channel_id,
	    const char *desc)
{
	u8 *msg;

	if (warn) {
		msg = towire_warningfmt(desc, channel_id, "%s", desc);
	} else {
		msg = towire_errorfmt(desc, channel_id, "%s", desc);
	}
	peer_write(pps, msg);

	/* Tell master the error so it can re-xmit. */
	msg = towire_status_peer_error(NULL,
				       disconnect,
				       desc,
				       warn,
				       msg);
	peer_billboard(true, desc);
	peer_fatal_continue(take(msg), pps);
}

void peer_failed_warn(struct per_peer_state *pps,
		      const struct channel_id *channel_id,
		      const char *fmt, ...)
{
	va_list ap;
	const char *desc;

 	va_start(ap, fmt);
	desc = tal_vfmt(tmpctx, fmt, ap);
	va_end(ap);

	peer_failed(pps, true, true, channel_id, desc);
}

void peer_failed_warn_nodisconnect(struct per_peer_state *pps,
				   const struct channel_id *channel_id,
				   const char *fmt, ...)
{
	va_list ap;
	const char *desc;

 	va_start(ap, fmt);
	desc = tal_vfmt(tmpctx, fmt, ap);
	va_end(ap);

	peer_failed(pps, false, true, channel_id, desc);
}

void peer_failed_err(struct per_peer_state *pps,
		     const struct channel_id *channel_id,
		     const char *fmt, ...)
{
	va_list ap;
	const char *desc;

	assert(channel_id);
 	va_start(ap, fmt);
	desc = tal_vfmt(tmpctx, fmt, ap);
	va_end(ap);

	peer_failed(pps, true, false, channel_id, desc);
}

/* We're failing because peer sent us an error/warning message */
void peer_failed_received_errmsg(struct per_peer_state *pps,
				 bool disconnect,
				 const char *desc)
{
	u8 *msg;

	msg = towire_status_peer_error(NULL, disconnect, desc, false, NULL);
	peer_billboard(true, "Received %s", desc);
	peer_fatal_continue(take(msg), pps);
}

void peer_failed_connection_lost(void)
{
	status_send_fatal(take(towire_status_peer_connection_lost(NULL)));
}
