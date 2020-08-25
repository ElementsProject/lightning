#include <ccan/breakpoint/breakpoint.h>
#include <ccan/tal/str/str.h>
#include <common/crypto_sync.h>
#include <common/peer_billboard.h>
#include <common/peer_failed.h>
#include <common/peer_status_wiregen.h>
#include <common/status.h>
#include <common/status_wiregen.h>
#include <common/wire_error.h>
#include <stdarg.h>

/* Fatal error here, return peer control to lightningd */
static void NORETURN
peer_fatal_continue(const u8 *msg TAKES, const struct per_peer_state *pps)
{
 	int reason = fromwire_peektype(msg);
 	breakpoint();
 	status_send(msg);

	status_send_fd(pps->peer_fd);
	status_send_fd(pps->gossip_fd);
	status_send_fd(pps->gossip_store_fd);
	exit(0x80 | (reason & 0xFF));
}

/* We only support one channel per peer anyway */
void peer_failed(struct per_peer_state *pps,
		 const struct channel_id *channel_id,
		 const char *fmt, ...)
{
	va_list ap;
	const char *desc;
	u8 *msg, *err;

 	va_start(ap, fmt);
	desc = tal_vfmt(NULL, fmt, ap);
	va_end(ap);

	/* Tell peer the error. */
	err = towire_errorfmt(desc, channel_id, "%s", desc);
	sync_crypto_write(pps, err);

	/* Tell master the error so it can re-xmit. */
	msg = towire_status_peer_error(NULL, channel_id,
				       desc, false, pps,
				       err);
	peer_billboard(true, desc);
	tal_free(desc);
	peer_fatal_continue(take(msg), pps);
}

/* We're failing because peer sent us an error message */
void peer_failed_received_errmsg(struct per_peer_state *pps,
				 const char *desc,
				 const struct channel_id *channel_id,
				 bool soft_error)
{
	static const struct channel_id all_channels;
	u8 *msg;

	if (!channel_id)
		channel_id = &all_channels;
	msg = towire_status_peer_error(NULL, channel_id, desc, soft_error, pps,
				       NULL);
	peer_billboard(true, "Received error from peer: %s", desc);
	peer_fatal_continue(take(msg), pps);
}

void peer_failed_connection_lost(void)
{
	status_send_fatal(take(towire_status_peer_connection_lost(NULL)));
}
