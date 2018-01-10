#include <ccan/io/io.h>
#include <ccan/tal/str/str.h>
#include <common/crypto_sync.h>
#include <common/peer_failed.h>
#include <common/status.h>
#include <common/wire_error.h>
#include <fcntl.h>
#include <stdarg.h>
#include <unistd.h>
#include <wire/gen_peer_wire.h>

/* We only support one channel per peer anyway */
void peer_failed(int peer_fd, struct crypto_state *cs,
		 const struct channel_id *channel_id,
		 const char *fmt, ...)
{
	va_list ap;
	const char *errmsg;
	struct channel_id all_channels;
	u8 *msg;

	/* BOLT #1:
	 *
	 * The channel is referred to by `channel_id` unless `channel_id` is
	 * zero (ie. all bytes zero), in which case it refers to all channels.
	 */
	if (!channel_id) {
		memset(&all_channels, 0, sizeof(all_channels));
		channel_id = &all_channels;
	}

	va_start(ap, fmt);
	errmsg = tal_vfmt(NULL, fmt, ap);
	va_end(ap);

	va_start(ap, fmt);
	msg = towire_errorfmtv(errmsg, channel_id, fmt, ap);
	va_end(ap);

	/* This is only best-effort; don't block. */
	io_fd_block(peer_fd, false);
	sync_crypto_write(cs, peer_fd, take(msg));

	status_failed(STATUS_FAIL_PEER_BAD, "%s", errmsg);
}
