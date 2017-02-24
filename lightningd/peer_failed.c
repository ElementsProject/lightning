#include <ccan/tal/str/str.h>
#include <fcntl.h>
#include <lightningd/crypto_sync.h>
#include <lightningd/peer_failed.h>
#include <status.h>
#include <stdarg.h>
#include <unistd.h>
#include <wire/gen_peer_wire.h>

/* We only support one channel per peer anyway */
void peer_failed(int peer_fd, struct crypto_state *cs,
		 const struct channel_id *channel_id,
		 u16 error_code, const char *fmt, ...)
{
	va_list ap;
	const char *errmsg;
	struct channel_id all_channels;
	u8 *msg;

	/* BOLT #1:
	 *
	 * A node sending `error` MUST fail the channel referred to by the
	 * `channel-id`, or if `channel-id` is `0xFFFFFFFFFFFFFFFF` it MUST
	 * fail all channels and MUST close the connection.
	 */
	if (!channel_id) {
		memset(&all_channels, 0xFF, sizeof(all_channels));
		channel_id = &all_channels;
	}

	va_start(ap, fmt);
	errmsg = tal_vfmt(NULL, fmt, ap);
	va_end(ap);
	msg = towire_error(errmsg, channel_id, (const u8 *)errmsg);

	/* This is only best-effort; don't block. */
	fcntl(peer_fd, F_SETFL, fcntl(peer_fd, F_GETFL) | O_NONBLOCK);
	sync_crypto_write(cs, peer_fd, msg);

	status_failed(error_code, "%s", errmsg);
}
